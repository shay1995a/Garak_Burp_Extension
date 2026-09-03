// Copyright 2026 the garak Bridge authors
// SPDX-License-Identifier: Apache-2.0

package burp.garak.bridge;

import burp.garak.util.Json;
import com.google.gson.JsonObject;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import java.util.function.Function;

/**
 * The loopback endpoint garak talks to.
 *
 * <p>A hand-rolled HTTP/1.1 server rather than {@code com.sun.net.httpserver}, because the
 * JRE bundled with Burp does not ship the {@code jdk.httpserver} module -- an extension
 * that imported it would compile and then fail to load. The protocol surface needed here
 * is one POST with a JSON body, and this extension generates the client config too, so
 * there is no unknown client to accommodate.
 *
 * <p>Bound to the loopback interface only, behind a random path token that must also be
 * echoed in a header: the bridge replays authenticated requests against a live target, so
 * it must not be reachable by anything but the garak process this extension started.
 */
public final class BridgeServer {

    /** Header garak is configured to send, checked alongside the path token. */
    public static final String AUTH_HEADER = "X-Garak-Bridge-Key";

    private static final int HEADER_LIMIT = 64 * 1024;
    private static final int BODY_LIMIT = 8 * 1024 * 1024;
    private static final int IDLE_TIMEOUT_MS = 300_000;

    private final Consumer<String> log;
    private final AtomicBoolean running = new AtomicBoolean();

    private ServerSocket socket;
    private ExecutorService workers;
    private Thread acceptor;
    private String token = "";
    private int port;

    /** Set while a run is active; returns the answer for one prompt. */
    private volatile Function<String, ExchangeRunner.Outcome> handler;

    public BridgeServer(Consumer<String> log) {
        this.log = log;
    }

    // ------------------------------------------------------------------ lifecycle

    /**
     * Starts listening.
     *
     * @param requestedPort 0 to let the OS pick a free port
     * @param threads       worker threads; should exceed garak's parallel attempts
     */
    public synchronized void start(int requestedPort, int threads) throws IOException {
        if (running.get()) {
            return;
        }
        token = newToken();
        socket = new ServerSocket();
        socket.setReuseAddress(true);
        socket.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), requestedPort), 64);
        port = socket.getLocalPort();

        workers = Executors.newFixedThreadPool(Math.max(2, threads), runnable -> {
            Thread thread = new Thread(runnable, "garak-bridge-worker");
            thread.setDaemon(true);
            return thread;
        });

        running.set(true);
        acceptor = new Thread(this::acceptLoop, "garak-bridge-acceptor");
        acceptor.setDaemon(true);
        acceptor.start();

        log.accept("bridge listening on " + endpoint());
    }

    public synchronized void stop() {
        if (!running.compareAndSet(true, false)) {
            return;
        }
        closeQuietly(socket);
        if (workers != null) {
            workers.shutdownNow();
            try {
                workers.awaitTermination(2, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        if (acceptor != null) {
            acceptor.interrupt();
        }
        log.accept("bridge stopped");
    }

    public boolean isRunning() {
        return running.get();
    }

    public int port() {
        return port;
    }

    public String token() {
        return token;
    }

    /** The URI written into garak's generator config. */
    public String endpoint() {
        return "http://127.0.0.1:" + port + path();
    }

    public String path() {
        return "/garak/" + token;
    }

    /** Installs the handler for the duration of a run; null means "no run in progress". */
    public void setHandler(Function<String, ExchangeRunner.Outcome> handler) {
        this.handler = handler;
    }

    // -------------------------------------------------------------------- serving

    private void acceptLoop() {
        while (running.get()) {
            try {
                Socket connection = socket.accept();
                workers.submit(() -> serve(connection));
            } catch (IOException e) {
                if (running.get()) {
                    log.accept("bridge accept failed: " + e.getMessage());
                }
                return;
            } catch (RuntimeException e) {
                if (running.get()) {
                    log.accept("bridge rejected a connection: " + e.getMessage());
                }
            }
        }
    }

    private void serve(Socket connection) {
        try (Socket open = connection) {
            open.setSoTimeout(IDLE_TIMEOUT_MS);
            open.setTcpNoDelay(true);
            InputStream in = open.getInputStream();
            OutputStream out = new BufferedOutputStream(open.getOutputStream());

            // Keep-alive: urllib3 pools connections, and a long run would otherwise leave
            // thousands of sockets in TIME_WAIT.
            while (running.get()) {
                Request request = readRequest(in);
                if (request == null) {
                    return;
                }
                boolean keepAlive = handle(request, out);
                out.flush();
                if (!keepAlive) {
                    return;
                }
            }
        } catch (SocketTimeoutException e) {
            // idle connection reaped; nothing to say
        } catch (IOException e) {
            // client hung up mid-request; normal when a run is cancelled
        } catch (RuntimeException e) {
            log.accept("bridge worker error: " + e);
        }
    }

    private boolean handle(Request request, OutputStream out) throws IOException {
        boolean keepAlive = !"close".equalsIgnoreCase(request.header("connection"));

        if (!request.path.equals(path()) && !request.path.equals(path() + "/health")) {
            // Do not confirm or deny the token: an unauthenticated caller learns nothing.
            respond(out, 404, "{\"error\":\"not found\"}", keepAlive);
            return keepAlive;
        }
        String presented = request.header(AUTH_HEADER.toLowerCase(Locale.ROOT));
        if (presented != null && !presented.equals(token)) {
            respond(out, 404, "{\"error\":\"not found\"}", keepAlive);
            return keepAlive;
        }

        if (request.path.endsWith("/health")) {
            respond(out, 200, "{\"ok\":true,\"handler\":" + (handler != null) + "}", keepAlive);
            return keepAlive;
        }
        if (!"POST".equals(request.method)) {
            respond(out, 200, "{\"output\":\"\"}", keepAlive);
            return keepAlive;
        }

        Function<String, ExchangeRunner.Outcome> current = handler;
        if (current == null) {
            // No run in progress. 204 is a skip to garak, never an abort.
            respondNoContent(out, keepAlive);
            return keepAlive;
        }

        String prompt = readPrompt(request.body);
        if (prompt == null) {
            log.accept("bridge got a request with no 'prompt' field; skipping");
            respondNoContent(out, keepAlive);
            return keepAlive;
        }

        ExchangeRunner.Outcome outcome;
        try {
            outcome = current.apply(prompt);
        } catch (RuntimeException e) {
            log.accept("bridge handler failed: " + e);
            respondNoContent(out, keepAlive);
            return keepAlive;
        }

        switch (outcome.status()) {
            case 200 -> {
                JsonObject body = new JsonObject();
                body.addProperty("output", outcome.output());
                respond(out, 200, Json.GSON.toJson(body), keepAlive);
            }
            case 429 -> respond(out, 429, "{\"error\":\"rate limited\"}", keepAlive);
            default -> respondNoContent(out, keepAlive);
        }
        return keepAlive;
    }

    /** garak posts {"prompt": "..."}; accept a bare string body as a courtesy. */
    private static String readPrompt(byte[] body) {
        String text = new String(body, StandardCharsets.UTF_8);
        return Json.parseObject(text)
                .filter(object -> object.has("prompt"))
                .map(object -> Json.string(object, "prompt", ""))
                .orElseGet(() -> text.isBlank() ? null : text);
    }

    // ---------------------------------------------------------------- HTTP wire

    private record Request(String method, String path, Map<String, String> headers, byte[] body) {
        String header(String lowercaseName) {
            return headers.get(lowercaseName);
        }
    }

    /** Reads one request, or null at end of stream. */
    private static Request readRequest(InputStream in) throws IOException {
        String requestLine = readLine(in);
        if (requestLine == null || requestLine.isEmpty()) {
            return null;
        }
        String[] parts = requestLine.split(" ");
        if (parts.length < 2) {
            throw new IOException("malformed request line");
        }
        String method = parts[0];
        String target = parts[1];
        int queryAt = target.indexOf('?');
        String path = queryAt < 0 ? target : target.substring(0, queryAt);

        Map<String, String> headers = new HashMap<>();
        int headerBytes = 0;
        String line;
        while ((line = readLine(in)) != null && !line.isEmpty()) {
            headerBytes += line.length();
            if (headerBytes > HEADER_LIMIT) {
                throw new IOException("header block too large");
            }
            int colon = line.indexOf(':');
            if (colon > 0) {
                headers.put(line.substring(0, colon).trim().toLowerCase(Locale.ROOT),
                        line.substring(colon + 1).trim());
            }
        }

        byte[] body = readBody(in, headers);
        return new Request(method, path, headers, body);
    }

    private static byte[] readBody(InputStream in, Map<String, String> headers) throws IOException {
        if ("chunked".equalsIgnoreCase(headers.get("transfer-encoding"))) {
            return readChunked(in);
        }
        String lengthHeader = headers.get("content-length");
        if (lengthHeader == null) {
            return new byte[0];
        }
        int length;
        try {
            length = Integer.parseInt(lengthHeader.trim());
        } catch (NumberFormatException e) {
            throw new IOException("bad Content-Length");
        }
        if (length < 0 || length > BODY_LIMIT) {
            throw new IOException("body too large");
        }
        return in.readNBytes(length);
    }

    private static byte[] readChunked(InputStream in) throws IOException {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        while (true) {
            String sizeLine = readLine(in);
            if (sizeLine == null) {
                throw new IOException("truncated chunked body");
            }
            int semicolon = sizeLine.indexOf(';');
            String hex = (semicolon < 0 ? sizeLine : sizeLine.substring(0, semicolon)).trim();
            int size;
            try {
                size = Integer.parseInt(hex, 16);
            } catch (NumberFormatException e) {
                throw new IOException("bad chunk size");
            }
            if (size == 0) {
                while (true) {
                    String trailer = readLine(in);
                    if (trailer == null || trailer.isEmpty()) {
                        break;
                    }
                }
                return body.toByteArray();
            }
            if (body.size() + size > BODY_LIMIT) {
                throw new IOException("body too large");
            }
            body.write(in.readNBytes(size));
            readLine(in); // trailing CRLF
        }
    }

    /**
     * Reads one CRLF-terminated line. Byte-at-a-time on purpose: a buffered reader would
     * consume past the header block into the body.
     */
    private static String readLine(InputStream in) throws IOException {
        ByteArrayOutputStream line = new ByteArrayOutputStream(128);
        int b;
        while ((b = in.read()) != -1) {
            if (b == '\n') {
                byte[] bytes = line.toByteArray();
                int length = bytes.length > 0 && bytes[bytes.length - 1] == '\r'
                        ? bytes.length - 1 : bytes.length;
                return new String(bytes, 0, length, StandardCharsets.ISO_8859_1);
            }
            line.write(b);
            if (line.size() > HEADER_LIMIT) {
                throw new IOException("line too long");
            }
        }
        return line.size() == 0 ? null : line.toString(StandardCharsets.ISO_8859_1);
    }

    private static void respond(OutputStream out, int status, String body, boolean keepAlive)
            throws IOException {
        byte[] payload = body.getBytes(StandardCharsets.UTF_8);
        StringBuilder head = new StringBuilder()
                .append("HTTP/1.1 ").append(status).append(' ').append(reason(status)).append("\r\n")
                .append("Content-Type: application/json; charset=utf-8\r\n")
                .append("Content-Length: ").append(payload.length).append("\r\n")
                .append("Connection: ").append(keepAlive ? "keep-alive" : "close").append("\r\n")
                .append("\r\n");
        out.write(head.toString().getBytes(StandardCharsets.ISO_8859_1));
        out.write(payload);
    }

    /** 204 must carry no body and no Content-Length. */
    private static void respondNoContent(OutputStream out, boolean keepAlive) throws IOException {
        String head = "HTTP/1.1 204 No Content\r\n"
                + "Connection: " + (keepAlive ? "keep-alive" : "close") + "\r\n\r\n";
        out.write(head.getBytes(StandardCharsets.ISO_8859_1));
    }

    private static String reason(int status) {
        return switch (status) {
            case 200 -> "OK";
            case 204 -> "No Content";
            case 404 -> "Not Found";
            case 429 -> "Too Many Requests";
            default -> "OK";
        };
    }

    private static String newToken() {
        byte[] bytes = new byte[18];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static void closeQuietly(ServerSocket socket) {
        if (socket != null) {
            try {
                socket.close();
            } catch (IOException e) {
                // shutting down anyway
            }
        }
    }
}
