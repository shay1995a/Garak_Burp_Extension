// Copyright 2026 the garak Bridge authors
// SPDX-License-Identifier: Apache-2.0

package burp.garak.bridge;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.garak.model.Exchange;
import burp.garak.model.PreludeStep;
import burp.garak.model.ResponseExtractor;
import burp.garak.model.RunConfig;
import burp.garak.model.TargetProfile;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

/**
 * Runs one prompt against the target: prelude, injection, send, extraction.
 *
 * <h2>Why this never returns a 4xx or 5xx to garak</h2>
 *
 * garak's {@code RestGenerator} turns any 4xx into a {@code ConnectionError} and any 3xx
 * into a {@code NotImplementedError}, either of which aborts the whole run. Its retry
 * decorator, {@code backoff.on_exception(backoff.fibo, ..., max_value=70)}, has no attempt
 * or time limit, so a 5xx that never clears makes garak retry forever.
 *
 * <p>So the bridge does its own retrying, where it can also apply the throttle, and speaks
 * to garak in only three codes: 200 with an answer, 429 when it wants garak to slow down
 * (capped, so a permanently rate-limited target cannot hang the run), and 204 to skip a
 * generation. A skipped generation is scored as a "none" and the run still finishes.
 */
public final class ExchangeRunner {

    /** What the bridge should tell garak, and what actually happened. */
    public record Outcome(int status, String output, Exchange exchange) {
        public boolean ok() {
            return status == 200;
        }
    }

    /** Consecutive 429s handed to garak before the bridge gives up and skips instead. */
    private static final int MAX_CONSECUTIVE_RATE_LIMITS = 5;

    private final MontoyaApi api;
    private final TargetProfile profile;
    private final RunConfig config;
    private final ExchangeStore store;
    private final Consumer<String> log;

    private final Semaphore concurrency;
    private final Object paceLock = new Object();
    private long lastSendMillis;

    private final AtomicInteger consecutiveFailures = new AtomicInteger();
    private final AtomicInteger consecutiveRateLimits = new AtomicInteger();
    private final AtomicBoolean tripped = new AtomicBoolean();
    private final AtomicInteger served = new AtomicInteger();

    /** Values captured by per-run prelude steps, shared across every prompt. */
    private final Map<String, String> runVariables = new ConcurrentHashMap<>();
    private final AtomicBoolean runPreludeDone = new AtomicBoolean();
    private final Object preludeLock = new Object();

    /** Set when the circuit breaker trips, so the run controller can stop garak. */
    private volatile Runnable onCircuitBreak = () -> {
    };

    private volatile String currentProbe = "";

    public ExchangeRunner(MontoyaApi api, TargetProfile profile, RunConfig config,
                          ExchangeStore store, Consumer<String> log) {
        this.api = api;
        this.profile = profile;
        this.config = config;
        this.store = store;
        this.log = log;
        this.concurrency = new Semaphore(Math.max(1, config.maxConcurrent), true);
    }

    public void onCircuitBreak(Runnable handler) {
        this.onCircuitBreak = handler;
    }

    public void setCurrentProbe(String probe) {
        this.currentProbe = probe == null ? "" : probe;
    }

    public int served() {
        return served.get();
    }

    public boolean isTripped() {
        return tripped.get();
    }

    // --------------------------------------------------------------------- run

    public Outcome run(String prompt) {
        Exchange exchange = store.open(prompt);
        exchange.probe = currentProbe;
        long started = System.currentTimeMillis();

        if (tripped.get()) {
            return finish(exchange, Exchange.Status.SKIPPED, 204,
                    "run stopped: too many consecutive failures", started);
        }

        try {
            concurrency.acquire();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return finish(exchange, Exchange.Status.FAILED, 204, "interrupted", started);
        }

        try {
            return attemptWithRetries(exchange, prompt, started);
        } finally {
            concurrency.release();
            served.incrementAndGet();
            store.close(exchange);
        }
    }

    private Outcome attemptWithRetries(Exchange exchange, String prompt, long started) {
        int attempts = Math.max(1, config.retries + 1);
        String lastProblem = "";
        boolean lastWasRateLimit = false;

        for (int attempt = 1; attempt <= attempts; attempt++) {
            if (attempt > 1) {
                // Grow the wait between our own retries, independently of garak.
                sleep(Math.min(8_000L, 500L * (1L << (attempt - 2))));
            }
            pace();

            Attempt result = sendOnce(exchange, prompt);
            lastProblem = result.problem;
            lastWasRateLimit = result.rateLimited;

            if (result.text != null) {
                consecutiveFailures.set(0);
                consecutiveRateLimits.set(0);
                exchange.output = result.text;
                return finish(exchange, Exchange.Status.OK, 200, "", started);
            }
            if (result.fatal) {
                break; // a misconfiguration; retrying cannot help
            }
        }

        if (lastWasRateLimit) {
            int inARow = consecutiveRateLimits.incrementAndGet();
            if (inARow <= MAX_CONSECUTIVE_RATE_LIMITS) {
                log.accept("target is rate limiting (" + inARow + " in a row); telling garak to back off");
                return finish(exchange, Exchange.Status.RATE_LIMITED, 429, lastProblem, started);
            }
            log.accept("target still rate limiting after " + MAX_CONSECUTIVE_RATE_LIMITS
                    + " backoffs; skipping generations instead of stalling the run");
        }

        noteFailure(lastProblem);
        return finish(exchange, Exchange.Status.SKIPPED, 204, lastProblem, started);
    }

    /** One send: prelude, build, request, extract. */
    private record Attempt(String text, String problem, boolean rateLimited, boolean fatal) {
        static Attempt ok(String text) {
            return new Attempt(text, "", false, false);
        }

        static Attempt failed(String problem) {
            return new Attempt(null, problem, false, false);
        }

        static Attempt rateLimited(String problem) {
            return new Attempt(null, problem, true, false);
        }

        static Attempt fatal(String problem) {
            return new Attempt(null, problem, false, true);
        }
    }

    private Attempt sendOnce(Exchange exchange, String prompt) {
        Map<String, String> variables;
        try {
            variables = resolveVariables();
        } catch (PreludeFailure e) {
            return Attempt.failed("prelude failed: " + e.getMessage());
        }

        RequestBuilder.Built built = RequestBuilder.build(profile, prompt, variables);
        for (String warning : built.warnings()) {
            log.accept("build warning: " + warning);
        }

        HttpRequestResponse traffic;
        try {
            traffic = api.http().sendRequest(built.request(), RequestOptions.requestOptions()
                    .withResponseTimeout(config.requestTimeoutMs));
        } catch (RuntimeException e) {
            return Attempt.failed("send failed: " + describe(e));
        }

        // Keep the traffic addressable from the results table without holding every body
        // on the heap; Burp pages temp-file messages to disk.
        exchange.requestResponse = safeCopyToTempFile(traffic);

        HttpResponse response = traffic.response();
        if (response == null) {
            return Attempt.failed("no response from " + profile.host
                    + " within " + config.requestTimeoutMs + "ms");
        }
        int status = response.statusCode();
        exchange.httpStatus = status;

        if (status == 429 || status == 503) {
            return Attempt.rateLimited("target returned HTTP " + status);
        }
        if (status >= 500) {
            return Attempt.failed("target returned HTTP " + status);
        }
        if (status == 401 || status == 403) {
            // Session almost certainly expired. Retrying the same request will not fix it,
            // and hammering an auth endpoint is exactly what should not happen unattended.
            return Attempt.fatal("target returned HTTP " + status
                    + " - the captured session has probably expired; re-capture the request");
        }
        if (status >= 400) {
            return Attempt.failed("target returned HTTP " + status);
        }

        Extractors.Result extracted = Extractors.extract(response.bodyToString(), profile.extractor);
        if (!extracted.ok()) {
            return Attempt.failed("could not read the reply: " + extracted.problem());
        }
        if (extracted.text().isBlank() && profile.extractor.emptyIsSkip) {
            return Attempt.failed("the reply extracted to an empty string");
        }
        return Attempt.ok(extracted.text());
    }

    // ----------------------------------------------------------------- prelude

    private static final class PreludeFailure extends Exception {
        PreludeFailure(String message) {
            super(message);
        }
    }

    /**
     * Runs whatever prelude steps this prompt needs and returns the variables in scope.
     * Per-run steps execute once; per-prompt steps execute on every call, because a
     * single-use CSRF token or a fresh conversation id is the whole reason they exist.
     */
    private Map<String, String> resolveVariables() throws PreludeFailure {
        if (profile.prelude.isEmpty()) {
            return Map.of();
        }

        if (!runPreludeDone.get()) {
            synchronized (preludeLock) {
                if (!runPreludeDone.get()) {
                    for (PreludeStep step : profile.prelude) {
                        if (step.cadence == PreludeStep.Cadence.PER_RUN) {
                            runVariables.putAll(execute(step, runVariables));
                        }
                    }
                    runPreludeDone.set(true);
                }
            }
        }

        Map<String, String> variables = new LinkedHashMap<>(runVariables);
        for (PreludeStep step : profile.prelude) {
            if (step.cadence == PreludeStep.Cadence.PER_PROMPT) {
                variables.putAll(execute(step, variables));
            }
        }
        return variables;
    }

    private Map<String, String> execute(PreludeStep step, Map<String, String> known)
            throws PreludeFailure {
        byte[] raw = java.util.Base64.getDecoder().decode(
                step.requestBase64 == null ? "" : step.requestBase64);
        if (raw.length == 0) {
            throw new PreludeFailure("step '" + step.name + "' has no request");
        }
        HttpService service = step.host == null || step.host.isBlank()
                ? profile.service()
                : HttpService.httpService(step.host, step.port, step.secure);

        List<String> warnings = new ArrayList<>();
        HttpRequest request = RequestBuilder.substituteVariables(
                HttpRequest.httpRequest(service, ByteArray.byteArray(raw)), known, warnings);
        warnings.forEach(warning -> log.accept("prelude '" + step.name + "': " + warning));

        pace();
        HttpRequestResponse traffic;
        try {
            traffic = api.http().sendRequest(request, RequestOptions.requestOptions()
                    .withResponseTimeout(config.requestTimeoutMs));
        } catch (RuntimeException e) {
            throw new PreludeFailure("step '" + step.name + "' could not be sent: " + describe(e));
        }
        HttpResponse response = traffic.response();
        if (response == null) {
            throw new PreludeFailure("step '" + step.name + "' got no response");
        }
        if (!step.okCodes.isEmpty() && !step.okCodes.contains((int) response.statusCode())) {
            throw new PreludeFailure("step '" + step.name + "' returned HTTP "
                    + response.statusCode() + ", expected one of " + step.okCodes);
        }

        Map<String, String> captured = new HashMap<>();
        for (PreludeStep.Capture capture : step.captures) {
            ResponseExtractor spec = capture.from;
            Extractors.Result result = Extractors.extract(response.bodyToString(), spec);
            if (!result.ok() || result.text().isBlank()) {
                throw new PreludeFailure("step '" + step.name + "' could not capture '"
                        + capture.name + "': "
                        + (result.ok() ? "extracted an empty value" : result.problem()));
            }
            captured.put(capture.name, result.text());
        }
        return captured;
    }

    // ---------------------------------------------------------------- plumbing

    /** Enforces the minimum gap between requests leaving the bridge, plus jitter. */
    private void pace() {
        long wait;
        synchronized (paceLock) {
            long now = System.currentTimeMillis();
            long earliest = lastSendMillis + config.delayMs;
            wait = Math.max(0, earliest - now);
            if (config.jitterMs > 0) {
                wait += (long) (Math.random() * config.jitterMs);
            }
            lastSendMillis = now + wait;
        }
        sleep(wait);
    }

    private void noteFailure(String problem) {
        int failures = consecutiveFailures.incrementAndGet();
        log.accept("prompt failed (" + failures + " in a row): " + problem);
        if (failures >= config.circuitBreakerThreshold && tripped.compareAndSet(false, true)) {
            log.accept("stopping: " + failures + " prompts in a row failed. "
                    + "The remaining probes would only produce empty results.");
            try {
                onCircuitBreak.run();
            } catch (RuntimeException e) {
                log.accept("could not stop the run cleanly: " + describe(e));
            }
        }
    }

    private Outcome finish(Exchange exchange, Exchange.Status status, int httpStatus,
                           String problem, long started) {
        exchange.status = status;
        exchange.error = problem == null ? "" : problem;
        exchange.durationMs = System.currentTimeMillis() - started;
        return new Outcome(httpStatus, exchange.output, exchange);
    }

    private HttpRequestResponse safeCopyToTempFile(HttpRequestResponse traffic) {
        try {
            return traffic.copyToTempFile();
        } catch (RuntimeException e) {
            return traffic; // temp-file storage is an optimisation, not a requirement
        }
    }

    private static void sleep(long millis) {
        if (millis <= 0) {
            return;
        }
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static String describe(Throwable error) {
        String message = error.getMessage();
        return message == null || message.isBlank()
                ? error.getClass().getSimpleName()
                : error.getClass().getSimpleName() + ": " + message;
    }
}
