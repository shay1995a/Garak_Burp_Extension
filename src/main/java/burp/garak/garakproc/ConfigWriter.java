// Copyright 2026 the garak Bridge authors
// SPDX-License-Identifier: Apache-2.0

package burp.garak.garakproc;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.garak.model.InsertionPoint;
import burp.garak.model.ResponseExtractor;
import burp.garak.model.RunConfig;
import burp.garak.model.TargetProfile;
import burp.garak.util.Json;
import burp.garak.util.JsonPathLite;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

/**
 * Writes the two JSON files a garak run is configured with.
 *
 * <p>Both are JSON rather than YAML on purpose: garak's {@code _load_config_files} tries
 * {@code json.load} before falling back to a YAML parser, and an absolute {@code --config}
 * path is used as given, so there is no reason to hand-roll a YAML writer.
 */
public final class ConfigWriter {

    /** Headers that describe a specific connection and must not be replayed by garak. */
    private static final Set<String> HOP_BY_HOP = Set.of(
            "content-length", "host", "connection", "keep-alive", "transfer-encoding",
            "upgrade", "proxy-connection", "te", "trailer", "expect");

    public record Files(Path generatorConfig, Path runConfig, Path reportDir, String reportPrefix) {
        /** Where garak will write its report, given report_dir and report_prefix. */
        public Path reportFile() {
            return reportDir.resolve(reportPrefix + ".report.jsonl");
        }

        public Path hitlogFile() {
            return reportDir.resolve(reportPrefix + ".hitlog.jsonl");
        }

        public Path digestFile() {
            return reportDir.resolve(reportPrefix + ".report.html");
        }
    }

    private ConfigWriter() {
    }

    // ------------------------------------------------------------- bridge config

    /**
     * Writes the generator and run configs for a bridged run.
     *
     * @param runDir directory this extension owns; garak writes its report here
     */
    public static Files writeBridgeConfig(Path runDir, String endpoint, String token,
                                          RunConfig config) throws IOException {
        Path generatorConfig = runDir.resolve("generator.json");
        Path runConfig = runDir.resolve("run.json");

        Json.write(generatorConfig, bridgeGenerator(endpoint, token, config));
        Json.write(runConfig, runSettings(runDir, config));

        return new Files(generatorConfig, runConfig, runDir, "run");
    }

    public static JsonObject bridgeGenerator(String endpoint, String token, RunConfig config) {
        JsonObject headers = new JsonObject();
        headers.addProperty("Content-Type", "application/json");
        headers.addProperty(burp.garak.bridge.BridgeServer.AUTH_HEADER, token);

        JsonObject template = new JsonObject();
        template.addProperty("prompt", "$INPUT");

        JsonObject rest = new JsonObject();
        rest.addProperty("name", "burp-bridge");
        rest.addProperty("uri", endpoint);
        rest.addProperty("method", "post");
        rest.add("headers", headers);
        rest.add("req_template_json_object", template);
        rest.addProperty("response_json", true);
        rest.addProperty("response_json_field", "$.output");
        rest.addProperty("request_timeout", bridgeTimeoutSeconds(config));
        rest.add("ratelimit_codes", array(429));
        rest.add("skip_codes", array(204));

        return wrap("rest", "RestGenerator", rest);
    }

    /**
     * garak must wait longer than the bridge's own worst case, otherwise it abandons a
     * request the bridge is still legitimately retrying and the run fills with timeouts.
     */
    private static int bridgeTimeoutSeconds(RunConfig config) {
        long attempts = Math.max(1, config.retries + 1);
        long worstCaseMs = attempts * (config.requestTimeoutMs + config.delayMs + config.jitterMs)
                + 8_000L * attempts   // the runner's own escalating backoff between retries
                + 15_000L;            // slack for queueing behind the concurrency limit
        return (int) Math.min(3600, Math.max(30, worstCaseMs / 1000));
    }

    public static JsonObject runSettings(Path runDir, RunConfig config) {
        JsonObject system = new JsonObject();
        // The bridge is the real throttle; garak's parallelism just keeps it fed.
        if (config.parallelAttempts > 1) {
            system.addProperty("parallel_attempts", config.parallelAttempts);
        } else {
            system.addProperty("parallel_attempts", false);
        }
        system.addProperty("parallel_requests", false);
        // 'lite' trims the default probe set; irrelevant when probes are named explicitly,
        // but it also suppresses a startup hint, so turn it off for clean logs.
        system.addProperty("lite", false);

        JsonObject run = new JsonObject();
        run.addProperty("generations", Math.max(1, config.generations));
        run.addProperty("soft_probe_prompt_cap", Math.max(1, config.softProbePromptCap));
        if (config.seed >= 0) {
            run.addProperty("seed", config.seed);
        }

        JsonObject reporting = new JsonObject();
        reporting.addProperty("report_dir", runDir.toAbsolutePath().toString());

        JsonObject root = new JsonObject();
        root.add("system", system);
        root.add("run", run);
        root.add("reporting", reporting);
        return root;
    }

    // ------------------------------------------------------------ standalone config

    /** A direct-to-target config, plus anything it could not faithfully represent. */
    public record Standalone(JsonObject config, List<String> limitations) {
    }

    /**
     * Builds a config that points garak straight at the target, with no bridge, so a run
     * can be reproduced from a terminal or in CI.
     *
     * <p>Only the shapes garak's RestGenerator can actually express survive the trip: one
     * JSON insertion point and a JSON reply. Anything else -- streaming, a prelude, several
     * insertion points -- is reported as a limitation rather than silently dropped, because
     * a config that looks right and quietly tests nothing is worse than no config.
     */
    public static Standalone standaloneGenerator(TargetProfile profile, int burpProxyPort) {
        List<String> limitations = new ArrayList<>();
        HttpRequest request = profile.request();

        if (profile.transport != TargetProfile.Transport.HTTP) {
            limitations.add("This target is a WebSocket. garak's rest generator cannot speak "
                    + "WebSocket; only the in-Burp bridge can drive it.");
        }
        if (!profile.prelude.isEmpty()) {
            limitations.add("The " + profile.prelude.size() + "-step prelude (conversation "
                    + "setup, CSRF or token refresh) is dropped: RestGenerator sends one "
                    + "stateless request per prompt.");
        }
        if (profile.insertionPoints.size() > 1) {
            limitations.add("Only the first of " + profile.insertionPoints.size()
                    + " insertion points is used.");
        }

        JsonObject rest = new JsonObject();
        rest.addProperty("name", profile.name);
        rest.addProperty("uri", profile.baseUrl() + pathOf(request));
        rest.addProperty("method", request.method().toLowerCase(Locale.ROOT));
        rest.add("headers", headersOf(request));

        applyBodyTemplate(profile, request, rest, limitations);
        applyResponseRule(profile, rest, limitations);

        rest.addProperty("request_timeout", 60);
        rest.add("ratelimit_codes", array(429));

        if (burpProxyPort > 0) {
            JsonObject proxies = new JsonObject();
            proxies.addProperty("http", "http://127.0.0.1:" + burpProxyPort);
            proxies.addProperty("https", "http://127.0.0.1:" + burpProxyPort);
            rest.add("proxies", proxies);
            // Burp presents its own CA, which the garak process will not trust.
            rest.addProperty("verify_ssl", false);
        }

        return new Standalone(wrap("rest", "RestGenerator", rest), limitations);
    }

    private static void applyBodyTemplate(TargetProfile profile, HttpRequest request,
                                          JsonObject rest, List<String> limitations) {
        if (profile.insertionPoints.isEmpty()) {
            limitations.add("No insertion point is set, so the prompt has nowhere to go.");
            return;
        }
        InsertionPoint point = profile.insertionPoints.get(0);

        if (point.kind == InsertionPoint.Kind.JSON_PATH) {
            Optional<JsonElement> body = Json.parse(request.bodyToString());
            if (body.isPresent() && JsonPathLite.setString(body.get(), point.locator,
                    point.wrap("$INPUT"))) {
                rest.add("req_template_json_object", body.get());
                return;
            }
            limitations.add("Could not place $INPUT at " + point.locator
                    + " in the captured body.");
            return;
        }

        if (point.kind == InsertionPoint.Kind.QUERY_PARAM
                || point.kind == InsertionPoint.Kind.BODY_PARAM) {
            // RestGenerator sends the template as the body for POST, and as query params
            // for GET, so a form-encoded template works directly.
            rest.addProperty("req_template", point.locator + "=" + point.wrap("$INPUT"));
            limitations.add("Other parameters in the original request are dropped: "
                    + "RestGenerator sends only the template.");
            return;
        }

        rest.addProperty("req_template", point.wrap("$INPUT"));
        limitations.add("Insertion point '" + point.describe()
                + "' has no direct equivalent; the request body is just the prompt.");
    }

    private static void applyResponseRule(TargetProfile profile, JsonObject rest,
                                          List<String> limitations) {
        ResponseExtractor extractor = profile.extractor;
        switch (extractor.mode) {
            case JSON_PATH -> {
                rest.addProperty("response_json", true);
                rest.addProperty("response_json_field", extractor.expression);
            }
            case RAW -> rest.addProperty("response_json", false);
            case SSE_CONCAT, NDJSON_CONCAT -> {
                rest.addProperty("response_json", false);
                limitations.add("The reply is streamed. RestGenerator has no way to "
                        + "reassemble deltas, so garak would score the raw event stream. "
                        + "Use the bridge for this target.");
            }
            case REGEX, HTML_TEXT -> {
                rest.addProperty("response_json", false);
                limitations.add("The '" + extractor.describe() + "' extraction rule has no "
                        + "RestGenerator equivalent; garak would score the whole body.");
            }
        }
    }

    private static JsonObject headersOf(HttpRequest request) {
        JsonObject headers = new JsonObject();
        for (HttpHeader header : request.headers()) {
            if (!HOP_BY_HOP.contains(header.name().toLowerCase(Locale.ROOT))) {
                headers.addProperty(header.name(), header.value());
            }
        }
        return headers;
    }

    private static String pathOf(HttpRequest request) {
        String path = request.path();
        return path == null || path.isEmpty() ? "/" : path;
    }

    // ------------------------------------------------------------------- helpers

    private static JsonObject wrap(String module, String className, JsonObject settings) {
        JsonObject inner = new JsonObject();
        inner.add(className, settings);
        JsonObject root = new JsonObject();
        root.add(module, inner);
        return root;
    }

    private static JsonArray array(int... values) {
        JsonArray array = new JsonArray();
        for (int value : values) {
            array.add(value);
        }
        return array;
    }
}
