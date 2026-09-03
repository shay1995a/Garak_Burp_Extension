// Copyright 2026 the garak Bridge authors
// SPDX-License-Identifier: Apache-2.0

package burp.garak;

import burp.garak.bridge.Extractors;
import burp.garak.capture.Calibrator;
import burp.garak.capture.RequestAnalyzer;
import burp.garak.capture.ResponseAnalyzer;
import burp.garak.garakproc.ConfigWriter;
import burp.garak.garakproc.GarakLocator;
import burp.garak.garakproc.PluginCatalog;
import burp.garak.garakproc.ReportTailer;
import burp.garak.model.InsertionPoint;
import burp.garak.model.ResponseExtractor;
import burp.garak.model.RunConfig;
import burp.garak.model.ScanDepth;
import burp.garak.util.Json;
import burp.garak.util.JsonPathLite;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Tests for everything that does not need a live Burp.
 *
 * <p>Plain Java with no test framework: the extension ships with two jars and adding a
 * third just to assert would not earn its keep. Run with tools/run-tests.sh.
 */
public final class Tests {

    private static int passed;
    private static final List<String> failures = new ArrayList<>();

    public static void main(String[] args) {
        jsonPathLite();
        extractors();
        streaming();
        promptDetection();
        replyDetection();
        calibration();
        throttling();
        platform();
        configWriter();
        reportDecoding();
        catalogue(args.length > 0 ? Path.of(args[0]) : null);

        System.out.println();
        System.out.println(passed + " passed, " + failures.size() + " failed");
        failures.forEach(failure -> System.out.println("  FAIL " + failure));
        System.exit(failures.isEmpty() ? 0 : 1);
    }

    // ------------------------------------------------------------- JsonPathLite

    private static void jsonPathLite() {
        section("JsonPathLite");
        JsonElement doc = Json.parse("""
                {"a": {"b": [{"c": "first"}, {"c": "second"}]},
                 "weird key": "punctuated",
                 "n": 42,
                 "messages": [{"role":"system","content":"sys"},
                              {"role":"user","content":"hello there"}]}
                """).orElseThrow();

        is("dotted path", "second", JsonPathLite.evalToString(doc, "$.a.b[1].c").orElse(""));
        is("negative index", "second", JsonPathLite.evalToString(doc, "$.a.b[-1].c").orElse(""));
        is("wildcard concatenates", "firstsecond",
                JsonPathLite.evalToString(doc, "$.a.b[*].c").orElse(""));
        is("bracket-quoted key", "punctuated",
                JsonPathLite.evalToString(doc, "$['weird key']").orElse(""));
        is("bare key is a top-level field", "punctuated",
                JsonPathLite.evalToString(doc, "weird key").orElse(""));
        is("number renders as text", "42", JsonPathLite.evalToString(doc, "$.n").orElse(""));
        ok("missing path yields empty", JsonPathLite.evalToString(doc, "$.nope").isEmpty());
        ok("invalid path is rejected", !JsonPathLite.isValid("$.a["));
        ok("valid path is accepted", JsonPathLite.isValid("$.a.b[0].c"));

        // Round trip: format(parse(x)) == x for the syntax we emit.
        is("round trip", "$.a.b[1].c",
                JsonPathLite.format(JsonPathLite.parse("$.a.b[1].c")));

        // The reverse direction, which drives "select the text, get the rule".
        is("path to text", "$.messages[1].content",
                JsonPathLite.pathToText(doc, "hello there").orElse(""));
        is("path to partial text", "$.messages[1].content",
                JsonPathLite.pathToText(doc, "hello").orElse(""));

        JsonElement mutable = JsonPathLite.copy(doc);
        ok("setString writes", JsonPathLite.setString(mutable, "$.messages[1].content", "PROBE"));
        is("setString took effect", "PROBE",
                JsonPathLite.evalToString(mutable, "$.messages[1].content").orElse(""));
        is("original is untouched", "hello there",
                JsonPathLite.evalToString(doc, "$.messages[1].content").orElse(""));
        ok("setString refuses a multi-match wildcard",
                !JsonPathLite.setString(JsonPathLite.copy(doc), "$.a.b[*].c", "x"));
        ok("setString refuses a multi-match parent",
                !JsonPathLite.setString(JsonPathLite.copy(doc), "$.messages[*].content", "x"));
        ok("setString reports a miss",
                !JsonPathLite.setString(JsonPathLite.copy(doc), "$.absent", "x"));

        // A wildcard that happens to address exactly one node is unambiguous, so allow it.
        JsonElement single = Json.parse("{\"m\":[{\"c\":\"only\"}]}").orElseThrow();
        ok("setString allows a single-match wildcard",
                JsonPathLite.setString(single, "$.m[*].c", "written"));
        is("single-match wildcard wrote the value", "written",
                JsonPathLite.evalToString(single, "$.m[0].c").orElse(""));

        // A prompt containing JSON metacharacters must survive serialisation.
        JsonElement tricky = JsonPathLite.copy(doc);
        String nasty = "\"}]; DROP--\n\\ é 😀";
        JsonPathLite.setString(tricky, "$.messages[1].content", nasty);
        String serialised = Json.GSON.toJson(tricky);
        is("hostile prompt round-trips through JSON", nasty,
                JsonPathLite.evalToString(Json.parse(serialised).orElseThrow(),
                        "$.messages[1].content").orElse(""));
    }

    // --------------------------------------------------------------- Extractors

    private static void extractors() {
        section("Extractors");

        is("JSON path", "hi there", extract("{\"reply\":\"hi there\"}",
                ResponseExtractor.jsonPath("$.reply")));
        is("nested OpenAI shape", "hello",
                extract("{\"choices\":[{\"message\":{\"content\":\"hello\"}}]}",
                        ResponseExtractor.jsonPath("$.choices[0].message.content")));
        is("raw body", "not json at all",
                extract("not json at all", ResponseExtractor.raw()));

        Extractors.Result missing = Extractors.extract("{\"a\":1}",
                ResponseExtractor.jsonPath("$.b"));
        ok("missing field fails", !missing.ok());
        ok("failure explains itself", missing.problem().contains("$.b"));

        Extractors.Result notJson = Extractors.extract("<html>hi</html>",
                ResponseExtractor.jsonPath("$.a"));
        ok("non-JSON body fails clearly", !notJson.ok() && notJson.problem().contains("not JSON"));

        ResponseExtractor regex = new ResponseExtractor(ResponseExtractor.Mode.REGEX,
                "(?m)^0:\"(.*)\"$");
        is("regex concatenates every match", "HelloWorld",
                extract("0:\"Hello\"\n0:\"World\"\nd:{\"finish\":\"stop\"}", regex));

        ResponseExtractor html = new ResponseExtractor(ResponseExtractor.Mode.HTML_TEXT, "");
        is("html strips tags and scripts", "Hello world",
                extract("<div><script>var x=1;</script><p>Hello</p> <b>world</b></div>", html));

        // garak refuses a response_json_field that lands on a dict or list, so the
        // extension must refuse it too -- and say which, because the fix differs.
        Extractors.Result nonText = Extractors.extract(
                "{\"content\":[{\"type\":\"text\",\"text\":\"hi\"}]}",
                ResponseExtractor.jsonPath("$.content"));
        ok("a path landing on an array fails", !nonText.ok());
        ok("and says it matched an array, not text",
                nonText.problem().contains("array") && nonText.problem().contains("not text"));
        Extractors.Result objectMatch = Extractors.extract(
                "{\"message\":{\"role\":\"assistant\",\"content\":\"hi\"}}",
                ResponseExtractor.jsonPath("$.message"));
        ok("a path landing on an object fails", !objectMatch.ok());
        ok("and says it matched an object", objectMatch.problem().contains("object"));

        ResponseExtractor whitespace = ResponseExtractor.jsonPath("$.r");
        whitespace.normaliseWhitespace = true;
        is("whitespace normalisation", "a b c",
                extract("{\"r\":\"  a\\n\\n b   c \"}", whitespace));
    }

    private static void streaming() {
        section("Streaming");

        String openai = """
                data: {"choices":[{"delta":{"role":"assistant"}}]}

                data: {"choices":[{"delta":{"content":"Hel"}}]}

                data: {"choices":[{"delta":{"content":"lo"}}]}

                data: [DONE]

                """;
        is("OpenAI SSE reassembles", "Hello",
                extract(openai, ResponseExtractor.sse("$.choices[0].delta.content")));

        String anthropic = """
                event: content_block_delta
                data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"one "}}

                event: content_block_delta
                data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"two"}}

                """;
        is("Anthropic SSE reassembles", "one two",
                extract(anthropic, ResponseExtractor.sse("$.delta.text")));

        // Keep-alive comments and non-delta events must not break the stream.
        String noisy = """
                : ping

                data: {"type":"start"}

                data: {"text":"a"}

                data: {"type":"usage","tokens":9}

                data: {"text":"b"}

                """;
        is("noise between deltas is skipped", "ab",
                extract(noisy, ResponseExtractor.sse("$.text")));

        // Multi-line data fields join with a newline, per the SSE spec.
        is("multi-line data field", "line1\nline2",
                extract("data: line1\ndata: line2\n\n", ResponseExtractor.sse("")));

        String ndjson = """
                {"token":{"text":"foo"}}
                {"token":{"text":"bar"}}
                """;
        is("NDJSON reassembles", "foobar", extract(ndjson,
                new ResponseExtractor(ResponseExtractor.Mode.NDJSON_CONCAT, "$.token.text")));

        Extractors.Result wrongPath = Extractors.extract(openai,
                ResponseExtractor.sse("$.nope"));
        ok("wrong delta path fails", !wrongPath.ok());
        ok("wrong delta path says how many events it saw",
                wrongPath.problem().contains("events"));

        // The terminator must stop parsing rather than being treated as a delta.
        is("terminator stops the stream", "Hello",
                extract(openai + "data: {\"choices\":[{\"delta\":{\"content\":\"AFTER\"}}]}\n\n",
                        ResponseExtractor.sse("$.choices[0].delta.content")));
    }

    private static String extract(String body, ResponseExtractor spec) {
        Extractors.Result result = Extractors.extract(body, spec);
        return result.ok() ? result.text() : "<<failed: " + result.problem() + ">>";
    }

    // ----------------------------------------------------------- prompt detection

    private static void promptDetection() {
        section("Prompt auto-detection");

        is("simple {\"message\": ...} body", "$.message",
                guessPrompt("{\"message\":\"hello there\",\"model\":\"gpt-4\"}"));

        is("prefers 'prompt' over neighbours", "$.prompt",
                guessPrompt("{\"prompt\":\"tell me a joke\",\"text\":\"unused\"}"));

        // The OpenAI shape is the one a naive scorer gets wrong: the system prompt is
        // longer and equally 'content', but the user turn is what is under test.
        is("OpenAI messages array picks the last user turn", "$.messages[2].content",
                guessPrompt("""
                        {"model":"gpt-4",
                         "messages":[{"role":"system","content":"You are a careful and \
                         thorough assistant that always explains its reasoning at length."},
                                     {"role":"user","content":"earlier question"},
                                     {"role":"user","content":"what is the capital of France?"}],
                         "temperature":0.7}
                        """));

        is("assistant turns are not chosen", "$.messages[1].content",
                guessPrompt("""
                        {"messages":[{"role":"assistant","content":"How can I help you today?"},
                                     {"role":"user","content":"summarise this document"}]}
                        """));

        // Identifiers and metadata must never win, however prose-shaped the key looks.
        is("ignores uuids and metadata", "$.text",
                guessPrompt("""
                        {"conversation_id":"3f2504e0-4f89-11d3-9a0c-0305e82c3301",
                         "timestamp":"2026-09-02T10:00:00Z",
                         "model":"helpbot-1",
                         "text":"why is the sky blue?"}
                        """));

        ok("no guess when nothing looks like a message",
                RequestAnalyzer.bestGuessInJsonBody(
                        "{\"id\":\"abc\",\"n\":3,\"role\":\"user\"}").isEmpty());
        ok("non-JSON body yields no JSON candidates",
                RequestAnalyzer.detectInJsonBody("name=value&other=thing").isEmpty());
    }

    private static String guessPrompt(String body) {
        Optional<InsertionPoint> point = RequestAnalyzer.bestGuessInJsonBody(body);
        return point.map(value -> value.locator).orElse("<<no guess>>");
    }

    // ------------------------------------------------------------ reply detection

    private static void replyDetection() {
        section("Reply auto-detection");

        // Exactly what tools/mock_chat_server.py returns from /api/chat.
        is("mock plain JSON endpoint", "$.reply",
                guessReply("{\"conversationId\":\"ae5456b9-ba8f\","
                        + "\"reply\":\"You said: hello. As an AI assistant, here is my reply.\","
                        + "\"model\":\"helpbot-1\"}", "application/json"));

        is("OpenAI chat completions", "$.choices[0].message.content",
                guessReply("""
                        {"id":"chatcmpl-abc","object":"chat.completion","model":"helpbot-1",
                         "choices":[{"index":0,"finish_reason":"stop",
                                     "message":{"role":"assistant","content":"Sure, I can do that."}}],
                         "usage":{"total_tokens":42}}
                        """, "application/json"));

        is("Anthropic messages", "$.content[0].text",
                guessReply("{\"content\":[{\"type\":\"text\",\"text\":\"Hello from Claude\"}],"
                        + "\"stop_reason\":\"end_turn\"}", "application/json"));

        is("nested data envelope", "$.data.message",
                guessReply("{\"data\":{\"message\":\"You said: hi. Here is my reply.\"},"
                        + "\"status\":\"ok\"}", "application/json"));

        // The mock server's /api/stream output, verbatim in shape.
        ResponseExtractor stream = ResponseAnalyzer.bestGuess("""
                data: {"choices": [{"delta": {"role": "assistant"}}]}

                data: {"choices": [{"delta": {"content": "You said: st"}}]}

                data: {"choices": [{"delta": {"content": "ream me."}}]}

                data: {"usage": {"total_tokens": 42}}

                data: [DONE]

                """, "text/event-stream");
        is("SSE stream is detected as a stream", ResponseExtractor.Mode.SSE_CONCAT, stream.mode);
        is("SSE delta path", "$.choices[0].delta.content", stream.expression);
        is("SSE rule reassembles the reply", "You said: stream me.",
                extract("""
                        data: {"choices": [{"delta": {"role": "assistant"}}]}

                        data: {"choices": [{"delta": {"content": "You said: st"}}]}

                        data: {"choices": [{"delta": {"content": "ream me."}}]}

                        data: [DONE]

                        """, stream));

        // A stream mislabelled as JSON must still be recognised from its framing.
        is("stream detected despite a wrong content type", ResponseExtractor.Mode.SSE_CONCAT,
                ResponseAnalyzer.bestGuess(
                        "data: {\"text\":\"a\"}\n\ndata: {\"text\":\"b\"}\n\n",
                        "application/json").mode);

        ResponseExtractor html = ResponseAnalyzer.bestGuess(
                "<html><body><p>the reply</p></body></html>", "text/html");
        ok("HTML falls back to text extraction",
                html.mode == ResponseExtractor.Mode.HTML_TEXT
                        || html.mode == ResponseExtractor.Mode.RAW);

        is("unparseable body falls back to the whole body", ResponseExtractor.Mode.RAW,
                ResponseAnalyzer.bestGuess("just some text", "text/plain").mode);
    }

    private static String guessReply(String body, String contentType) {
        return ResponseAnalyzer.bestGuess(body, contentType).expression;
    }

    // ------------------------------------------------------------- calibration

    /** A target where exactly one field actually reaches the "model". */
    private static Calibrator.Sender target(String liveField, String shape) {
        return (point, prompt) -> {
            boolean reached = liveField.equals(point.locator);
            String reply = reached ? modelAnswer(prompt) : "I did not catch that.";
            String body = switch (shape) {
                case "openai" -> "{\"choices\":[{\"message\":{\"role\":\"assistant\","
                        + "\"content\":" + Json.GSON.toJson(reply) + "}}]}";
                case "sse" -> "data: {\"choices\":[{\"delta\":{\"content\":"
                        + Json.GSON.toJson(reply) + "}}]}\n\ndata: [DONE]\n\n";
                default -> "{\"reply\":" + Json.GSON.toJson(reply) + ",\"model\":\"m1\"}";
            };
            String contentType = "sse".equals(shape) ? "text/event-stream" : "application/json";
            return new Calibrator.Reply(200, body, contentType, 120, "");
        };
    }

    /** A cooperative model: answers the question and repeats the token it was given. */
    private static String modelAnswer(String prompt) {
        String token = prompt.contains("ALFA7Q2X") ? "ALFA7Q2X"
                : prompt.contains("BRAVO9M4K") ? "BRAVO9M4K" : "";
        String subject = prompt.contains("sky") ? "The sky is blue." : "A spider has eight legs.";
        return subject + " " + token;
    }

    private static void calibration() {
        section("Calibration");

        List<InsertionPoint> candidates = List.of(
                InsertionPoint.jsonPath("$.user"),
                InsertionPoint.jsonPath("$.message"),
                InsertionPoint.jsonPath("$.note"));

        // The whole point: the first guess is wrong, and only a live differential check
        // can tell, because the wrong field still returns a valid 200 with a valid reply.
        Calibrator.Outcome found = Calibrator.calibrate(
                candidates, target("$.message", "plain"), ignored -> { });
        is("skips a wrong insertion point and finds the live one", "$.message",
                found.point().locator);
        is("confirms via the echoed token", Calibrator.Confidence.ECHOED, found.confidence());
        is("picks the matching extraction rule", "$.reply", found.extractor().expression);
        ok("reports it is proven", found.proven() && found.usable());
        is("costs two requests per candidate tried", 4, found.requestsUsed());

        // Same search, but the reply arrives as a stream.
        Calibrator.Outcome streamed = Calibrator.calibrate(
                candidates, target("$.message", "sse"), ignored -> { });
        is("works against a streaming endpoint", "$.message", streamed.point().locator);
        is("chooses a stream extractor", ResponseExtractor.Mode.SSE_CONCAT,
                streamed.extractor().mode);
        ok("stream check is proven", streamed.proven());

        Calibrator.Outcome openai = Calibrator.calibrate(
                candidates, target("$.message", "openai"), ignored -> { });
        is("nested reply shape", "$.choices[0].message.content", openai.extractor().expression);

        // A model that ignores the token but still answers differently is still proof.
        Calibrator.Sender terse = (point, prompt) -> {
            String reply = !"$.message".equals(point.locator) ? "Hello!"
                    : prompt.contains("sky") ? "Blue." : "Eight.";
            return new Calibrator.Reply(200, "{\"reply\":" + Json.GSON.toJson(reply) + "}",
                    "application/json", 90, "");
        };
        Calibrator.Outcome differing = Calibrator.calibrate(candidates, terse, ignored -> { });
        is("differing replies are accepted as proof", Calibrator.Confidence.REPLIES_DIFFER,
                differing.confidence());
        is("and identify the live field", "$.message", differing.point().locator);

        // A canned-response endpoint cannot be proven, but must not be reported as broken.
        Calibrator.Sender canned = (point, prompt) -> new Calibrator.Reply(
                200, "{\"reply\":\"I am sorry, I cannot help with that.\"}",
                "application/json", 90, "");
        Calibrator.Outcome unproven = Calibrator.calibrate(candidates, canned, ignored -> { });
        is("identical replies are unconfirmed", Calibrator.Confidence.UNCONFIRMED,
                unproven.confidence());
        ok("unconfirmed is still usable", unproven.usable() && !unproven.proven());
        ok("and says why", unproven.headline().contains("did not change"));

        // Nothing usable at all.
        Calibrator.Sender broken = (point, prompt) ->
                new Calibrator.Reply(403, "", "", 0, "");
        Calibrator.Outcome failed = Calibrator.calibrate(candidates, broken, ignored -> { });
        is("a 403 fails the check", Calibrator.Confidence.FAILED, failed.confidence());
        ok("not usable", !failed.usable());
        ok("blames the expired session",
                String.join(" ", failed.notes()).contains("session"));

        Calibrator.Outcome none = Calibrator.calibrate(List.of(), canned, ignored -> { });
        is("no candidates fails cleanly", Calibrator.Confidence.FAILED, none.confidence());
        is("and sends nothing", 0, none.requestsUsed());

        // Budget: the search must stay cheap even when every candidate is wrong.
        java.util.concurrent.atomic.AtomicInteger sends =
                new java.util.concurrent.atomic.AtomicInteger();
        Calibrator.Sender counting = (point, prompt) -> {
            sends.incrementAndGet();
            return new Calibrator.Reply(200, "{\"reply\":\"same\"}", "application/json", 50, "");
        };
        List<InsertionPoint> many = new ArrayList<>();
        for (int i = 0; i < 12; i++) {
            many.add(InsertionPoint.jsonPath("$.f" + i));
        }
        Calibrator.calibrate(many, counting, ignored -> { });
        ok("bounded to at most 10 requests when nothing works (" + sends.get() + ")",
                sends.get() <= 10);
    }

    // --------------------------------------------------------------- throttling

    private static void throttling() {
        section("Auto-throttle and depth");

        RunConfig fast = new RunConfig();
        fast.applyAutoThrottle(80);
        ok("a fast endpoint gets a delay (" + fast.delayMs + "ms)", fast.delayMs > 0);
        ok("and is capped near three per second",
                1000.0 / Math.max(1, fast.delayMs) <= 3.5);

        RunConfig slow = new RunConfig();
        slow.applyAutoThrottle(4000);
        is("a slow endpoint needs no extra delay", 0, slow.delayMs);
        ok("but gets a longer reply timeout (" + slow.requestTimeoutMs + "ms)",
                slow.requestTimeoutMs >= 24_000);
        ok("timeout stays bounded", slow.requestTimeoutMs <= 180_000);

        RunConfig depth = new RunConfig();
        depth.probes = List.of("probes.a.A", "probes.b.B");
        ScanDepth.SMOKE.applyTo(depth);
        ok("a quick test stays small (" + depth.estimatedRequests() + " requests)",
                depth.estimatedRequests() <= 16);
        ScanDepth.THOROUGH.applyTo(depth);
        ok("thorough is much larger", depth.estimatedRequests() > 500);
    }

    // ----------------------------------------------------------------- platform

    private static void platform() {
        section("Cross-platform locator");

        // On POSIX a PATH entry is the bare name.
        is("posix looks for the bare name", List.of("garak"),
                GarakLocator.executableNames("garak", false, null));

        // On Windows it is really garak.exe, so searching the bare name finds nothing.
        List<String> windows = GarakLocator.executableNames("garak", true,
                ".COM;.EXE;.BAT;.CMD;.PY");
        ok("windows tries garak.exe", windows.contains("garak.exe"));
        ok("windows tries garak.bat", windows.contains("garak.bat"));
        ok("windows honours PATHEXT extras", windows.contains("garak.py"));
        ok("windows still tries the bare name (Git Bash, WSL)", windows.contains("garak"));
        ok("windows has a sane default without PATHEXT",
                GarakLocator.executableNames("garak", true, null).contains("garak.exe"));
        is("an explicit extension is left alone", List.of("garak.exe"),
                GarakLocator.executableNames("garak.exe", true, ".EXE"));

        // The interpreter-free route to the probe catalogue: garak --list_config.
        String listConfig = String.join("\n",
                "transient:",
                "    cache_dir: C:\\Users\\t\\AppData\\Local\\garak\\garak\\cache",
                "    package_dir: C:\\Python312\\Lib\\site-packages\\garak",
                "    run_id: None",
                "run:",
                "    generations: 5");
        is("finds package_dir in --list_config output",
                "C:\\Python312\\Lib\\site-packages\\garak",
                GarakLocator.parsePackageDir(listConfig).orElse(""));
        is("and on a posix path", "/home/t/.venv/lib/python3.12/site-packages/garak",
                GarakLocator.parsePackageDir(
                        "transient:\n    package_dir: /home/t/.venv/lib/python3.12/site-packages/garak\n")
                        .orElse(""));
        ok("absent package_dir yields nothing",
                GarakLocator.parsePackageDir("run:\n    generations: 5\n").isEmpty());
        ok("a None value yields nothing",
                GarakLocator.parsePackageDir("    package_dir: None\n").isEmpty());
        ok("null input is handled", GarakLocator.parsePackageDir(null).isEmpty());
    }

    // -------------------------------------------------------------- ConfigWriter

    private static void configWriter() {
        section("ConfigWriter");

        RunConfig config = new RunConfig();
        config.retries = 2;
        config.requestTimeoutMs = 60_000;
        config.delayMs = 250;
        config.jitterMs = 250;

        JsonObject generator = ConfigWriter.bridgeGenerator(
                "http://127.0.0.1:9999/garak/tok", "tok", config);
        JsonObject rest = generator.getAsJsonObject("rest").getAsJsonObject("RestGenerator");

        is("module nesting matches garak's -G format", "http://127.0.0.1:9999/garak/tok",
                Json.string(rest, "uri", ""));
        is("prompt template", "$INPUT",
                Json.string(rest.getAsJsonObject("req_template_json_object"), "prompt", ""));
        is("response field", "$.output", Json.string(rest, "response_json_field", ""));
        ok("response_json is on", Json.bool(rest, "response_json", false));
        is("auth header is sent", "tok",
                Json.string(rest.getAsJsonObject("headers"), "X-Garak-Bridge-Key", ""));
        is("429 is the rate-limit code", 429,
                rest.getAsJsonArray("ratelimit_codes").get(0).getAsInt());
        is("204 is the skip code", 204,
                rest.getAsJsonArray("skip_codes").get(0).getAsInt());

        // garak must outwait the bridge, or it abandons requests still being retried.
        int garakTimeout = Json.integer(rest, "request_timeout", 0);
        long bridgeWorstCase = (long) (config.retries + 1)
                * (config.requestTimeoutMs + config.delayMs + config.jitterMs) / 1000;
        ok("garak timeout exceeds the bridge's worst case ("
                        + garakTimeout + "s > " + bridgeWorstCase + "s)",
                garakTimeout > bridgeWorstCase);

        JsonObject run = ConfigWriter.runSettings(Path.of("/tmp/run-dir"), config);
        is("report_dir is absolute", "/tmp/run-dir",
                Json.string(run.getAsJsonObject("reporting"), "report_dir", ""));
        is("generations", 1, Json.integer(run.getAsJsonObject("run"), "generations", -1));
        ok("seed is omitted when unset", !run.getAsJsonObject("run").has("seed"));

        config.seed = 7;
        is("seed is written when set", 7, Json.integer(
                ConfigWriter.runSettings(Path.of("/x"), config).getAsJsonObject("run"), "seed", -1));

        // Both files must be loadable by garak's json-first config loader.
        ok("generator config is valid JSON", Json.parse(Json.PRETTY.toJson(generator)).isPresent());
        ok("run config is valid JSON", Json.parse(Json.PRETTY.toJson(run)).isPresent());
    }

    // ----------------------------------------------------------- report decoding

    private static void reportDecoding() {
        section("Report decoding");

        // The shape garak actually writes: a Conversation of Turns holding Messages.
        JsonElement conversation = Json.parse("""
                {"turns":[{"role":"user","content":{"text":"first turn","lang":"en"}},
                          {"role":"user","content":{"text":"the probe prompt","lang":"en"}}],
                 "notes":{}}
                """).orElseThrow();
        is("prompt comes from the last turn", "the probe prompt",
                ReportTailer.promptText(conversation));

        is("plain string prompt still works", "legacy",
                ReportTailer.promptText(Json.parse("\"legacy\"").orElseThrow()));
        is("null prompt is empty", "", ReportTailer.promptText(null));

        is("message text", "the model said this", ReportTailer.messageText(
                Json.parse("{\"text\":\"the model said this\",\"lang\":\"en\"}").orElseThrow()));
        is("null output is empty", "", ReportTailer.messageText(null));
    }

    // ------------------------------------------------------------------ catalogue

    private static void catalogue(Path pluginCache) {
        section("PluginCatalog");
        if (pluginCache == null || !Files.isRegularFile(pluginCache)) {
            System.out.println("  (skipped: no plugin_cache.json supplied)");
            return;
        }
        PluginCatalog catalogue = PluginCatalog.fromPluginCache(pluginCache);
        ok("probes were parsed (" + catalogue.probes().size() + ")",
                catalogue.probes().size() > 100);
        ok("families were derived", catalogue.families().size() > 20);
        ok("owasp tags are present",
                catalogue.tags().stream().anyMatch(tag -> tag.startsWith("owasp:llm01")));

        Optional<PluginCatalog.Probe> dan = catalogue.probes().stream()
                .filter(probe -> probe.family().equals("dan")).findFirst();
        ok("dan family exists", dan.isPresent());
        dan.ifPresent(probe -> {
            ok("dan probe has a goal", !probe.goal().isBlank());
            ok("dan probe is text-only", probe.textOnly());
            ok("dan probe is runnable through the bridge", probe.isReadyToRun());
        });

        // Probes that drive their own attacker model cannot run against a bare bridge.
        long secondaryModel = catalogue.probes().stream()
                .filter(PluginCatalog.Probe::needsSecondaryModel).count();
        ok("probes needing an attacker model are flagged (" + secondaryModel + ")",
                secondaryModel > 0);
        catalogue.probes().stream()
                .filter(probe -> probe.family().equals("tap"))
                .findFirst()
                .ifPresent(probe -> ok("tap is flagged as needing a second model",
                        probe.needsSecondaryModel() && !probe.isReadyToRun()));

        // Non-text probes cannot work through a text bridge.
        long nonText = catalogue.probes().stream()
                .filter(probe -> !probe.textOnly()).count();
        ok("non-text probes are flagged (" + nonText + ")", nonText > 0);

        for (PluginCatalog.Preset preset : PluginCatalog.presets()) {
            List<String> resolved = catalogue.resolve(preset);
            ok("preset \"" + preset.name() + "\" resolves (" + resolved.size() + " probes)",
                    !resolved.isEmpty());
            ok("preset \"" + preset.name() + "\" names are fully qualified",
                    resolved.stream().allMatch(name -> name.startsWith("probes.")));
        }
    }

    // ------------------------------------------------------------------- harness

    private static void section(String name) {
        System.out.println("\n" + name);
    }

    private static void ok(String what, boolean condition) {
        if (condition) {
            passed++;
            System.out.println("  ok   " + what);
        } else {
            failures.add(what);
            System.out.println("  FAIL " + what);
        }
    }

    private static void is(String what, Object expected, Object actual) {
        boolean equal = expected == null ? actual == null : expected.equals(actual);
        if (equal) {
            passed++;
            System.out.println("  ok   " + what);
        } else {
            failures.add(what + " (expected " + quote(expected) + ", got " + quote(actual) + ")");
            System.out.println("  FAIL " + what + "\n         expected " + quote(expected)
                    + "\n         got      " + quote(actual));
        }
    }

    private static String quote(Object value) {
        return value instanceof String text ? "\"" + text.replace("\n", "\\n") + "\"" : String.valueOf(value);
    }

    private static void is(String what, int expected, int actual) {
        is(what, Integer.valueOf(expected), Integer.valueOf(actual));
    }
}
