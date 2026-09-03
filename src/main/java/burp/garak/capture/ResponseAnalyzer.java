// Copyright 2026 the garak Bridge authors
// SPDX-License-Identifier: Apache-2.0

package burp.garak.capture;

import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.garak.bridge.Extractors;
import burp.garak.model.ResponseExtractor;
import burp.garak.util.Json;
import burp.garak.util.JsonPathLite;
import com.google.gson.JsonElement;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

/**
 * Works out how to read the assistant's reply out of a captured response.
 *
 * <p>Detection is verified rather than guessed: every candidate rule is actually run
 * against the captured body, and only rules that produce text are offered. That matters
 * because the cost of a wrong rule is a whole scan's worth of empty answers that garak's
 * detectors will score as if the model had said nothing.
 */
public final class ResponseAnalyzer {

    /**
     * Reply locations for the APIs that chat front-ends are usually built on, checked
     * before any heuristic. Order is preference order.
     */
    private static final List<String> KNOWN_JSON_PATHS = List.of(
            "$.choices[0].message.content",          // OpenAI chat completions
            "$.choices[0].text",                     // OpenAI legacy completions
            "$.content[0].text",                     // Anthropic messages
            "$.candidates[0].content.parts[0].text", // Gemini
            "$.output[0].content[0].text",           // OpenAI responses API
            "$.message.content",
            "$.generated_text",
            "$[0].generated_text",                   // HF inference
            "$.response", "$.answer", "$.reply", "$.completion", "$.output",
            "$.result", "$.text", "$.message", "$.content", "$.data.message",
            "$.data.response", "$.data.text", "$.data.answer", "$.data.content");

    /** Per-event delta locations for the streaming protocols in common use. */
    private static final List<String> KNOWN_STREAM_PATHS = List.of(
            "$.choices[0].delta.content",             // OpenAI streaming
            "$.delta.text",                           // Anthropic streaming
            "$.candidates[0].content.parts[0].text",  // Gemini streaming
            "$.token.text",                           // HF text-generation-inference
            "$.choices[0].text",
            "$.message.content",
            "$.delta", "$.text", "$.content", "$.chunk", "$.token",
            "$.answer", "$.response", "$.message", "$.data", "$.v");

    private static final Set<String> STRONG_KEYS = Set.of(
            "response", "answer", "reply", "completion", "output", "generated_text",
            "generatedtext", "result", "assistant", "bot_message", "botmessage");

    private static final Set<String> WEAK_KEYS = Set.of(
            "text", "content", "message", "data", "value", "body", "msg");

    private static final Set<String> NEGATIVE_KEYS = Set.of(
            "id", "uuid", "role", "type", "model", "object", "created", "finish_reason",
            "conversation_id", "conversationid", "message_id", "messageid", "status",
            "error", "code", "index", "usage", "timestamp", "stop_reason", "signature");

    /** A rule that was tried against the captured body, with what it actually produced. */
    public record Candidate(ResponseExtractor extractor, int score, String produced, String reason) {
    }

    private ResponseAnalyzer() {
    }

    // ------------------------------------------------------------ from a selection

    /**
     * Derives an extraction rule from reply text the user highlighted in the response
     * editor. This is the reliable path: the user can see the answer, so pointing at it
     * beats any heuristic.
     */
    public static Optional<ResponseExtractor> fromSelection(HttpResponse response, Range selection) {
        if (response == null || selection == null
                || selection.endIndexExclusive() <= selection.startIndexInclusive()) {
            return Optional.empty();
        }
        byte[] raw = response.toByteArray().getBytes();
        int start = selection.startIndexInclusive();
        int end = Math.min(selection.endIndexExclusive(), raw.length);
        if (start >= end) {
            return Optional.empty();
        }
        String selected = new String(raw, start, end - start, StandardCharsets.UTF_8).trim();
        if (selected.isEmpty()) {
            return Optional.empty();
        }
        String body = response.bodyToString();

        // A streaming body is chopped into deltas, so the selection is at most one chunk;
        // find the delta path that reproduces text containing it.
        String contentType = headerValue(response, "Content-Type");
        if (isStream(contentType, body)) {
            List<String> events = eventsFor(contentType, body);
            for (String path : KNOWN_STREAM_PATHS) {
                ResponseExtractor candidate = streamExtractor(contentType, body, path);
                Extractors.Result result = Extractors.extract(body, candidate);
                if (result.ok() && result.text().contains(unescape(selected))) {
                    return Optional.of(candidate);
                }
            }
            if (!events.isEmpty()) {
                return Optional.of(streamExtractor(contentType, body, ""));
            }
        }

        Optional<JsonElement> parsed = Json.parse(body);
        if (parsed.isPresent()) {
            Optional<String> path = JsonPathLite.pathToText(parsed.get(), unescape(selected));
            if (path.isEmpty()) {
                // The selection is raw wire text, still JSON-escaped.
                for (JsonPathLite.Leaf leaf : JsonPathLite.leaves(parsed.get())) {
                    if (Json.escapeBody(leaf.value()).contains(selected)) {
                        path = Optional.of(leaf.path());
                        break;
                    }
                }
            }
            if (path.isPresent()) {
                return Optional.of(ResponseExtractor.jsonPath(path.get()));
            }
        }

        return Optional.empty();
    }

    // -------------------------------------------------------------- auto-detect

    /** Rules that demonstrably produce text from this response, best first. */
    public static List<Candidate> detect(HttpResponse response) {
        if (response == null) {
            return List.of();
        }
        return detect(response.bodyToString(), headerValue(response, "Content-Type"));
    }

    /**
     * The body-level detection, separated from Burp's response object so it can be
     * exercised directly against a captured body.
     */
    public static List<Candidate> detect(String body, String contentType) {
        List<Candidate> candidates = new ArrayList<>();
        if (body == null || body.isEmpty()) {
            return candidates;
        }

        if (isStream(contentType, body)) {
            for (String path : KNOWN_STREAM_PATHS) {
                ResponseExtractor extractor = streamExtractor(contentType, body, path);
                Extractors.Result result = Extractors.extract(body, extractor);
                if (result.ok() && !result.text().isBlank()) {
                    candidates.add(new Candidate(extractor, 60 + lengthBonus(result.text()),
                            preview(result.text()), "streamed deltas at " + path));
                }
            }
            if (candidates.isEmpty()) {
                // Plain-text deltas: no per-event JSON at all.
                ResponseExtractor extractor = streamExtractor(contentType, body, "");
                Extractors.Result result = Extractors.extract(body, extractor);
                if (result.ok() && !result.text().isBlank()) {
                    candidates.add(new Candidate(extractor, 40, preview(result.text()),
                            "streamed plain-text deltas"));
                }
            }
        }

        Optional<JsonElement> parsed = Json.parse(body);
        if (parsed.isPresent()) {
            for (String path : KNOWN_JSON_PATHS) {
                Optional<String> value = JsonPathLite.evalToString(parsed.get(), path);
                if (value.isPresent() && !value.get().isBlank()) {
                    candidates.add(new Candidate(ResponseExtractor.jsonPath(path),
                            70 + lengthBonus(value.get()), preview(value.get()),
                            "known API shape " + path));
                }
            }
            for (JsonPathLite.Leaf leaf : JsonPathLite.leaves(parsed.get())) {
                if (leaf.value().isBlank()) {
                    continue;
                }
                int score = scoreKey(leaf.key()) + lengthBonus(leaf.value()) - leaf.depth();
                if (score > 0) {
                    candidates.add(new Candidate(ResponseExtractor.jsonPath(leaf.path()), score,
                            preview(leaf.value()), "field '" + leaf.key() + "'"));
                }
            }
        }

        if (candidates.isEmpty()) {
            if (isHtml(contentType)) {
                String text = Extractors.htmlText(body);
                if (!text.isBlank()) {
                    candidates.add(new Candidate(new ResponseExtractor(ResponseExtractor.Mode.HTML_TEXT, ""),
                            20, preview(text), "HTML text content"));
                }
            }
            candidates.add(new Candidate(ResponseExtractor.raw(), 5, preview(body),
                    "whole response body"));
        }

        candidates.sort(Comparator.comparingInt(Candidate::score).reversed());
        return dedupe(candidates);
    }

    /** The best rule for this response, always returning something usable. */
    public static ResponseExtractor bestGuess(HttpResponse response) {
        return detect(response).stream()
                .findFirst()
                .map(Candidate::extractor)
                .orElseGet(ResponseExtractor::raw);
    }

    /** The best rule for a captured body, for testing and for previewing a paste. */
    public static ResponseExtractor bestGuess(String body, String contentType) {
        return detect(body, contentType).stream()
                .findFirst()
                .map(Candidate::extractor)
                .orElseGet(ResponseExtractor::raw);
    }

    // ------------------------------------------------------------------ helpers

    /**
     * Content-Type is the signal, but servers get it wrong often enough that the body
     * shape is checked too: {@code data:} framing means a stream whatever the header says.
     */
    private static boolean isStream(String rawContentType, String body) {
        String contentType = rawContentType == null ? "" : rawContentType.toLowerCase(Locale.ROOT);
        if (contentType.contains("event-stream")) {
            return true;
        }
        if (contentType.contains("ndjson") || contentType.contains("jsonlines")) {
            return true;
        }
        if (body.startsWith("data:") || body.contains("\ndata:")) {
            return true;
        }
        // Several standalone JSON documents, one per line, is a stream in all but name.
        String[] lines = body.split("\r\n|\n", 4);
        int jsonLines = 0;
        for (String line : lines) {
            if (line.trim().startsWith("{") && Json.parse(line.trim()).isPresent()) {
                jsonLines++;
            }
        }
        return jsonLines >= 2 && Json.parse(body).isEmpty();
    }

    private static boolean isNdjson(String rawContentType, String body) {
        String contentType = rawContentType == null ? "" : rawContentType.toLowerCase(Locale.ROOT);
        if (contentType.contains("event-stream")) {
            return false;
        }
        return !body.startsWith("data:") && !body.contains("\ndata:");
    }

    private static ResponseExtractor streamExtractor(String contentType, String body, String path) {
        ResponseExtractor.Mode mode = isNdjson(contentType, body)
                ? ResponseExtractor.Mode.NDJSON_CONCAT
                : ResponseExtractor.Mode.SSE_CONCAT;
        return new ResponseExtractor(mode, path);
    }

    private static List<String> eventsFor(String contentType, String body) {
        return isNdjson(contentType, body)
                ? Extractors.ndjsonEvents(body) : Extractors.sseEvents(body);
    }

    private static boolean isHtml(String contentType) {
        return contentType != null && contentType.toLowerCase(Locale.ROOT).contains("html");
    }

    private static String headerValue(HttpResponse response, String name) {
        try {
            String value = response.headerValue(name);
            return value == null ? "" : value;
        } catch (RuntimeException e) {
            return "";
        }
    }

    /** Longer replies are more likely to be the actual answer than a status string. */
    private static int lengthBonus(String text) {
        int length = text.trim().length();
        if (length == 0) {
            return -20;
        }
        if (length < 4) {
            return -10;
        }
        return Math.min(20, length / 20);
    }

    private static int scoreKey(String key) {
        if (key == null || key.isEmpty()) {
            return 0;
        }
        String normalised = key.toLowerCase(Locale.ROOT);
        if (STRONG_KEYS.contains(normalised)) {
            return 45;
        }
        if (WEAK_KEYS.contains(normalised)) {
            return 18;
        }
        if (NEGATIVE_KEYS.contains(normalised)) {
            return -50;
        }
        return 0;
    }

    /** Keeps the highest-scoring candidate per rule, so known shapes don't repeat as leaves. */
    private static List<Candidate> dedupe(List<Candidate> candidates) {
        List<Candidate> unique = new ArrayList<>();
        for (Candidate candidate : candidates) {
            boolean seen = unique.stream().anyMatch(existing ->
                    existing.extractor().mode == candidate.extractor().mode
                            && existing.extractor().expression.equals(candidate.extractor().expression));
            if (!seen) {
                unique.add(candidate);
            }
        }
        return unique;
    }

    private static String unescape(String selected) {
        return Json.parse("\"" + selected.replace("\"", "\\\"") + "\"")
                .filter(JsonElement::isJsonPrimitive)
                .map(JsonElement::getAsString)
                .orElse(selected);
    }

    private static String preview(String text) {
        String flat = text.replace('\n', ' ').replace('\r', ' ').trim();
        return flat.length() <= 90 ? flat : flat.substring(0, 89) + "…";
    }
}
