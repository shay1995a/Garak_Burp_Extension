// Copyright 2026 the garak Bridge authors
// SPDX-License-Identifier: Apache-2.0

package burp.garak.bridge;

import burp.garak.model.ResponseExtractor;
import burp.garak.util.Json;
import burp.garak.util.JsonPathLite;
import com.google.gson.JsonElement;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Turns a raw response body into the single string garak scores.
 *
 * <p>Every mode is pure and side-effect free, so the "Test connection" panel can run one
 * against a captured body and show the user exactly what a probe would see.
 */
public final class Extractors {

    /** Outcome of an extraction: the text, or why there wasn't any. */
    public record Result(String text, boolean ok, String problem) {
        public static Result of(String text) {
            return new Result(text, true, "");
        }

        public static Result failed(String problem) {
            return new Result("", false, problem);
        }
    }

    /** Tags stripped whole, including their content, before HTML text extraction. */
    private static final Pattern SCRIPT_OR_STYLE =
            Pattern.compile("(?is)<(script|style)\\b[^>]*>.*?</\\1>");
    private static final Pattern HTML_TAG = Pattern.compile("<[^>]+>");
    private static final Pattern WHITESPACE_RUN = Pattern.compile("\\s+");

    private Extractors() {
    }

    public static Result extract(String body, ResponseExtractor spec) {
        if (body == null) {
            return Result.failed("no response body");
        }
        Result result = switch (spec.mode) {
            case RAW -> Result.of(body);
            case JSON_PATH -> jsonPath(body, spec.expression);
            case SSE_CONCAT -> streamConcat(sseEvents(body), spec);
            case NDJSON_CONCAT -> streamConcat(ndjsonEvents(body), spec);
            case REGEX -> regex(body, spec.expression);
            case HTML_TEXT -> Result.of(htmlText(body));
        };

        if (!result.ok()) {
            return result;
        }
        String text = result.text();
        if (spec.normaliseWhitespace) {
            text = WHITESPACE_RUN.matcher(text).replaceAll(" ").trim();
        }
        return Result.of(text);
    }

    // -------------------------------------------------------------- JSON body

    private static Result jsonPath(String body, String expression) {
        Optional<JsonElement> parsed = Json.parse(body);
        if (parsed.isEmpty()) {
            return Result.failed("response is not JSON (first 120 chars: " + peek(body) + ")");
        }
        if (!JsonPathLite.isValid(expression)) {
            return Result.failed("not a valid path: " + expression);
        }
        // The outcomes are reported separately because they need different fixes:
        // a typo'd path, a path one level too shallow, or a response that changed shape.
        JsonPathLite.Text resolved = JsonPathLite.evalToText(parsed.get(), expression);
        if (resolved instanceof JsonPathLite.Text.Matched matched) {
            return Result.of(matched.value());
        }
        if (resolved instanceof JsonPathLite.Text.NotText notText) {
            return Result.failed("path " + expression + " matched a JSON " + notText.type()
                    + ", not text. garak needs a single string; point the path at the field "
                    + "inside it. Matched: " + notText.preview());
        }
        return Result.failed("path " + expression + " matched nothing in the response JSON");
    }

    // ---------------------------------------------------------------- streams

    /**
     * Splits a text/event-stream body into event payloads.
     *
     * <p>Follows the SSE framing rules that matter here: events are separated by a blank
     * line, {@code data:} lines within one event join with a newline, and one optional
     * space after the colon is not part of the value. Other fields are ignored.
     */
    public static List<String> sseEvents(String body) {
        List<String> events = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        boolean sawData = false;

        for (String line : body.split("\r\n|\n|\r", -1)) {
            if (line.isEmpty()) {
                if (sawData) {
                    events.add(current.toString());
                }
                current.setLength(0);
                sawData = false;
                continue;
            }
            if (line.startsWith(":")) {
                continue; // comment / keep-alive
            }
            if (line.startsWith("data:")) {
                String value = line.substring(5);
                if (value.startsWith(" ")) {
                    value = value.substring(1);
                }
                if (sawData) {
                    current.append('\n');
                }
                current.append(value);
                sawData = true;
            }
        }
        if (sawData) {
            events.add(current.toString());
        }
        return events;
    }

    /** Newline-delimited JSON: one payload per non-blank line. */
    public static List<String> ndjsonEvents(String body) {
        List<String> events = new ArrayList<>();
        for (String line : body.split("\r\n|\n|\r", -1)) {
            String trimmed = line.trim();
            if (!trimmed.isEmpty()) {
                events.add(trimmed);
            }
        }
        return events;
    }

    /**
     * Concatenates the delta from every event.
     *
     * <p>Events that do not carry the delta are skipped rather than failing the whole
     * extraction: a real stream is full of role announcements, usage summaries and
     * keep-alives that legitimately have nothing at the delta path.
     */
    private static Result streamConcat(List<String> events, ResponseExtractor spec) {
        if (events.isEmpty()) {
            return Result.failed("no stream events found in the response body");
        }

        String terminator = spec.streamTerminator == null ? "" : spec.streamTerminator.trim();
        boolean pathGiven = spec.expression != null && !spec.expression.isBlank();
        if (pathGiven && !JsonPathLite.isValid(spec.expression)) {
            return Result.failed("not a valid path: " + spec.expression);
        }

        StringBuilder out = new StringBuilder();
        int matched = 0;
        int parsedEvents = 0;

        for (String event : events) {
            if (!terminator.isEmpty() && event.trim().equals(terminator)) {
                break;
            }
            if (!pathGiven) {
                // No path: the events are plain text deltas.
                out.append(event);
                matched++;
                continue;
            }
            Optional<JsonElement> parsed = Json.parse(event);
            if (parsed.isEmpty()) {
                continue;
            }
            parsedEvents++;
            Optional<String> delta = JsonPathLite.evalToString(parsed.get(), spec.expression);
            if (delta.isPresent()) {
                out.append(delta.get());
                matched++;
            }
        }

        if (matched == 0) {
            String detail = pathGiven && parsedEvents == 0
                    ? "none of the " + events.size() + " events were JSON"
                    : "path " + spec.expression + " matched nothing in any of the "
                            + events.size() + " events";
            return Result.failed("stream produced no text: " + detail);
        }
        return Result.of(out.toString());
    }

    // ----------------------------------------------------------------- regex

    /**
     * Concatenates group 1 of every match, so a pattern also works against streaming
     * protocols that emit one chunk per line (the Vercel AI SDK's {@code 0:"..."} being
     * the common one). A pattern with no groups contributes its whole match.
     */
    private static Result regex(String body, String expression) {
        if (expression == null || expression.isBlank()) {
            return Result.failed("no pattern set");
        }
        Pattern pattern;
        try {
            pattern = Pattern.compile(expression);
        } catch (PatternSyntaxException e) {
            return Result.failed("bad pattern: " + e.getDescription());
        }
        Matcher matcher = pattern.matcher(body);
        StringBuilder out = new StringBuilder();
        int matches = 0;
        while (matcher.find()) {
            out.append(matcher.groupCount() >= 1 && matcher.group(1) != null
                    ? matcher.group(1)
                    : matcher.group());
            matches++;
        }
        return matches == 0
                ? Result.failed("pattern matched nothing in the response body")
                : Result.of(out.toString());
    }

    // ------------------------------------------------------------------ HTML

    public static String htmlText(String body) {
        String stripped = SCRIPT_OR_STYLE.matcher(body).replaceAll(" ");
        stripped = HTML_TAG.matcher(stripped).replaceAll(" ");
        stripped = unescapeEntities(stripped);
        return WHITESPACE_RUN.matcher(stripped).replaceAll(" ").trim();
    }

    /** The handful of entities that actually show up in chat markup. */
    private static String unescapeEntities(String text) {
        return text.replace("&nbsp;", " ")
                .replace("&amp;", "&")
                .replace("&lt;", "<")
                .replace("&gt;", ">")
                .replace("&quot;", "\"")
                .replace("&#39;", "'")
                .replace("&apos;", "'");
    }

    private static String peek(String body) {
        String flat = body.replace('\n', ' ').replace('\r', ' ').trim();
        return flat.length() <= 120 ? flat : flat.substring(0, 120) + "…";
    }
}
