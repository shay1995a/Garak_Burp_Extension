// Copyright 2026 the garak Bridge authors
// SPDX-License-Identifier: Apache-2.0

package burp.garak.model;

/**
 * How the assistant's reply is recovered from the target's response.
 *
 * <p>garak only ever sees the extracted string, so this is the single point where the
 * variety of real chat endpoints -- plain JSON, server-sent events, newline-delimited
 * JSON, HTML fragments -- is collapsed into one text answer.
 */
public class ResponseExtractor {

    public enum Mode {
        /** The whole response body is the reply. */
        RAW,
        /** A JSONPath into a JSON body. */
        JSON_PATH,
        /** Concatenate a field from every {@code data:} event of a text/event-stream. */
        SSE_CONCAT,
        /** Concatenate a field from every line of a newline-delimited JSON stream. */
        NDJSON_CONCAT,
        /** First capturing group of a regular expression over the body. */
        REGEX,
        /** Strip tags and return the text content. */
        HTML_TEXT
    }

    public Mode mode = Mode.JSON_PATH;

    /**
     * JSONPath for {@link Mode#JSON_PATH}; the per-event JSONPath for the streaming modes;
     * the pattern for {@link Mode#REGEX}. Unused for {@link Mode#RAW} and {@link Mode#HTML_TEXT}.
     */
    public String expression = "$.response";

    /**
     * Streaming modes only: an event payload equal to this marks end of stream and is not
     * parsed. Defaults to the OpenAI/SSE convention.
     */
    public String streamTerminator = "[DONE]";

    /** Collapse runs of whitespace and trim. Off by default -- detectors care about layout. */
    public boolean normaliseWhitespace;

    /** Treat an empty extraction as a skipped generation rather than an empty answer. */
    public boolean emptyIsSkip = true;

    public ResponseExtractor() {
    }

    public ResponseExtractor(Mode mode, String expression) {
        this.mode = mode;
        this.expression = expression;
    }

    public static ResponseExtractor jsonPath(String path) {
        return new ResponseExtractor(Mode.JSON_PATH, path);
    }

    public static ResponseExtractor sse(String deltaPath) {
        return new ResponseExtractor(Mode.SSE_CONCAT, deltaPath);
    }

    public static ResponseExtractor raw() {
        return new ResponseExtractor(Mode.RAW, "");
    }

    public ResponseExtractor copy() {
        ResponseExtractor clone = new ResponseExtractor(mode, expression);
        clone.streamTerminator = streamTerminator;
        clone.normaliseWhitespace = normaliseWhitespace;
        clone.emptyIsSkip = emptyIsSkip;
        return clone;
    }

    public String describe() {
        return switch (mode) {
            case RAW -> "whole body";
            case JSON_PATH -> "JSON " + expression;
            case SSE_CONCAT -> "SSE deltas at " + expression;
            case NDJSON_CONCAT -> "NDJSON deltas at " + expression;
            case REGEX -> "regex " + expression;
            case HTML_TEXT -> "HTML text";
        };
    }

    @Override
    public String toString() {
        return describe();
    }
}
