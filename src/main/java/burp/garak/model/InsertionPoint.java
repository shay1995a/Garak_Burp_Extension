// Copyright 2026 the garak Bridge authors
// SPDX-License-Identifier: Apache-2.0

package burp.garak.model;

/**
 * Where a garak prompt is spliced into the captured request.
 *
 * <p>Modelled structurally wherever possible ({@link Kind#JSON_PATH},
 * {@link Kind#BODY_PARAM}, {@link Kind#QUERY_PARAM}, {@link Kind#HEADER}) rather than as a
 * byte range, because prompts vary in length: a structural edit re-serialises the message
 * and lets Burp recompute Content-Length, while a byte range recorded against the captured
 * message stops being meaningful the moment the payload is a different size.
 *
 * <p>{@link Kind#RAW_OFFSET} exists for messages the parsers cannot model -- a proprietary
 * binary-ish body, say -- and is only ever produced from an explicit user selection.
 */
public class InsertionPoint {

    public enum Kind {
        /** Replace the string addressed by a JSONPath in the JSON body. */
        JSON_PATH,
        /** Replace a body parameter (form-encoded or multipart). */
        BODY_PARAM,
        /** Replace a URL query parameter. */
        QUERY_PARAM,
        /** Replace a request header value. */
        HEADER,
        /** Replace a byte range of the raw request. */
        RAW_OFFSET
    }

    /** How the prompt is encoded before it is written into the message. */
    public enum Encoding {
        /**
         * Whatever is correct for this location: none for a JSON path (the serialiser
         * escapes), percent-encoding for a form or query parameter. The right default.
         */
        AUTO,
        /** Insert the prompt verbatim, escaping nothing. */
        RAW,
        /** Escape as a JSON string body, without the surrounding quotes. */
        JSON_STRING,
        /** Percent-encode for a URL or form field. */
        URL,
        /** Base64, for endpoints that wrap the message. */
        BASE64
    }

    public Kind kind = Kind.JSON_PATH;

    /** JSONPath, parameter name or header name, depending on {@link #kind}. */
    public String locator = "";

    public Encoding encoding = Encoding.AUTO;

    /** Text placed immediately before the prompt; lets a probe ride inside a longer message. */
    public String prefix = "";

    /** Text placed immediately after the prompt. */
    public String suffix = "";

    /** Byte range, {@link Kind#RAW_OFFSET} only. */
    public int start;
    public int end;

    public InsertionPoint() {
    }

    public InsertionPoint(Kind kind, String locator, Encoding encoding) {
        this.kind = kind;
        this.locator = locator;
        this.encoding = encoding;
    }

    public static InsertionPoint jsonPath(String path) {
        return new InsertionPoint(Kind.JSON_PATH, path, Encoding.AUTO);
    }

    public static InsertionPoint bodyParam(String name) {
        return new InsertionPoint(Kind.BODY_PARAM, name, Encoding.AUTO);
    }

    public static InsertionPoint queryParam(String name) {
        return new InsertionPoint(Kind.QUERY_PARAM, name, Encoding.AUTO);
    }

    public static InsertionPoint rawOffset(int start, int end, Encoding encoding) {
        InsertionPoint point = new InsertionPoint(Kind.RAW_OFFSET, "", encoding);
        point.start = start;
        point.end = end;
        return point;
    }

    /** Applies prefix/suffix wrapping. Encoding is applied separately, by the writer. */
    public String wrap(String prompt) {
        if (prefix.isEmpty() && suffix.isEmpty()) {
            return prompt;
        }
        return prefix + prompt + suffix;
    }

    public InsertionPoint copy() {
        InsertionPoint clone = new InsertionPoint(kind, locator, encoding);
        clone.prefix = prefix;
        clone.suffix = suffix;
        clone.start = start;
        clone.end = end;
        return clone;
    }

    /** Short human description for the UI list. */
    public String describe() {
        String where = switch (kind) {
            case JSON_PATH -> "JSON " + locator;
            case BODY_PARAM -> "body param " + locator;
            case QUERY_PARAM -> "query param " + locator;
            case HEADER -> "header " + locator;
            case RAW_OFFSET -> "bytes " + start + "-" + end;
        };
        return encoding == Encoding.AUTO ? where : where + " (" + encoding.name().toLowerCase() + ")";
    }

    @Override
    public String toString() {
        return describe();
    }
}
