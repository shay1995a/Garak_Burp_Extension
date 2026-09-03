// Copyright 2026 the garak Bridge authors
// SPDX-License-Identifier: Apache-2.0

package burp.garak.bridge;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.garak.model.InsertionPoint;
import burp.garak.model.TargetProfile;
import burp.garak.util.Json;
import burp.garak.util.JsonPathLite;
import com.google.gson.JsonElement;

import java.io.ByteArrayOutputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Splices a garak prompt into the captured request. */
public final class RequestBuilder {

    /** Prelude captures are referenced as {@code {{name}}}. */
    private static final Pattern VARIABLE = Pattern.compile("\\{\\{([A-Za-z0-9_.-]+)}}");

    /** What was built, plus anything the user should know about how it was built. */
    public record Built(HttpRequest request, List<String> warnings) {
    }

    private RequestBuilder() {
    }

    /**
     * Builds the request for one prompt.
     *
     * <p>Variables are substituted before the prompt goes in, never after. garak prompts
     * are adversarial text that quite legitimately contains braces and template syntax;
     * substituting afterwards would let a probe's payload address the extension's own
     * variables.
     */
    public static Built build(TargetProfile profile, String prompt, Map<String, String> variables) {
        List<String> warnings = new ArrayList<>();

        HttpRequest request = substituteVariables(profile.request(), variables, warnings);

        for (String header : profile.dropHeaders) {
            if (!header.isBlank() && request.hasHeader(header)) {
                request = request.withRemovedHeader(header);
            }
        }

        for (InsertionPoint point : profile.insertionPoints) {
            request = apply(request, point, prompt, warnings);
        }

        return new Built(request, warnings);
    }

    // ------------------------------------------------------------------ insertion

    private static HttpRequest apply(HttpRequest request, InsertionPoint point, String prompt,
                                     List<String> warnings) {
        String wrapped = point.wrap(prompt);
        return switch (point.kind) {
            case JSON_PATH -> applyJsonPath(request, point, wrapped, warnings);
            case QUERY_PARAM -> request.withUpdatedParameters(
                    HttpParameter.urlParameter(point.locator, encode(wrapped, point, InsertionPoint.Encoding.URL)));
            case BODY_PARAM -> request.withUpdatedParameters(
                    HttpParameter.bodyParameter(point.locator, encode(wrapped, point, InsertionPoint.Encoding.URL)));
            case HEADER -> applyHeader(request, point, wrapped, warnings);
            case RAW_OFFSET -> applyRawOffset(request, point, wrapped, warnings);
        };
    }

    private static HttpRequest applyJsonPath(HttpRequest request, InsertionPoint point,
                                             String prompt, List<String> warnings) {
        Optional<JsonElement> parsed = Json.parse(request.bodyToString());
        if (parsed.isEmpty()) {
            warnings.add("insertion point " + point.describe()
                    + " needs a JSON body, but the request body is not JSON - prompt not inserted");
            return request;
        }
        JsonElement root = parsed.get();
        String value = encode(prompt, point, InsertionPoint.Encoding.RAW);
        if (!JsonPathLite.setString(root, point.locator, value)) {
            warnings.add("path " + point.locator + " matched nothing in the request body"
                    + " - prompt not inserted");
            return request;
        }
        // Serialising through Gson re-escapes the value correctly, and Burp fixes up
        // Content-Length as part of withBody.
        return request.withBody(Json.GSON.toJson(root));
    }

    private static HttpRequest applyHeader(HttpRequest request, InsertionPoint point,
                                           String prompt, List<String> warnings) {
        String value = encode(prompt, point, InsertionPoint.Encoding.RAW)
                .replace("\r", "").replace("\n", " ");
        if (!StandardCharsets.ISO_8859_1.newEncoder().canEncode(value)) {
            // Matches the constraint garak itself hits: RFC 7230 only guarantees latin-1
            // in header field values, and non-encodable bytes fail at the HTTP layer.
            warnings.add("header " + point.locator + " carries characters outside latin-1;"
                    + " some servers and clients will reject or mangle them");
        }
        return request.withUpdatedHeader(point.locator, value);
    }

    /**
     * Byte-range replacement, for messages nothing else can model. The range addresses the
     * captured request, so this must run against bytes that have not been restructured --
     * which is why raw offsets and structural points should not be mixed on one profile.
     */
    private static HttpRequest applyRawOffset(HttpRequest request, InsertionPoint point,
                                              String prompt, List<String> warnings) {
        byte[] raw = request.toByteArray().getBytes();
        if (point.start < 0 || point.end > raw.length || point.start >= point.end) {
            warnings.add("byte range " + point.start + "-" + point.end
                    + " is outside the request (" + raw.length + " bytes) - prompt not inserted");
            return request;
        }
        byte[] payload = encode(prompt, point, InsertionPoint.Encoding.JSON_STRING)
                .getBytes(StandardCharsets.UTF_8);

        ByteArrayOutputStream out = new ByteArrayOutputStream(raw.length + payload.length);
        out.write(raw, 0, point.start);
        out.write(payload, 0, payload.length);
        out.write(raw, point.end, raw.length - point.end);

        HttpRequest rebuilt = HttpRequest.httpRequest(request.httpService(),
                ByteArray.byteArray(out.toByteArray()));
        // The splice changed the body length; restate it so the server reads the whole body.
        return rebuilt.hasHeader("Content-Length")
                ? rebuilt.withBody(rebuilt.body())
                : rebuilt;
    }

    // ------------------------------------------------------------------ encoding

    /** Applies the point's encoding, falling back to whatever suits the location. */
    private static String encode(String prompt, InsertionPoint point,
                                 InsertionPoint.Encoding auto) {
        InsertionPoint.Encoding encoding =
                point.encoding == InsertionPoint.Encoding.AUTO ? auto : point.encoding;
        return switch (encoding) {
            case RAW, AUTO -> prompt;
            case JSON_STRING -> Json.escapeBody(prompt);
            case URL -> URLEncoder.encode(prompt, StandardCharsets.UTF_8);
            case BASE64 -> Base64.getEncoder()
                    .encodeToString(prompt.getBytes(StandardCharsets.UTF_8));
        };
    }

    // ----------------------------------------------------------------- variables

    /** Replaces {@code {{name}}} throughout the request with prelude-captured values. */
    public static HttpRequest substituteVariables(HttpRequest request, Map<String, String> variables,
                                                  List<String> warnings) {
        if (variables == null || variables.isEmpty()) {
            return request;
        }
        String raw = new String(request.toByteArray().getBytes(), StandardCharsets.UTF_8);
        Matcher matcher = VARIABLE.matcher(raw);
        if (!matcher.find()) {
            return request;
        }

        matcher.reset();
        StringBuilder out = new StringBuilder();
        while (matcher.find()) {
            String name = matcher.group(1);
            String value = variables.get(name);
            if (value == null) {
                warnings.add("no prelude capture named '" + name + "' - left as-is");
                matcher.appendReplacement(out, Matcher.quoteReplacement(matcher.group()));
            } else {
                matcher.appendReplacement(out, Matcher.quoteReplacement(value));
            }
        }
        matcher.appendTail(out);

        HttpRequest rebuilt = HttpRequest.httpRequest(request.httpService(),
                ByteArray.byteArray(out.toString().getBytes(StandardCharsets.UTF_8)));
        return rebuilt.hasHeader("Content-Length") ? rebuilt.withBody(rebuilt.body()) : rebuilt;
    }

    /** Variable names referenced by a request, for the prelude editor's validation. */
    public static List<String> referencedVariables(byte[] rawRequest) {
        List<String> names = new ArrayList<>();
        Matcher matcher = VARIABLE.matcher(new String(rawRequest, StandardCharsets.UTF_8));
        while (matcher.find()) {
            if (!names.contains(matcher.group(1))) {
                names.add(matcher.group(1));
            }
        }
        return names;
    }
}
