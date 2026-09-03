// Copyright 2026 the garak Bridge authors
// SPDX-License-Identifier: Apache-2.0

package burp.garak.capture;

import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.garak.model.InsertionPoint;
import burp.garak.util.Json;
import burp.garak.util.JsonPathLite;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Works out where the user's chat message sits in a captured request.
 *
 * <p>Two routes in. {@link #fromSelection} is exact: the user highlights the prompt text in
 * Burp's request editor and gets back the rule that addresses it. {@link #detect} is the
 * guess made when nothing is selected, so that the common shapes -- an OpenAI-style
 * {@code messages} array, a {@code {"message": "..."}} body, a {@code ?q=} parameter --
 * need no configuration at all.
 */
public final class RequestAnalyzer {

    /** Field names that almost always carry the user's message. */
    private static final Set<String> STRONG_KEYS = Set.of(
            "prompt", "message", "question", "user_input", "userinput", "user_message",
            "usermessage", "human_input", "userprompt", "user_prompt", "chatinput", "chat_input");

    /** Field names that often carry it, but also carry other things. */
    private static final Set<String> WEAK_KEYS = Set.of(
            "content", "text", "query", "input", "msg", "q", "ask", "utterance", "body",
            "search", "chat", "said", "value");

    /** Field names that are structurally never the prompt. */
    private static final Set<String> NEGATIVE_KEYS = Set.of(
            "id", "uuid", "role", "type", "model", "token", "key", "apikey", "api_key",
            "csrf", "session", "sessionid", "session_id", "conversation_id", "conversationid",
            "thread_id", "threadid", "parent_id", "timestamp", "created", "version", "name",
            "email", "username", "signature", "nonce", "state", "locale", "lang", "format",
            "stream", "temperature", "max_tokens", "top_p", "n", "stop", "user");

    /** Values that are plainly machine identifiers rather than prose. */
    private static final Pattern UUID_LIKE =
            Pattern.compile("(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");
    private static final Pattern HEX_OR_B64_TOKEN =
            Pattern.compile("^[A-Za-z0-9+/_=-]{24,}$");
    private static final Pattern URL_LIKE = Pattern.compile("(?i)^(https?://|/|data:)");
    private static final Pattern ISO_DATE = Pattern.compile("^\\d{4}-\\d{2}-\\d{2}[T ].*");
    private static final Set<String> ROLE_VALUES = Set.of("user", "assistant", "system", "tool", "model");

    /** A ranked candidate, so the UI can offer alternatives when the top guess is wrong. */
    public record Candidate(InsertionPoint point, int score, String preview, String reason) {
    }

    private RequestAnalyzer() {
    }

    // ------------------------------------------------------------ from a selection

    /**
     * Derives the insertion rule for text the user highlighted in the request editor.
     *
     * <p>Prefers a structural rule -- a JSON path or a named parameter -- and only falls
     * back to a byte range when the selection lands somewhere unparseable, because a byte
     * range stops addressing the right thing as soon as the prompt is a different length.
     */
    public static Optional<InsertionPoint> fromSelection(HttpRequest request, Range selection) {
        if (selection == null || selection.endIndexExclusive() <= selection.startIndexInclusive()) {
            return Optional.empty();
        }
        int start = selection.startIndexInclusive();
        int end = selection.endIndexExclusive();
        byte[] raw = request.toByteArray().getBytes();
        if (end > raw.length) {
            return Optional.empty();
        }
        String selected = new String(raw, start, end - start, StandardCharsets.UTF_8);

        // A parameter whose value span covers the selection is the most precise answer,
        // and Burp has already parsed the offsets for us.
        for (ParsedHttpParameter parameter : request.parameters()) {
            Range value = parameter.valueOffsets();
            if (value == null || !overlaps(value, start, end)) {
                continue;
            }
            switch (parameter.type()) {
                case URL:
                    return Optional.of(InsertionPoint.queryParam(parameter.name()));
                case BODY:
                case MULTIPART_ATTRIBUTE:
                    return Optional.of(InsertionPoint.bodyParam(parameter.name()));
                default:
                    break; // JSON params are handled below, with full paths
            }
        }

        // Inside a JSON body: resolve the selection to the string leaf that contains it.
        int bodyOffset = request.bodyOffset();
        if (start >= bodyOffset) {
            Optional<JsonElement> parsed = Json.parse(request.bodyToString());
            if (parsed.isPresent()) {
                Optional<String> path = pathForSelectedText(parsed.get(), selected);
                if (path.isPresent()) {
                    return Optional.of(InsertionPoint.jsonPath(path.get()));
                }
            }
        }

        // Nothing structural matched: keep the exact bytes the user chose, and escape for
        // JSON if that is what surrounds them.
        InsertionPoint.Encoding encoding = start >= bodyOffset && looksLikeJson(request.bodyToString())
                ? InsertionPoint.Encoding.JSON_STRING
                : InsertionPoint.Encoding.AUTO;
        return Optional.of(InsertionPoint.rawOffset(start, end, encoding));
    }

    /**
     * Matches selected raw bytes against JSON string values. The selection comes from the
     * wire, so it is still JSON-escaped; the parsed leaves are not. Compare both ways.
     */
    private static Optional<String> pathForSelectedText(JsonElement root, String selected) {
        Optional<String> direct = JsonPathLite.pathToText(root, selected);
        if (direct.isPresent()) {
            return direct;
        }
        for (JsonPathLite.Leaf leaf : JsonPathLite.leaves(root)) {
            String escaped = Json.escapeBody(leaf.value());
            if (escaped.equals(selected.trim()) || escaped.contains(selected.trim())) {
                return Optional.of(leaf.path());
            }
        }
        return Optional.empty();
    }

    private static boolean overlaps(Range range, int start, int end) {
        return range.startIndexInclusive() < end && range.endIndexExclusive() > start;
    }

    // -------------------------------------------------------------- auto-detect

    /** Ranked guesses at where the prompt goes, best first. Empty when nothing looks right. */
    public static List<Candidate> detect(HttpRequest request) {
        List<Candidate> candidates = new ArrayList<>();

        Optional<JsonElement> body = Json.parse(request.bodyToString());
        if (body.isPresent()) {
            candidates.addAll(detectInJson(body.get()));
        }

        for (ParsedHttpParameter parameter : request.parameters()) {
            InsertionPoint point = switch (parameter.type()) {
                case URL -> InsertionPoint.queryParam(parameter.name());
                case BODY, MULTIPART_ATTRIBUTE -> InsertionPoint.bodyParam(parameter.name());
                default -> null;
            };
            if (point == null) {
                continue;
            }
            int score = scoreKey(parameter.name()) + scoreValue(parameter.value());
            candidates.add(new Candidate(point, score, preview(parameter.value()),
                    describe(parameter.name(), score)));
        }

        candidates.sort(Comparator.comparingInt(Candidate::score).reversed());
        return candidates;
    }

    /** The single best guess, or empty when nothing scores well enough to be worth offering. */
    public static Optional<InsertionPoint> bestGuess(HttpRequest request) {
        return detect(request).stream()
                .filter(candidate -> candidate.score() > 0)
                .findFirst()
                .map(Candidate::point);
    }

    /**
     * Ranked guesses within a JSON request body, separated from Burp's request object so
     * it can be exercised directly against a captured body.
     */
    public static List<Candidate> detectInJsonBody(String body) {
        Optional<JsonElement> parsed = Json.parse(body);
        if (parsed.isEmpty()) {
            return List.of();
        }
        List<Candidate> candidates = new ArrayList<>(detectInJson(parsed.get()));
        candidates.sort(Comparator.comparingInt(Candidate::score).reversed());
        return candidates;
    }

    /** The best JSON-body guess, or empty when nothing scores well enough to offer. */
    public static Optional<InsertionPoint> bestGuessInJsonBody(String body) {
        return detectInJsonBody(body).stream()
                .filter(candidate -> candidate.score() > 0)
                .findFirst()
                .map(Candidate::point);
    }

    private static List<Candidate> detectInJson(JsonElement root) {
        List<Candidate> candidates = new ArrayList<>();
        for (JsonPathLite.Leaf leaf : JsonPathLite.leaves(root)) {
            int score = scoreKey(leaf.key()) + scoreValue(leaf.value());
            score += chatArrayBonus(root, leaf);
            // Deeply buried strings are usually metadata, not the message.
            score -= Math.max(0, leaf.depth() - 3);
            candidates.add(new Candidate(InsertionPoint.jsonPath(leaf.path()), score,
                    preview(leaf.value()), describe(leaf.key(), score)));
        }
        return candidates;
    }

    /**
     * Recognises the chat-completions shape: an array of {role, content} objects where the
     * message being sent is the last one with {@code role: "user"}. Without this the
     * scorer would happily pick the system prompt, which is present, longer, and wrong.
     */
    private static int chatArrayBonus(JsonElement root, JsonPathLite.Leaf leaf) {
        if (!"content".equals(leaf.key())) {
            return 0;
        }
        int lastBracket = leaf.path().lastIndexOf('[');
        int closeBracket = leaf.path().indexOf(']', lastBracket + 1);
        if (lastBracket < 0 || closeBracket < 0) {
            return 0;
        }
        String parentPath = leaf.path().substring(0, closeBracket + 1);
        List<JsonElement> parents = JsonPathLite.eval(root, parentPath);
        if (parents.size() != 1 || !parents.get(0).isJsonObject()) {
            return 0;
        }
        JsonObject entry = parents.get(0).getAsJsonObject();
        String role = Json.string(entry, "role", "");
        if (role.isEmpty()) {
            return 0; // not a role/content pair after all
        }
        if (!"user".equalsIgnoreCase(role)) {
            // A system or assistant turn is context, never the prompt under test.
            return -40;
        }
        int index;
        try {
            index = Integer.parseInt(leaf.path().substring(lastBracket + 1, closeBracket));
        } catch (NumberFormatException e) {
            return 30;
        }
        // Later user turns win: the newest message is the one being sent.
        return 30 + Math.min(index, 10);
    }

    private static int scoreKey(String key) {
        if (key == null || key.isEmpty()) {
            return 0;
        }
        String normalised = key.toLowerCase(Locale.ROOT);
        if (STRONG_KEYS.contains(normalised)) {
            return 50;
        }
        if (WEAK_KEYS.contains(normalised)) {
            return 20;
        }
        if (NEGATIVE_KEYS.contains(normalised)) {
            return -50;
        }
        for (String strong : STRONG_KEYS) {
            if (normalised.contains(strong)) {
                return 30;
            }
        }
        return 0;
    }

    private static int scoreValue(String value) {
        if (value == null || value.isBlank()) {
            return -10;
        }
        String trimmed = value.trim();
        if (ROLE_VALUES.contains(trimmed.toLowerCase(Locale.ROOT))) {
            return -60;
        }
        if (UUID_LIKE.matcher(trimmed).matches() || ISO_DATE.matcher(trimmed).matches()) {
            return -50;
        }
        if (URL_LIKE.matcher(trimmed).find()) {
            return -30;
        }
        if (!trimmed.contains(" ") && HEX_OR_B64_TOKEN.matcher(trimmed).matches()) {
            return -40;
        }

        int score = 0;
        if (trimmed.contains(" ")) {
            score += 15; // prose has spaces
        }
        int length = trimmed.length();
        if (length >= 3 && length <= 2000) {
            score += 10;
        } else if (length > 8000) {
            score -= 20; // an embedded document, not a chat message
        }
        if (trimmed.endsWith("?") || trimmed.endsWith(".") || trimmed.endsWith("!")) {
            score += 5;
        }
        return score;
    }

    private static boolean looksLikeJson(String body) {
        String trimmed = body == null ? "" : body.trim();
        return trimmed.startsWith("{") || trimmed.startsWith("[");
    }

    private static String describe(String key, int score) {
        if (score >= 50) {
            return "field name '" + key + "' names a prompt";
        }
        if (score >= 20) {
            return "field name '" + key + "' often carries the message";
        }
        if (score <= -20) {
            return "looks like metadata, not a message";
        }
        return "possible, from the value's shape";
    }

    private static String preview(String value) {
        if (value == null) {
            return "";
        }
        String flat = value.replace('\n', ' ').replace('\r', ' ').trim();
        return flat.length() <= 80 ? flat : flat.substring(0, 79) + "…";
    }
}
