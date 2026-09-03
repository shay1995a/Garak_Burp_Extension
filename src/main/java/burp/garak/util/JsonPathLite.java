// Copyright 2026 the garak Bridge authors
// SPDX-License-Identifier: Apache-2.0

package burp.garak.util;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * The subset of JSONPath that both this extension and garak's jsonpath_ng agree on:
 * {@code $.a.b[0].c}, {@code $['a']['b']}, {@code $.a[*].b}.
 *
 * <p>Deliberately not a full JSONPath engine. Paths produced here are also written into
 * exported garak configs as {@code response_json_field}, so staying inside the common
 * subset is a compatibility requirement, not just simplicity.
 *
 * <p>Also runs in reverse: {@link #leaves} enumerates every string leaf with its path,
 * which is how the extension turns "the text the user selected" into an extraction rule.
 */
public final class JsonPathLite {

    /** A plain identifier can use dot notation; anything else needs bracket-quoting. */
    private static final Pattern PLAIN_KEY = Pattern.compile("[A-Za-z_][A-Za-z0-9_]*");

    public enum Kind { FIELD, INDEX, WILDCARD }

    public record Step(Kind kind, String name, int index) {
        public static Step field(String name) {
            return new Step(Kind.FIELD, name, -1);
        }

        public static Step index(int index) {
            return new Step(Kind.INDEX, null, index);
        }

        public static Step wildcard() {
            return new Step(Kind.WILDCARD, null, -1);
        }
    }

    /** A string leaf and the path that addresses it. */
    public record Leaf(String path, String value, String key, int depth) {
    }

    private JsonPathLite() {
    }

    // ---------------------------------------------------------------- parsing

    /** Parses a path expression, or throws {@link IllegalArgumentException} if malformed. */
    public static List<Step> parse(String path) {
        String expression = path == null ? "" : path.trim();
        if (expression.isEmpty()) {
            throw new IllegalArgumentException("empty path");
        }
        if (expression.charAt(0) != '$') {
            // Bare field name: garak treats a non-'$' response_json_field as a top-level key.
            return List.of(Step.field(expression));
        }

        List<Step> steps = new ArrayList<>();
        int i = 1;
        while (i < expression.length()) {
            char c = expression.charAt(i);
            if (c == '.') {
                i++;
                if (i < expression.length() && expression.charAt(i) == '*') {
                    steps.add(Step.wildcard());
                    i++;
                    continue;
                }
                int start = i;
                while (i < expression.length() && expression.charAt(i) != '.' && expression.charAt(i) != '[') {
                    i++;
                }
                if (start == i) {
                    throw new IllegalArgumentException("empty field name at offset " + start);
                }
                steps.add(Step.field(expression.substring(start, i)));
            } else if (c == '[') {
                int close = expression.indexOf(']', i);
                if (close < 0) {
                    throw new IllegalArgumentException("unclosed '[' at offset " + i);
                }
                String inner = expression.substring(i + 1, close).trim();
                if (inner.equals("*")) {
                    steps.add(Step.wildcard());
                } else if ((inner.startsWith("'") && inner.endsWith("'") && inner.length() >= 2)
                        || (inner.startsWith("\"") && inner.endsWith("\"") && inner.length() >= 2)) {
                    steps.add(Step.field(inner.substring(1, inner.length() - 1)));
                } else {
                    try {
                        steps.add(Step.index(Integer.parseInt(inner)));
                    } catch (NumberFormatException e) {
                        throw new IllegalArgumentException("not an index or quoted key: [" + inner + "]");
                    }
                }
                i = close + 1;
            } else {
                throw new IllegalArgumentException("unexpected '" + c + "' at offset " + i);
            }
        }
        return steps;
    }

    /** True if the expression parses; used to validate user input before a run starts. */
    public static boolean isValid(String path) {
        try {
            parse(path);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    public static String format(List<Step> steps) {
        StringBuilder out = new StringBuilder("$");
        for (Step step : steps) {
            switch (step.kind()) {
                case FIELD -> {
                    if (PLAIN_KEY.matcher(step.name()).matches()) {
                        out.append('.').append(step.name());
                    } else {
                        out.append("['").append(step.name().replace("'", "\\'")).append("']");
                    }
                }
                case INDEX -> out.append('[').append(step.index()).append(']');
                case WILDCARD -> out.append("[*]");
            }
        }
        return out.toString();
    }

    // ------------------------------------------------------------- evaluation

    public static List<JsonElement> eval(JsonElement root, String path) {
        return eval(root, parse(path));
    }

    public static List<JsonElement> eval(JsonElement root, List<Step> steps) {
        List<JsonElement> current = new ArrayList<>();
        if (root != null) {
            current.add(root);
        }
        for (Step step : steps) {
            List<JsonElement> next = new ArrayList<>();
            for (JsonElement element : current) {
                switch (step.kind()) {
                    case FIELD -> {
                        if (element.isJsonObject() && element.getAsJsonObject().has(step.name())) {
                            next.add(element.getAsJsonObject().get(step.name()));
                        }
                    }
                    case INDEX -> {
                        if (element.isJsonArray()) {
                            JsonArray array = element.getAsJsonArray();
                            int idx = step.index() < 0 ? array.size() + step.index() : step.index();
                            if (idx >= 0 && idx < array.size()) {
                                next.add(array.get(idx));
                            }
                        }
                    }
                    case WILDCARD -> {
                        if (element.isJsonArray()) {
                            element.getAsJsonArray().forEach(next::add);
                        } else if (element.isJsonObject()) {
                            element.getAsJsonObject().entrySet().forEach(e -> next.add(e.getValue()));
                        }
                    }
                }
            }
            current = next;
            if (current.isEmpty()) {
                break;
            }
        }
        return current;
    }

    /** What a path resolved to: text, something that is not text, or nothing. */
    public sealed interface Text {
        record Matched(String value) implements Text {
        }

        /** The path addressed a node, but an object or array rather than a value. */
        record NotText(String type, String preview) implements Text {
        }

        record NoMatch() implements Text {
        }
    }

    /**
     * Resolves a path to text, concatenating every match.
     *
     * <p>A path that lands on an object or an array is reported as {@link Text.NotText}
     * rather than being serialised back to JSON. This mirrors garak's own RestGenerator,
     * which refuses a {@code response_json_field} that "matched a dict, not text" -- so a
     * rule that looks right here behaves the same way once garak is driving it, and the
     * auto-detector cannot prefer a rule that would fail mid-run.
     */
    public static Text evalToText(JsonElement root, String path) {
        List<JsonElement> matches;
        try {
            matches = eval(root, path);
        } catch (IllegalArgumentException e) {
            return new Text.NoMatch();
        }
        if (matches.isEmpty()) {
            return new Text.NoMatch();
        }
        StringBuilder out = new StringBuilder();
        for (JsonElement match : matches) {
            if (match.isJsonNull()) {
                continue;
            }
            if (!match.isJsonPrimitive()) {
                String type = match.isJsonArray() ? "array" : "object";
                String preview = Json.GSON.toJson(match);
                return new Text.NotText(type,
                        preview.length() > 200 ? preview.substring(0, 200) + "…" : preview);
            }
            out.append(match.getAsString());
        }
        return new Text.Matched(out.toString());
    }

    /**
     * Resolves a path to text, or empty when it addresses nothing or addresses something
     * that is not a value.
     */
    public static Optional<String> evalToString(JsonElement root, String path) {
        return evalToText(root, path) instanceof Text.Matched matched
                ? Optional.of(matched.value())
                : Optional.empty();
    }

    // -------------------------------------------------------------- mutation

    /**
     * Replaces the string at {@code path} with {@code value}, in place.
     *
     * <p>Refuses a path that addresses more than one node. A prompt written into several
     * places at once is almost never what was meant, and it corrupts the message quietly:
     * the request still sends, the target still answers, and the probe is measuring
     * something other than what the user configured. Better to fail visibly.
     *
     * @return true if exactly one node was replaced
     */
    public static boolean setString(JsonElement root, String path, String value) {
        List<Step> steps = parse(path);
        if (steps.isEmpty()) {
            return false;
        }
        List<JsonElement> parents = eval(root, steps.subList(0, steps.size() - 1));
        Step last = steps.get(steps.size() - 1);

        // Count addressable targets before touching anything.
        int targets = 0;
        for (JsonElement parent : parents) {
            targets += switch (last.kind()) {
                case FIELD -> parent.isJsonObject()
                        && parent.getAsJsonObject().has(last.name()) ? 1 : 0;
                case INDEX -> parent.isJsonArray()
                        && resolveIndex(parent.getAsJsonArray(), last.index()) >= 0 ? 1 : 0;
                case WILDCARD -> parent.isJsonArray() ? parent.getAsJsonArray().size()
                        : parent.isJsonObject() ? parent.getAsJsonObject().size() : 0;
            };
        }
        if (targets != 1) {
            return false;
        }

        for (JsonElement parent : parents) {
            switch (last.kind()) {
                case FIELD -> {
                    if (parent.isJsonObject() && parent.getAsJsonObject().has(last.name())) {
                        parent.getAsJsonObject().add(last.name(), new JsonPrimitive(value));
                        return true;
                    }
                }
                case INDEX -> {
                    if (parent.isJsonArray()) {
                        JsonArray array = parent.getAsJsonArray();
                        int index = resolveIndex(array, last.index());
                        if (index >= 0) {
                            array.set(index, new JsonPrimitive(value));
                            return true;
                        }
                    }
                }
                case WILDCARD -> {
                    if (parent.isJsonArray() && parent.getAsJsonArray().size() == 1) {
                        parent.getAsJsonArray().set(0, new JsonPrimitive(value));
                        return true;
                    }
                    if (parent.isJsonObject() && parent.getAsJsonObject().size() == 1) {
                        String key = parent.getAsJsonObject().keySet().iterator().next();
                        parent.getAsJsonObject().add(key, new JsonPrimitive(value));
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /** Resolves a possibly negative index, or -1 when it falls outside the array. */
    private static int resolveIndex(JsonArray array, int index) {
        int resolved = index < 0 ? array.size() + index : index;
        return resolved >= 0 && resolved < array.size() ? resolved : -1;
    }

    // --------------------------------------------------------------- reverse

    /** Every string leaf in the document, with the path that addresses it. */
    public static List<Leaf> leaves(JsonElement root) {
        List<Leaf> found = new ArrayList<>();
        collect(root, new ArrayList<>(), null, found);
        return found;
    }

    private static void collect(JsonElement node, List<Step> trail, String key, List<Leaf> out) {
        if (node == null || node.isJsonNull()) {
            return;
        }
        if (node.isJsonPrimitive()) {
            if (node.getAsJsonPrimitive().isString()) {
                out.add(new Leaf(format(trail), node.getAsString(), key, trail.size()));
            }
            return;
        }
        if (node.isJsonObject()) {
            for (Map.Entry<String, JsonElement> entry : node.getAsJsonObject().entrySet()) {
                trail.add(Step.field(entry.getKey()));
                collect(entry.getValue(), trail, entry.getKey(), out);
                trail.remove(trail.size() - 1);
            }
        } else if (node.isJsonArray()) {
            JsonArray array = node.getAsJsonArray();
            for (int i = 0; i < array.size(); i++) {
                trail.add(Step.index(i));
                collect(array.get(i), trail, key, out);
                trail.remove(trail.size() - 1);
            }
        }
    }

    /**
     * Finds the path to the leaf that best corresponds to text the user selected.
     * Prefers an exact match, then a leaf containing the selection, then a leaf
     * contained by it (the user may have selected surrounding punctuation).
     */
    public static Optional<String> pathToText(JsonElement root, String selected) {
        String needle = selected == null ? "" : selected.trim();
        if (needle.isEmpty()) {
            return Optional.empty();
        }
        List<Leaf> leaves = leaves(root);
        for (Leaf leaf : leaves) {
            if (leaf.value().equals(needle)) {
                return Optional.of(leaf.path());
            }
        }
        for (Leaf leaf : leaves) {
            if (leaf.value().contains(needle)) {
                return Optional.of(leaf.path());
            }
        }
        for (Leaf leaf : leaves) {
            if (!leaf.value().isBlank() && needle.contains(leaf.value())) {
                return Optional.of(leaf.path());
            }
        }
        return Optional.empty();
    }

    /** Deep copy, so a template document can be reused across prompts without aliasing. */
    public static JsonElement copy(JsonElement source) {
        return source == null ? null : Json.GSON.fromJson(Json.GSON.toJson(source), JsonElement.class);
    }

    /** Convenience for the common "read a nested string" case. */
    public static Optional<String> stringAt(JsonObject root, String path) {
        return evalToString(root, path).filter(s -> !s.isEmpty());
    }
}
