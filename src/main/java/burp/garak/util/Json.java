// Copyright 2026 the garak Bridge authors
// SPDX-License-Identifier: Apache-2.0

package burp.garak.util;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

/** Shared Gson configuration and small parsing helpers. */
public final class Json {

    /** Lenient on read, compact on write; nulls are dropped so garak sees clean config. */
    public static final Gson GSON = new GsonBuilder().disableHtmlEscaping().create();

    public static final Gson PRETTY =
            new GsonBuilder().disableHtmlEscaping().setPrettyPrinting().create();

    private Json() {
    }

    /** Parses text as JSON, returning empty rather than throwing on malformed input. */
    public static Optional<JsonElement> parse(String text) {
        if (text == null || text.isBlank()) {
            return Optional.empty();
        }
        try {
            JsonElement parsed = JsonParser.parseString(text);
            return parsed == null || parsed.isJsonNull() ? Optional.empty() : Optional.of(parsed);
        } catch (JsonSyntaxException | IllegalStateException e) {
            return Optional.empty();
        }
    }

    public static Optional<JsonObject> parseObject(String text) {
        return parse(text).filter(JsonElement::isJsonObject).map(JsonElement::getAsJsonObject);
    }

    /**
     * Escapes a string as a JSON string body, without the surrounding quotes.
     * Used when splicing a prompt into a raw request body by byte offset, where
     * the quotes are already present in the captured message.
     */
    public static String escapeBody(String raw) {
        String quoted = GSON.toJson(raw);
        return quoted.substring(1, quoted.length() - 1);
    }

    public static void write(Path file, JsonElement content) throws IOException {
        Files.createDirectories(file.getParent());
        Files.writeString(file, PRETTY.toJson(content), StandardCharsets.UTF_8);
    }

    /** Reads a JSON file, returning empty if it is absent or malformed. */
    public static Optional<JsonElement> read(Path file) {
        try {
            return parse(Files.readString(file, StandardCharsets.UTF_8));
        } catch (IOException e) {
            return Optional.empty();
        }
    }

    /** Null-safe string field access. */
    public static String string(JsonObject object, String field, String fallback) {
        if (object == null || !object.has(field)) {
            return fallback;
        }
        JsonElement value = object.get(field);
        return value.isJsonPrimitive() ? value.getAsString() : fallback;
    }

    public static int integer(JsonObject object, String field, int fallback) {
        if (object == null || !object.has(field) || !object.get(field).isJsonPrimitive()) {
            return fallback;
        }
        try {
            return object.get(field).getAsInt();
        } catch (NumberFormatException e) {
            return fallback;
        }
    }

    public static boolean bool(JsonObject object, String field, boolean fallback) {
        if (object == null || !object.has(field) || !object.get(field).isJsonPrimitive()) {
            return fallback;
        }
        try {
            return object.get(field).getAsBoolean();
        } catch (RuntimeException e) {
            return fallback;
        }
    }
}
