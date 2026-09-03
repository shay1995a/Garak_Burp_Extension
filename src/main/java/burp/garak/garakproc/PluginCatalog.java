// Copyright 2026 the garak Bridge authors
// SPDX-License-Identifier: Apache-2.0

package burp.garak.garakproc;

import burp.garak.util.Json;
import burp.garak.util.Proc;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Predicate;

/**
 * The probe list, read from the catalogue garak ships at
 * {@code <package>/resources/plugin_cache.json}.
 *
 * <p>Reading the file directly rather than shelling out to {@code --list_probes} is worth
 * it: the catalogue carries the description, goal, OWASP/AVID tags and quality tier for
 * every probe, which is the difference between a picker that means something and a list of
 * 195 opaque class names. {@link #fromListProbes} is the fallback when the file is missing.
 */
public final class PluginCatalog {

    /** CSI escape sequences, stripped from --list_probes output. */
    private static final java.util.regex.Pattern ANSI =
            java.util.regex.Pattern.compile("\\u001B\\[[0-9;?]*[ -/]*[@-~]");

    /** Probes whose input is not plain text cannot work through a text bridge. */
    private static final String TEXT = "text";

    public record Probe(
            String name,
            String shortName,
            String family,
            String description,
            String goal,
            String docUri,
            String intent,
            List<String> tags,
            int tier,
            boolean active,
            String primaryDetector,
            boolean textOnly,
            boolean needsSecondaryModel,
            List<String> extraDependencies) {

        /** True when the probe can be run through the bridge with no extra setup. */
        public boolean isReadyToRun() {
            return textOnly && !needsSecondaryModel && extraDependencies.isEmpty();
        }

        /** Why it is not ready, for the warning column. Empty when it is. */
        public String caveat() {
            if (!textOnly) {
                return "needs non-text input (image or audio) - cannot run through the bridge";
            }
            if (needsSecondaryModel) {
                return "needs a second attacker/evaluator model configured in garak";
            }
            if (!extraDependencies.isEmpty()) {
                return "needs extra Python packages: " + String.join(", ", extraDependencies);
            }
            return "";
        }

        public List<String> owaspTags() {
            return tags.stream().filter(tag -> tag.startsWith("owasp:")).toList();
        }
    }

    private final List<Probe> probes;
    private final String source;

    private PluginCatalog(List<Probe> probes, String source) {
        this.probes = probes;
        this.source = source;
    }

    public static PluginCatalog empty() {
        return new PluginCatalog(List.of(), "not loaded");
    }

    public List<Probe> probes() {
        return probes;
    }

    public String source() {
        return source;
    }

    public boolean isEmpty() {
        return probes.isEmpty();
    }

    public Optional<Probe> byName(String name) {
        return probes.stream().filter(probe -> probe.name.equals(name)).findFirst();
    }

    /** Every module family present, sorted, for the family filter. */
    public List<String> families() {
        return new ArrayList<>(new TreeSet<>(probes.stream().map(Probe::family).toList()));
    }

    /** Every tag present, sorted, for the tag filter. */
    public List<String> tags() {
        Set<String> all = new TreeSet<>();
        probes.forEach(probe -> all.addAll(probe.tags));
        return new ArrayList<>(all);
    }

    // ------------------------------------------------------------------- loading

    /** Reads the catalogue that ships with the user's garak install. */
    public static PluginCatalog fromPluginCache(Path pluginCache) {
        Optional<JsonElement> root = Json.read(pluginCache);
        if (root.isEmpty() || !root.get().isJsonObject()) {
            return empty();
        }
        JsonElement probesNode = root.get().getAsJsonObject().get("probes");
        if (probesNode == null || !probesNode.isJsonObject()) {
            return empty();
        }

        List<Probe> parsed = new ArrayList<>();
        for (Map.Entry<String, JsonElement> entry : probesNode.getAsJsonObject().entrySet()) {
            String name = entry.getKey();
            if (!name.startsWith("probes.") || name.endsWith(".base") || name.contains(".base.")) {
                continue;
            }
            if (!entry.getValue().isJsonObject()) {
                continue;
            }
            parsed.add(parse(name, entry.getValue().getAsJsonObject()));
        }
        parsed.sort(Comparator.comparing(Probe::shortName));
        return new PluginCatalog(parsed, pluginCache.toString());
    }

    private static Probe parse(String name, JsonObject node) {
        String shortName = name.startsWith("probes.") ? name.substring("probes.".length()) : name;
        String family = shortName.contains(".") ? shortName.substring(0, shortName.indexOf('.')) : shortName;

        List<String> tags = strings(node.get("tags"));
        List<String> dependencies = strings(node.get("extra_dependency_names"));

        return new Probe(
                name,
                shortName,
                family,
                Json.string(node, "description", ""),
                Json.string(node, "goal", ""),
                Json.string(node, "doc_uri", ""),
                Json.string(node, "intent", ""),
                tags,
                Json.integer(node, "tier", 0),
                Json.bool(node, "active", true),
                Json.string(node, "primary_detector", ""),
                isTextOnly(node),
                needsSecondaryModel(node),
                dependencies);
    }

    private static boolean isTextOnly(JsonObject node) {
        JsonElement modality = node.get("modality");
        if (modality == null || !modality.isJsonObject()) {
            return true; // unstated means text, which is garak's own default
        }
        JsonElement inputs = modality.getAsJsonObject().get("in");
        if (inputs == null || !inputs.isJsonArray()) {
            return true;
        }
        for (JsonElement input : inputs.getAsJsonArray()) {
            if (input.isJsonPrimitive() && !TEXT.equals(input.getAsString())) {
                return false;
            }
        }
        return true;
    }

    /**
     * Probes that drive an attacker or judge model of their own -- atkgen, tap, goat and
     * the adaptive attacks -- declare it in their defaults as a {@code *_model_type}. They
     * will not run against a bare bridge without extra garak configuration, so the picker
     * flags them rather than letting the run fail halfway through.
     */
    private static boolean needsSecondaryModel(JsonObject node) {
        JsonElement defaults = node.get("DEFAULT_PARAMS");
        if (defaults == null || !defaults.isJsonObject()) {
            return false;
        }
        for (String key : defaults.getAsJsonObject().keySet()) {
            String lower = key.toLowerCase(Locale.ROOT);
            if (lower.endsWith("_model_type") || lower.endsWith("_model_name")) {
                return true;
            }
        }
        return false;
    }

    private static List<String> strings(JsonElement node) {
        if (node == null || !node.isJsonArray()) {
            return List.of();
        }
        List<String> values = new ArrayList<>();
        JsonArray array = node.getAsJsonArray();
        for (JsonElement element : array) {
            if (element.isJsonPrimitive()) {
                values.add(element.getAsString());
            }
        }
        return values;
    }

    /**
     * Fallback for installs without the catalogue file: parse {@code garak --list_probes}.
     * Names only -- no descriptions, tags or tiers.
     */
    public static PluginCatalog fromListProbes(List<String> command) {
        List<String> args = new ArrayList<>(command);
        args.add("--list_probes");
        Proc.Output out = Proc.run(args, null, GarakLocator.cleanEnv(), 300);
        if (out.stdout().isEmpty()) {
            return empty();
        }

        List<Probe> parsed = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        for (String line : out.stdout().split("\r?\n")) {
            // Lines look like "probes: dan.AntiDAN", optionally with ANSI colour and
            // trailing 🌟 (module) / 💤 (inactive) markers.
            String cleaned = ANSI.matcher(line).replaceAll("").trim();
            int marker = cleaned.indexOf("probes:");
            if (marker < 0) {
                continue;
            }
            String rest = cleaned.substring(marker + "probes:".length()).trim();
            boolean active = !rest.contains("💤");
            String shortName = rest.replace("🌟", "").replace("💤", "").trim();
            if (shortName.isEmpty() || !shortName.contains(".") || !seen.add(shortName)) {
                continue; // bare module names are group headers, not probes
            }
            String family = shortName.substring(0, shortName.indexOf('.'));
            parsed.add(new Probe("probes." + shortName, shortName, family, "", "", "", "",
                    List.of(), 0, active, "", true, false, List.of()));
        }
        parsed.sort(Comparator.comparing(Probe::shortName));
        return new PluginCatalog(parsed, "garak --list_probes");
    }

    // ------------------------------------------------------------------- presets

    /** A named selection, resolved against whatever catalogue is loaded. */
    public record Preset(String name, String description, Predicate<Probe> matches) {
    }

    /**
     * Selections chosen by property rather than by hard-coded probe name, so they keep
     * working as garak's probe set changes between releases.
     */
    public static List<Preset> presets() {
        return List.of(
                new Preset("Quick smoke",
                        "One trivial probe. Confirms the whole pipeline works before a real run.",
                        probe -> probe.family.equals("test")),
                new Preset("OWASP LLM01 - prompt injection",
                        "Active tier 1-2 probes tagged owasp:llm01.",
                        probe -> probe.active && probe.tier > 0 && probe.tier <= 2
                                && probe.tags.stream().anyMatch(tag -> tag.startsWith("owasp:llm01"))
                                && probe.isReadyToRun()),
                new Preset("Jailbreaks",
                        "Guardrail bypass families: dan, grandma, sata, dra, fitd, phrasing.",
                        probe -> probe.active && probe.isReadyToRun()
                                && Set.of("dan", "grandma", "sata", "dra", "fitd", "phrasing")
                                        .contains(probe.family)),
                new Preset("Data leakage",
                        "System prompt extraction, training-data replay and PII probes.",
                        probe -> probe.active && probe.isReadyToRun()
                                && Set.of("leakreplay", "propile", "sysprompt_extraction",
                                        "divergence", "apikey").contains(probe.family)),
                new Preset("Harmful content",
                        "Toxicity, malware generation and refusal-bypass probes.",
                        probe -> probe.active && probe.isReadyToRun()
                                && Set.of("lmrc", "realtoxicityprompts", "donotanswer",
                                        "malwaregen", "av_spam_scanning").contains(probe.family)),
                new Preset("Tier 1 sweep",
                        "Every active tier 1 probe. Thorough, and the longest of these.",
                        probe -> probe.active && probe.tier == 1 && probe.isReadyToRun()));
    }

    /** Probe names matching a preset, ready to drop into a run config. */
    public List<String> resolve(Preset preset) {
        return probes.stream().filter(preset.matches()).map(Probe::name).toList();
    }
}
