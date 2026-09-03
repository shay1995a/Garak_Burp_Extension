// Copyright 2026 the garak Bridge authors
// SPDX-License-Identifier: Apache-2.0

package burp.garak.garakproc;

import burp.garak.util.Proc;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Finds the user's garak install and works out how to talk to it.
 *
 * <p>garak stays external, so the only contract is a path. That path can be a {@code garak}
 * console script, a Python interpreter to run {@code -m garak} with, or nothing at all, in
 * which case {@code garak} is looked for on PATH. Whichever it is, this resolves the
 * version and the package directory, because the probe catalogue that drives the picker
 * ships inside the package as {@code resources/plugin_cache.json}.
 */
public final class GarakLocator {

    /** garak prints something like "garak LLM vulnerability scanner v0.16.0 ( ... )". */
    private static final Pattern VERSION = Pattern.compile("v?(\\d+)\\.(\\d+)(?:\\.(\\d+))?");

    /** Console scripts installed by pip start with the interpreter that installed them. */
    private static final Pattern SHEBANG = Pattern.compile("^#!\\s*(\\S+)");

    /** {@code --list_config} prints the transient section as "    package_dir: <path>". */
    private static final Pattern PACKAGE_DIR =
            Pattern.compile("(?m)^\\s*package_dir:\\s*(.+?)\\s*$");

    /** How long to allow for a garak startup, which imports torch and friends. */
    private static final long PROBE_TIMEOUT_SECONDS = 180;

    public record Installation(
            List<String> command,
            String version,
            int major,
            int minor,
            int patch,
            Path packageDir,
            Path pluginCache,
            String interpreter,
            String banner,
            List<String> problems) {

        public boolean isUsable() {
            return !command.isEmpty() && !version.isEmpty();
        }

        public boolean hasCatalogue() {
            return pluginCache != null && Files.isRegularFile(pluginCache);
        }

        /** {@code --spec} replaced {@code --probes} in 0.15; both still parse in 0.16. */
        public boolean supportsSpec() {
            return major > 0 || minor >= 15;
        }

        /** {@code --target_type} replaced {@code --model_type} in 0.13. */
        public boolean supportsTargetType() {
            return major > 0 || minor >= 13;
        }

        public String describe() {
            if (!isUsable()) {
                return "not found";
            }
            return "garak " + version + " via " + String.join(" ", command);
        }
    }

    private GarakLocator() {
    }

    /**
     * Probes a configured path. Never throws: every failure comes back as a problem string
     * the settings panel can show, because "garak isn't where you said" is the single most
     * likely setup issue and it deserves a readable answer rather than a stack trace.
     */
    public static Installation probe(String configuredPath) {
        List<String> problems = new ArrayList<>();

        List<String> command = resolveCommand(configuredPath, problems);
        if (command.isEmpty()) {
            return unusable(problems);
        }

        List<String> versionArgs = new ArrayList<>(command);
        versionArgs.add("--version");
        Proc.Output versionOut = Proc.run(versionArgs, null, cleanEnv(), PROBE_TIMEOUT_SECONDS);

        if (versionOut.timedOut()) {
            problems.add("garak did not respond to --version within " + PROBE_TIMEOUT_SECONDS
                    + "s. A first run imports torch and can be slow; try again, or check the path.");
            return unusable(problems);
        }
        String banner = versionOut.combined().trim();
        if (!versionOut.ok() && banner.isEmpty()) {
            problems.add("could not run " + String.join(" ", command)
                    + " (exit " + versionOut.exitCode() + ")");
            return unusable(problems);
        }

        Matcher matcher = VERSION.matcher(banner);
        if (!matcher.find()) {
            problems.add("ran, but the output did not look like a garak version: "
                    + firstLine(banner));
            return unusable(problems);
        }
        int major = Integer.parseInt(matcher.group(1));
        int minor = Integer.parseInt(matcher.group(2));
        int patch = matcher.group(3) == null ? 0 : Integer.parseInt(matcher.group(3));
        String version = major + "." + minor + "." + patch;

        String interpreter = resolveInterpreter(command);
        Path packageDir = interpreter.isEmpty() ? null : findPackageDirViaInterpreter(interpreter);
        if (packageDir == null) {
            // No usable interpreter, or it could not import garak. Ask garak itself.
            packageDir = findPackageDirViaGarak(command);
        }
        Path pluginCache = packageDir == null ? null
                : packageDir.resolve("resources").resolve("plugin_cache.json");

        if (pluginCache == null || !Files.isRegularFile(pluginCache)) {
            problems.add("could not find the probe catalogue (resources/plugin_cache.json). "
                    + "The probe list will be read from 'garak --list_probes' instead, "
                    + "without descriptions, tiers or tags.");
        }

        return new Installation(command, version, major, minor, patch, packageDir, pluginCache,
                interpreter, banner, problems);
    }

    // ------------------------------------------------------------------ resolving

    private static List<String> resolveCommand(String configuredPath, List<String> problems) {
        String configured = configuredPath == null ? "" : configuredPath.trim();

        if (configured.isEmpty()) {
            Optional<Path> onPath = searchPath("garak");
            if (onPath.isPresent()) {
                return new ArrayList<>(List.of(onPath.get().toString()));
            }
            problems.add("no garak path set, and 'garak' is not on PATH. "
                    + "Set the path to a garak executable, or to the Python interpreter of "
                    + "the environment garak is installed in.");
            return List.of();
        }

        Path path = Path.of(configured);
        if (!Files.exists(path)) {
            Optional<Path> onPath = searchPath(configured);
            if (onPath.isEmpty()) {
                problems.add("no such file: " + configured);
                return List.of();
            }
            path = onPath.get();
        }
        if (!Files.isExecutable(path)) {
            problems.add(path + " is not executable");
            return List.of();
        }

        if (looksLikeInterpreter(path)) {
            return new ArrayList<>(List.of(path.toString(), "-m", "garak"));
        }
        return new ArrayList<>(List.of(path.toString()));
    }

    private static boolean looksLikeInterpreter(Path path) {
        String name = stripExtension(path.getFileName().toString());
        return name.startsWith("python") || name.startsWith("pypy")
                || name.equals("uv") || name.equals("py"); // py = the Windows launcher
    }

    /**
     * The interpreter that can import garak, if one can be identified locally.
     *
     * <p>Three routes, cheapest first, because each successful one saves a garak startup:
     * it was configured directly; a POSIX console script names it in its shebang; or -- the
     * Windows case -- pip wrapped the entry point in a {@code .exe}, which has no shebang,
     * but which sits next to the interpreter that installed it.
     */
    private static String resolveInterpreter(List<String> command) {
        if (command.size() >= 2 && "-m".equals(command.get(1))) {
            return command.get(0);
        }
        Path script = Path.of(command.get(0));

        try {
            byte[] head = readHead(script, 256);
            Matcher matcher = SHEBANG.matcher(new String(head, StandardCharsets.ISO_8859_1));
            if (matcher.find()) {
                String interpreter = matcher.group(1);
                if (Files.isExecutable(Path.of(interpreter))) {
                    return interpreter;
                }
            }
        } catch (IOException e) {
            // a binary wrapper, or unreadable; fall through to the sibling search
        }

        return siblingInterpreter(script).orElse("");
    }

    /**
     * Looks for the interpreter beside a console script.
     *
     * <p>A venv puts {@code python.exe} and {@code garak.exe} together in {@code Scripts\},
     * and a global Windows install puts {@code garak.exe} in {@code Scripts\} with
     * {@code python.exe} one level up, so both the script's directory and its parent are
     * worth checking. Restricted to those two places on purpose: falling back to whatever
     * {@code python} is on PATH could resolve to a different environment and report a
     * package directory that has nothing to do with the garak being run.
     */
    private static Optional<String> siblingInterpreter(Path script) {
        Path directory = script.getParent();
        if (directory == null) {
            return Optional.empty();
        }
        List<Path> searchDirs = new ArrayList<>(List.of(directory));
        if (directory.getParent() != null) {
            searchDirs.add(directory.getParent());
        }
        for (Path dir : searchDirs) {
            for (String name : List.of("python", "python3", "pypy3")) {
                for (String candidate : withExecutableExtensions(name)) {
                    Path path = dir.resolve(candidate);
                    if (Files.isRegularFile(path) && Files.isExecutable(path)) {
                        return Optional.of(path.toString());
                    }
                }
            }
        }
        return Optional.empty();
    }

    /** Asks the interpreter where the garak package lives. Null if it cannot say. */
    private static Path findPackageDirViaInterpreter(String interpreter) {
        Proc.Output out = Proc.run(
                List.of(interpreter, "-c", "import garak,os;print(os.path.dirname(garak.__file__))"),
                null, cleanEnv(), PROBE_TIMEOUT_SECONDS);
        if (!out.ok()) {
            return null;
        }
        return directoryOrNull(out.stdout().trim());
    }

    /**
     * Asks garak itself, via {@code --list_config}, which prints its {@code transient}
     * section including {@code package_dir}.
     *
     * <p>Needs no interpreter, so this is the route that works when pip has wrapped the
     * entry point in a binary. It costs a second garak startup, which is why it is only
     * tried after the local filesystem routes have failed.
     */
    private static Path findPackageDirViaGarak(List<String> command) {
        List<String> args = new ArrayList<>(command);
        args.add("--list_config");
        Proc.Output out = Proc.run(args, null, cleanEnv(), PROBE_TIMEOUT_SECONDS);
        return parsePackageDir(out.combined()).map(GarakLocator::directoryOrNull).orElse(null);
    }

    /** Pulls {@code package_dir} out of {@code --list_config} output. */
    public static Optional<String> parsePackageDir(String listConfigOutput) {
        if (listConfigOutput == null) {
            return Optional.empty();
        }
        Matcher matcher = PACKAGE_DIR.matcher(listConfigOutput);
        if (!matcher.find()) {
            return Optional.empty();
        }
        String value = matcher.group(1).trim();
        return value.isEmpty() || "None".equals(value) ? Optional.empty() : Optional.of(value);
    }

    private static Path directoryOrNull(String candidate) {
        if (candidate.isEmpty()) {
            return null;
        }
        try {
            Path dir = Path.of(candidate);
            return Files.isDirectory(dir) ? dir : null;
        } catch (RuntimeException e) {
            return null; // not a usable path on this platform
        }
    }

    private static Optional<Path> searchPath(String name) {
        String pathEnv = System.getenv("PATH");
        if (pathEnv == null) {
            return Optional.empty();
        }
        for (String entry : pathEnv.split(java.io.File.pathSeparator)) {
            if (entry.isBlank()) {
                continue;
            }
            for (String candidate : withExecutableExtensions(name)) {
                Path path = Path.of(entry, candidate);
                if (Files.isRegularFile(path) && Files.isExecutable(path)) {
                    return Optional.of(path);
                }
            }
        }
        return Optional.empty();
    }

    /**
     * The names an executable might have. On Windows a PATH entry for {@code garak} is
     * really {@code garak.exe}, so searching for the bare name finds nothing; PATHEXT
     * names the suffixes that count, and Java's ProcessBuilder can launch all of them.
     */
    private static List<String> withExecutableExtensions(String name) {
        return executableNames(name, isWindows(), System.getenv("PATHEXT"));
    }

    /** Platform-independent core of the above, so both branches can be tested anywhere. */
    public static List<String> executableNames(String name, boolean windows, String pathExt) {
        if (!windows || name.contains(".")) {
            return List.of(name);
        }
        List<String> names = new ArrayList<>();
        String extensions = pathExt == null || pathExt.isBlank()
                ? ".COM;.EXE;.BAT;.CMD" : pathExt;
        for (String extension : extensions.split(";")) {
            String trimmed = extension.trim();
            if (!trimmed.isEmpty()) {
                names.add(name + trimmed.toLowerCase(Locale.ROOT));
            }
        }
        names.add(name); // an extension-less script, e.g. under Git Bash or WSL
        return names;
    }

    public static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).startsWith("windows");
    }

    private static String stripExtension(String fileName) {
        String lower = fileName.toLowerCase(Locale.ROOT);
        int dot = lower.lastIndexOf('.');
        return dot > 0 ? lower.substring(0, dot) : lower;
    }

    /**
     * Environment for garak subprocesses.
     *
     * <p>{@code NO_PROXY} matters: a tester very often has {@code HTTP_PROXY} pointed at
     * Burp, and without this exclusion garak's call to the loopback bridge would be routed
     * back through Burp's proxy, producing a confusing loop.
     */
    public static Map<String, String> cleanEnv() {
        return Map.of(
                "NO_PROXY", "127.0.0.1,localhost,::1",
                "no_proxy", "127.0.0.1,localhost,::1",
                "PYTHONUNBUFFERED", "1",
                "PYTHONIOENCODING", "utf-8");
    }

    private static byte[] readHead(Path path, int limit) throws IOException {
        byte[] all = Files.readAllBytes(path);
        return all.length <= limit ? all : java.util.Arrays.copyOf(all, limit);
    }

    private static Installation unusable(List<String> problems) {
        return new Installation(List.of(), "", 0, 0, 0, null, null, "", "", problems);
    }

    private static String firstLine(String text) {
        int newline = text.indexOf('\n');
        return newline < 0 ? text : text.substring(0, newline);
    }
}
