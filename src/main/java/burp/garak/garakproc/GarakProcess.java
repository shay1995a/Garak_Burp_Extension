// Copyright 2026 the garak Bridge authors
// SPDX-License-Identifier: Apache-2.0

package burp.garak.garakproc;

import burp.garak.model.RunConfig;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/**
 * Spawns garak and follows it to completion.
 *
 * <p>Flag names are chosen from the detected version: {@code --target_type} replaced
 * {@code --model_type} in 0.13 and {@code --spec} replaced {@code --probes} in 0.15, and
 * the deprecated forms still work but print warnings that make the run log harder to read.
 */
public final class GarakProcess {

    /** Substrings that identify a failure worth explaining rather than dumping raw. */
    private static final List<String[]> KNOWN_FAILURES = List.of(
            new String[]{"No module named garak",
                    "garak is not installed in that Python environment"},
            new String[]{"BadGeneratorException",
                    "garak rejected the bridge generator config - see the lines above"},
            new String[]{"APIKeyMissingError",
                    "a probe or detector wanted an API key; set it in the environment or "
                            + "choose probes that do not need a second model"},
            new String[]{"ConnectionError",
                    "garak could not reach the bridge. Check that no HTTP_PROXY in your "
                            + "environment is capturing 127.0.0.1 traffic"},
            new String[]{"Requested probe not found",
                    "one of the selected probes does not exist in this garak version"});

    /** CSI escape sequences: ESC [ ... final-byte. */
    private static final java.util.regex.Pattern ANSI =
            java.util.regex.Pattern.compile("\\u001B\\[[0-9;?]*[ -/]*[@-~]");

    private final GarakLocator.Installation installation;
    private final Consumer<String> log;
    private final AtomicBoolean cancelled = new AtomicBoolean();

    private volatile Process process;
    private volatile List<String> commandLine = List.of();

    public GarakProcess(GarakLocator.Installation installation, Consumer<String> log) {
        this.installation = installation;
        this.log = log;
    }

    /** The exact argv, for display and for the "copy command" button. */
    public List<String> commandLine() {
        return commandLine;
    }

    /** Builds the argv without running anything, so the UI can show it before launch. */
    public List<String> buildCommand(ConfigWriter.Files files, RunConfig config) {
        List<String> argv = new ArrayList<>(installation.command());

        argv.add(installation.supportsTargetType() ? "--target_type" : "--model_type");
        argv.add("rest");

        argv.add("--generator_option_file");
        argv.add(files.generatorConfig().toAbsolutePath().toString());

        argv.add("--config");
        argv.add(files.runConfig().toAbsolutePath().toString());

        argv.add("--report_prefix");
        argv.add(files.reportPrefix());

        if (!config.probes.isEmpty()) {
            if (installation.supportsSpec()) {
                // --spec wants fully qualified names.
                argv.add("--spec");
                argv.add(String.join(",", config.probes));
            } else {
                // --probes wants them without the leading "probes.".
                argv.add("--probes");
                argv.add(String.join(",", config.probes.stream()
                        .map(GarakProcess::stripProbesPrefix).toList()));
            }
        }
        return argv;
    }

    static String stripProbesPrefix(String name) {
        return name.startsWith("probes.") ? name.substring("probes.".length()) : name;
    }

    /**
     * Starts garak. Returns once the process has been spawned; output streams into the log
     * on background threads and {@link #await} blocks for the exit code.
     */
    public void start(ConfigWriter.Files files, RunConfig config, Path workingDir)
            throws IOException {
        commandLine = buildCommand(files, config);
        log.accept("$ " + String.join(" ", commandLine));

        ProcessBuilder builder = new ProcessBuilder(commandLine);
        if (workingDir != null) {
            builder.directory(workingDir.toFile());
        }
        Map<String, String> environment = builder.environment();
        environment.putAll(GarakLocator.cleanEnv());

        process = builder.start();
        follow(process.getInputStream(), "");
        follow(process.getErrorStream(), "");
    }

    private void follow(InputStream stream, String prefix) {
        Thread thread = new Thread(() -> {
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(stream, StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    String cleaned = stripAnsi(line);
                    if (!cleaned.isBlank()) {
                        log.accept(prefix + cleaned);
                        explainIfKnownFailure(cleaned);
                    }
                }
            } catch (IOException e) {
                // process ended; nothing further to read
            }
        }, "garak-output");
        thread.setDaemon(true);
        thread.start();
    }

    private void explainIfKnownFailure(String line) {
        for (String[] failure : KNOWN_FAILURES) {
            if (line.contains(failure[0])) {
                log.accept("  ^ " + failure[1]);
                return;
            }
        }
    }

    /** Waits for garak to exit. Returns the exit code, or -1 if it was cancelled. */
    public int await() throws InterruptedException {
        Process running = process;
        if (running == null) {
            return -1;
        }
        int code = running.waitFor();
        return cancelled.get() ? -1 : code;
    }

    public boolean isRunning() {
        Process running = process;
        return running != null && running.isAlive();
    }

    public boolean wasCancelled() {
        return cancelled.get();
    }

    /**
     * Stops garak and everything it started.
     *
     * <p>Descendants matter: with {@code parallel_attempts} set, garak runs a multiprocessing
     * pool, and killing only the parent leaves workers still hammering the target.
     */
    public void cancel() {
        if (!cancelled.compareAndSet(false, true)) {
            return;
        }
        Process running = process;
        if (running == null) {
            return;
        }
        log.accept("stopping garak…");
        running.descendants().forEach(ProcessHandle::destroy);
        running.destroy();
        try {
            if (!running.waitFor(5, TimeUnit.SECONDS)) {
                running.descendants().forEach(ProcessHandle::destroyForcibly);
                running.destroyForcibly();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            running.destroyForcibly();
        }
    }

    /** garak colours its console output; the run log is plain text. */
    static String stripAnsi(String line) {
        return ANSI.matcher(line).replaceAll("");
    }
}
