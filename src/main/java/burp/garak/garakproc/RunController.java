// Copyright 2026 the garak Bridge authors
// SPDX-License-Identifier: Apache-2.0

package burp.garak.garakproc;

import burp.api.montoya.MontoyaApi;
import burp.garak.bridge.BridgeServer;
import burp.garak.bridge.ExchangeRunner;
import burp.garak.bridge.ExchangeStore;
import burp.garak.model.Exchange;
import burp.garak.model.Finding;
import burp.garak.model.RunConfig;
import burp.garak.model.Settings;
import burp.garak.model.TargetProfile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Drives one scan end to end: bridge up, configs written, garak launched, reports followed,
 * findings correlated back to the traffic that produced them.
 */
public final class RunController {

    public enum State {
        IDLE, STARTING, RUNNING, STOPPING, FINISHED, FAILED
    }

    /** Live counters for the run panel. */
    public record Progress(int promptsSent, int generated, int evaluated, int findings,
                           String currentProbe, int probesDone, int probesTotal,
                           int skipped, int rateLimited) {
    }

    public interface Listener {
        void onState(State state, String message);

        void onLog(String line);

        void onProgress(Progress progress);

        /** A finding, already correlated to its exchange and enriched from the catalogue. */
        void onFinding(Finding finding);
    }

    private static final DateTimeFormatter RUN_STAMP =
            DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss");

    private final MontoyaApi api;
    private final BridgeServer bridge;
    private final ExchangeStore store;
    private final List<Listener> listeners = new CopyOnWriteArrayList<>();

    private volatile State state = State.IDLE;
    private volatile GarakProcess process;
    private volatile ReportTailer tailer;
    private volatile ExchangeRunner runner;
    private volatile ConfigWriter.Files files;
    private volatile Path runDirectory;
    private volatile PluginCatalog catalogue = PluginCatalog.empty();

    private final AtomicInteger generated = new AtomicInteger();
    private final AtomicInteger evaluated = new AtomicInteger();
    private final AtomicInteger findingCount = new AtomicInteger();
    private final Set<String> probesSeen = new LinkedHashSet<>();
    private volatile String currentProbe = "";
    private volatile int probesTotal;
    private final List<Finding> findings = new CopyOnWriteArrayList<>();

    public RunController(MontoyaApi api, BridgeServer bridge, ExchangeStore store) {
        this.api = api;
        this.bridge = bridge;
        this.store = store;
    }

    public void addListener(Listener listener) {
        listeners.add(listener);
    }

    public State state() {
        return state;
    }

    public boolean isBusy() {
        return state == State.STARTING || state == State.RUNNING || state == State.STOPPING;
    }

    public List<Finding> findings() {
        return List.copyOf(findings);
    }

    public ExchangeStore exchanges() {
        return store;
    }

    public Optional<Path> reportDirectory() {
        return Optional.ofNullable(runDirectory);
    }

    public Optional<Path> digest() {
        ConfigWriter.Files current = files;
        if (current == null) {
            return Optional.empty();
        }
        Path html = current.digestFile();
        return Files.isRegularFile(html) ? Optional.of(html) : Optional.empty();
    }

    // ----------------------------------------------------------------- validation

    /** Everything wrong with this run, in the order a user would want to fix it. */
    public static List<String> preflightProblems(TargetProfile profile, RunConfig config,
                                                 GarakLocator.Installation installation,
                                                 MontoyaApi api) {
        List<String> problems = new ArrayList<>();
        if (profile == null) {
            problems.add("No target selected. Right-click a chat request in Burp and choose "
                    + "\"Send chat request to garak\".");
            return problems;
        }
        if (!profile.isRunnable()) {
            problems.add("Target is not ready: " + profile.blocker());
        }
        if (installation == null || !installation.isUsable()) {
            problems.add("garak was not found. Set its path in the garak tab's Settings.");
        }
        if (config.probes.isEmpty()) {
            problems.add("No probes selected.");
        }
        if (!config.allowOutOfScope && api != null && !profile.host.isEmpty()) {
            String url = profile.baseUrl() + "/";
            try {
                if (!api.scope().isInScope(url)) {
                    problems.add(profile.host + " is not in Burp's target scope. Add it to "
                            + "scope, or tick \"Allow out-of-scope target\" to override.");
                }
            } catch (RuntimeException e) {
                // scope check unavailable; not a reason to block the run
            }
        }
        return problems;
    }

    // ---------------------------------------------------------------------- start

    /**
     * Starts a run. Returns immediately; progress arrives through listeners.
     *
     * @throws IllegalStateException if a run is already in progress
     */
    public void start(TargetProfile profile, RunConfig config,
                      GarakLocator.Installation installation, Settings settings,
                      PluginCatalog catalogue) {
        if (isBusy()) {
            throw new IllegalStateException("a run is already in progress");
        }
        this.catalogue = catalogue == null ? PluginCatalog.empty() : catalogue;
        reset(config);
        setState(State.STARTING, "preparing");

        Thread thread = new Thread(() -> {
            try {
                runInBackground(profile, config, installation, settings);
            } catch (Exception e) {
                log("run failed: " + e);
                setState(State.FAILED, e.getMessage() == null ? e.toString() : e.getMessage());
                teardown();
            }
        }, "garak-run");
        thread.setDaemon(true);
        thread.start();
    }

    private void runInBackground(TargetProfile profile, RunConfig config,
                                 GarakLocator.Installation installation, Settings settings)
            throws IOException, InterruptedException {

        runDirectory = settings.resolveRunsDirectory()
                .resolve(LocalDateTime.now().format(RUN_STAMP) + "-" + safeName(profile.name));
        Files.createDirectories(runDirectory);
        log("run directory: " + runDirectory);

        if (!bridge.isRunning()) {
            // Worker threads must outnumber garak's parallel attempts, or requests queue
            // in the accept backlog and look like target latency.
            bridge.start(settings.bridgePort, Math.max(8, config.parallelAttempts * 2));
        }

        runner = new ExchangeRunner(api, profile, config, store, this::log);
        runner.onCircuitBreak(() -> {
            log("circuit breaker tripped - stopping the run");
            stop();
        });
        bridge.setHandler(runner::run);

        files = ConfigWriter.writeBridgeConfig(runDirectory, bridge.endpoint(), bridge.token(), config);
        log("generator config: " + files.generatorConfig());
        log("run config: " + files.runConfig());

        tailer = new ReportTailer(files.reportFile(), files.hitlogFile(), new TailerBridge());
        tailer.start();

        process = new GarakProcess(installation, this::log);
        process.start(files, config, runDirectory);
        setState(State.RUNNING, "running " + config.probes.size() + " probe(s)");

        int exit = process.await();

        // Let the tailer catch the final lines garak wrote on the way out.
        Thread.sleep(500);
        ReportTailer finalTailer = tailer;
        if (finalTailer != null) {
            finalTailer.stop();
        }
        boolean completed = finalTailer != null && finalTailer.sawCompletion();

        bridge.setHandler(null);

        if (process.wasCancelled()) {
            setState(State.FINISHED, "stopped after " + store.size() + " request(s)");
        } else if (exit == 0 || completed) {
            setState(State.FINISHED, summary());
        } else {
            setState(State.FAILED, "garak exited with code " + exit
                    + (findingCount.get() > 0 ? " after " + findingCount.get() + " finding(s)" : ""));
        }
        emitProgress();
    }

    private String summary() {
        int hits = findingCount.get();
        return hits == 0
                ? "no findings from " + store.size() + " request(s)"
                : hits + " finding" + (hits == 1 ? "" : "s") + " from " + store.size() + " request(s)";
    }

    // ----------------------------------------------------------------------- stop

    /** Stops garak and releases the bridge handler. Safe to call more than once. */
    public void stop() {
        if (state == State.IDLE || state == State.FINISHED || state == State.FAILED) {
            return;
        }
        setState(State.STOPPING, "stopping");
        GarakProcess current = process;
        if (current != null) {
            current.cancel();
        }
        bridge.setHandler(null);
    }

    private void teardown() {
        ReportTailer current = tailer;
        if (current != null) {
            current.stop();
        }
        bridge.setHandler(null);
    }

    private void reset(RunConfig config) {
        store.clear();
        findings.clear();
        generated.set(0);
        evaluated.set(0);
        findingCount.set(0);
        probesSeen.clear();
        currentProbe = "";
        probesTotal = config.probes.size();
    }

    // -------------------------------------------------------------- tailer bridge

    /** Turns report/hitlog records into progress and correlated findings. */
    private final class TailerBridge implements ReportTailer.Listener {

        @Override
        public void onStart(String garakVersion, String runId) {
            log("garak " + garakVersion + " started, run " + runId);
        }

        @Override
        public void onAttemptGenerated(String probe, String prompt) {
            noteProbe(probe);
            generated.incrementAndGet();
            emitProgress();
        }

        @Override
        public void onAttemptEvaluated(String probe, String prompt) {
            noteProbe(probe);
            evaluated.incrementAndGet();
            emitProgress();
        }

        @Override
        public void onEval(String probe, String detector, int passed, int failed, int nones,
                           int totalEvaluated) {
            String detail = probe + " / " + detector + ": " + passed + " passed, "
                    + failed + " failed" + (nones > 0 ? ", " + nones + " skipped" : "");
            log(detail);
            if (nones > 0 && nones >= totalEvaluated / 2 && totalEvaluated > 0) {
                // Half the generations produced nothing: almost always a broken extraction
                // rule rather than a coy model, and worth saying out loud.
                log("  ^ over half of these produced no answer. Check the response extraction "
                        + "rule on the Target tab with \"Test connection\".");
            }
        }

        @Override
        public void onFinding(Finding finding) {
            enrich(finding);
            findings.add(finding);
            findingCount.incrementAndGet();
            listeners.forEach(listener -> listener.onFinding(finding));
            emitProgress();
        }

        @Override
        public void onCompletion() {
            log("garak run complete");
        }

        @Override
        public void onProblem(String message) {
            log(message);
        }
    }

    /** Links a finding to its HTTP exchange and copies probe metadata onto it. */
    private void enrich(Finding finding) {
        store.find(finding.prompt, finding.attemptIdx)
                .map(exchange -> exchange.id)
                .ifPresent(id -> finding.exchangeId = id);

        String qualified = finding.probe.startsWith("probes.")
                ? finding.probe : "probes." + finding.probe;
        catalogue.byName(qualified).ifPresent(probe -> {
            finding.tags = String.join(", ", probe.tags());
            finding.tier = probe.tier();
            if (finding.goal.isBlank()) {
                finding.goal = probe.goal();
            }
        });
    }

    private void noteProbe(String probe) {
        if (probe == null || probe.isBlank()) {
            return;
        }
        currentProbe = probe;
        synchronized (probesSeen) {
            probesSeen.add(probe);
        }
        ExchangeRunner current = runner;
        if (current != null) {
            current.setCurrentProbe(probe);
        }
    }

    // ------------------------------------------------------------------ listeners

    private void setState(State next, String message) {
        state = next;
        listeners.forEach(listener -> listener.onState(next, message));
    }

    private void log(String line) {
        listeners.forEach(listener -> listener.onLog(line));
    }

    private void emitProgress() {
        int done;
        synchronized (probesSeen) {
            done = Math.max(0, probesSeen.size() - 1);
        }
        Progress progress = new Progress(
                store.size(),
                generated.get(),
                evaluated.get(),
                findingCount.get(),
                currentProbe,
                done,
                probesTotal,
                (int) store.counted(Exchange.Status.SKIPPED),
                (int) store.counted(Exchange.Status.RATE_LIMITED));
        listeners.forEach(listener -> listener.onProgress(progress));
    }

    private static String safeName(String name) {
        String cleaned = name == null ? "" : name.replaceAll("[^A-Za-z0-9._-]", "-");
        if (cleaned.length() > 40) {
            cleaned = cleaned.substring(0, 40);
        }
        return cleaned.isBlank() ? "target" : cleaned;
    }
}
