// Copyright 2026 the garak Bridge authors
// SPDX-License-Identifier: Apache-2.0

package burp.garak.ui;

import burp.garak.GarakContext;
import burp.garak.garakproc.ConfigWriter;
import burp.garak.garakproc.GarakLocator;
import burp.garak.garakproc.RunController;
import burp.garak.model.Finding;
import burp.garak.model.RunConfig;
import burp.garak.model.TargetProfile;
import burp.garak.util.Json;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JSpinner;
import javax.swing.JTextArea;
import javax.swing.SpinnerNumberModel;
import javax.swing.Timer;
import java.awt.BorderLayout;
import java.awt.Desktop;
import java.awt.Dimension;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

/** Pre-flight, run controls, live progress and the run log. */
public final class RunPanel extends JPanel implements RunController.Listener {

    /** Trim the log rather than let a long run grow it without bound. */
    private static final int LOG_LIMIT = 400_000;

    private final GarakContext context;

    private final JButton startButton = new JButton("Start scan");
    private final JButton stopButton = new JButton("Stop");
    private final JLabel stateLabel = Ui.bold("Idle");
    private final JLabel preflight = new JLabel(" ");

    private final JSpinner generations = spinner(1, 1, 100);
    private final JSpinner promptCap = spinner(64, 1, 10_000);
    private final JSpinner concurrency = spinner(2, 1, 32);
    private final JSpinner delay = spinner(250, 0, 60_000);
    private final JSpinner jitter = spinner(250, 0, 60_000);
    private final JSpinner parallelAttempts = spinner(4, 1, 64);
    private final JSpinner timeout = spinner(60, 5, 900);
    private final JCheckBox allowOutOfScope = new JCheckBox("Allow out-of-scope target");
    private final JCheckBox createIssues = new JCheckBox("Add findings to Burp Issues", true);

    private final JProgressBar progress = new JProgressBar();
    private final JLabel counters = Ui.hint(" ");
    private final JTextArea log = Ui.monospace(14, 100);

    private boolean populating;

    public RunPanel(GarakContext context) {
        super(new BorderLayout(6, 6));
        this.context = context;

        add(controls(), BorderLayout.NORTH);
        add(logArea(), BorderLayout.CENTER);

        context.controller().addListener(this);
        loadConfig();
        refreshPreflight();

        // Scope, probe selection and target readiness all change on other tabs; a slow
        // poll keeps the pre-flight line honest without wiring listeners into every panel.
        Timer poll = new Timer(1500, event -> refreshPreflight());
        poll.setRepeats(true);
        poll.start();
    }

    // ------------------------------------------------------------------- layout

    private JPanel controls() {
        startButton.addActionListener(event -> start());
        stopButton.addActionListener(event -> context.controller().stop());
        stopButton.setEnabled(false);

        JPanel buttons = Ui.row(startButton, stopButton, Ui.gap(12), stateLabel);
        buttons.add(Ui.gap(12));
        buttons.add(Ui.button("Show command", event -> showCommand()));
        buttons.add(Ui.button("Export standalone config", event -> exportStandalone()));
        buttons.add(Ui.button("Open report", event -> openReport()));

        JPanel volume = Ui.row(
                Ui.label("Answers per prompt:"), generations,
                Ui.label("Max prompts per probe:"), promptCap,
                Ui.label("garak parallel attempts:"), parallelAttempts);

        JPanel throttle = Ui.row(
                Ui.label("Concurrent requests:"), concurrency,
                Ui.label("Delay (ms):"), delay,
                Ui.label("Jitter (ms):"), jitter,
                Ui.label("Reply timeout (s):"), timeout);

        JPanel options = Ui.row(allowOutOfScope, createIssues);

        progress.setStringPainted(true);
        progress.setPreferredSize(new Dimension(400, 20));

        JPanel panel = new JPanel();
        panel.setLayout(new javax.swing.BoxLayout(panel, javax.swing.BoxLayout.Y_AXIS));
        panel.add(buttons);
        panel.add(Ui.titled("How much traffic this will generate", Ui.column(volume, throttle, options)));
        panel.add(Ui.row(preflight));
        panel.add(Ui.row(progress, counters));

        for (JSpinner field : List.of(generations, promptCap, concurrency, delay, jitter,
                parallelAttempts, timeout)) {
            field.addChangeListener(event -> saveConfig());
        }
        allowOutOfScope.addActionListener(event -> saveConfig());
        createIssues.addActionListener(event -> saveConfig());

        return panel;
    }

    private JScrollPane logArea() {
        log.setEditable(false);
        JScrollPane scroll = new JScrollPane(log);
        scroll.setBorder(BorderFactory.createTitledBorder("Run log"));
        return scroll;
    }

    private static JSpinner spinner(int value, int min, int max) {
        JSpinner spinner = new JSpinner(new SpinnerNumberModel(value, min, max, 1));
        spinner.setPreferredSize(new Dimension(70, spinner.getPreferredSize().height));
        return spinner;
    }

    // -------------------------------------------------------------- config binding

    private void loadConfig() {
        populating = true;
        try {
            RunConfig config = context.runConfig();
            generations.setValue(config.generations);
            promptCap.setValue(config.softProbePromptCap);
            concurrency.setValue(config.maxConcurrent);
            delay.setValue(config.delayMs);
            jitter.setValue(config.jitterMs);
            parallelAttempts.setValue(config.parallelAttempts);
            timeout.setValue(Math.max(5, config.requestTimeoutMs / 1000));
            allowOutOfScope.setSelected(config.allowOutOfScope);
            createIssues.setSelected(config.createAuditIssues);
        } finally {
            populating = false;
        }
    }

    private void saveConfig() {
        if (populating) {
            return;
        }
        RunConfig config = context.runConfig();
        config.generations = (Integer) generations.getValue();
        config.softProbePromptCap = (Integer) promptCap.getValue();
        config.maxConcurrent = (Integer) concurrency.getValue();
        config.delayMs = (Integer) delay.getValue();
        config.jitterMs = (Integer) jitter.getValue();
        config.parallelAttempts = (Integer) parallelAttempts.getValue();
        config.requestTimeoutMs = ((Integer) timeout.getValue()) * 1000;
        config.allowOutOfScope = allowOutOfScope.isSelected();
        config.createAuditIssues = createIssues.isSelected();
        context.saveRunConfig();
        refreshPreflight();
    }

    /**
     * Keeps an honest estimate in front of the user. This tool sends adversarial prompts to
     * someone's live application, and the difference between 60 requests and 60,000 is one
     * spinner, so the number belongs on screen rather than in a surprise.
     */
    private void refreshPreflight() {
        if (context.controller().isBusy()) {
            return;
        }
        RunConfig config = context.runConfig();
        List<String> problems = RunController.preflightProblems(
                context.active().orElse(null), config,
                context.installation().orElse(null), context.api());

        if (!problems.isEmpty()) {
            preflight.setText("Not ready: " + String.join("  ·  ", problems));
            startButton.setEnabled(false);
            return;
        }
        long requests = config.estimatedRequests();
        long seconds = config.estimatedSeconds();
        preflight.setText(String.format(
                "Ready: %d probe(s) → up to %,d requests to %s, roughly %s at this throttle.",
                config.probes.size(), requests,
                context.active().map(TargetProfile::baseUrl).orElse("?"),
                humanDuration(seconds)));
        startButton.setEnabled(true);
    }

    private static String humanDuration(long seconds) {
        if (seconds < 90) {
            return seconds + "s";
        }
        if (seconds < 5400) {
            return (seconds / 60) + " min";
        }
        return String.format("%.1f hours", seconds / 3600.0);
    }

    // ---------------------------------------------------------------------- run

    private void start() {
        Optional<TargetProfile> profile = context.active();
        Optional<GarakLocator.Installation> installation = context.installation();
        if (profile.isEmpty() || installation.isEmpty()) {
            refreshPreflight();
            return;
        }
        RunConfig config = context.runConfig();

        String message = String.format(
                "Send up to %,d adversarial prompts to %s?%n%n"
                        + "Probes: %d%nConcurrency: %d, delay %dms + up to %dms jitter%n"
                        + "Estimated time: %s%n%n"
                        + "Every request goes through Burp and will appear in your history.",
                config.estimatedRequests(), profile.get().baseUrl(), config.probes.size(),
                config.maxConcurrent, config.delayMs, config.jitterMs,
                humanDuration(config.estimatedSeconds()));

        int answer = JOptionPane.showConfirmDialog(this, message, "Start garak scan",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
        if (answer != JOptionPane.OK_OPTION) {
            return;
        }

        log.setText("");
        progress.setValue(0);
        progress.setIndeterminate(true);
        context.controller().start(profile.get(), config, installation.get(),
                context.settings(), context.catalogue());
    }

    private void showCommand() {
        Optional<GarakLocator.Installation> installation = context.installation();
        if (installation.isEmpty()) {
            JOptionPane.showMessageDialog(this, "garak has not been located yet. "
                    + "Set its path in the Settings tab.");
            return;
        }
        Path runDir = context.controller().reportDirectory()
                .orElse(context.settings().resolveRunsDirectory().resolve("<run>"));
        ConfigWriter.Files files = new ConfigWriter.Files(
                runDir.resolve("generator.json"), runDir.resolve("run.json"), runDir, "run");
        List<String> argv = new burp.garak.garakproc.GarakProcess(installation.get(), line -> {
        }).buildCommand(files, context.runConfig());

        String command = String.join(" ", argv);
        JTextArea area = Ui.monospace(6, 90);
        area.setText(command + "\n\nNote: the generator config points at the in-Burp bridge, "
                + "which only answers while a run is in progress.");
        area.setEditable(false);
        area.setCaretPosition(0);
        Object[] options = {"Copy", "Close"};
        int answer = JOptionPane.showOptionDialog(this, new JScrollPane(area),
                "garak command line", JOptionPane.DEFAULT_OPTION, JOptionPane.PLAIN_MESSAGE,
                null, options, options[1]);
        if (answer == 0) {
            Toolkit.getDefaultToolkit().getSystemClipboard()
                    .setContents(new StringSelection(command), null);
        }
    }

    /**
     * Writes a config that points garak straight at the target, for reproducing a run
     * headlessly. Limitations are shown rather than glossed over: several of the bridge's
     * capabilities have no RestGenerator equivalent.
     */
    private void exportStandalone() {
        Optional<TargetProfile> active = context.active();
        if (active.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No target selected.");
            return;
        }
        ConfigWriter.Standalone standalone =
                ConfigWriter.standaloneGenerator(active.get(), context.burpProxyPort());

        StringBuilder text = new StringBuilder(Json.PRETTY.toJson(standalone.config()));
        text.append("\n\n# Run with:\n#   garak --target_type rest -G <this file> --probes <names>\n");
        if (!standalone.limitations().isEmpty()) {
            text.append("\n# What this config cannot reproduce:\n");
            standalone.limitations().forEach(limitation ->
                    text.append("#   - ").append(limitation).append('\n'));
        }

        JTextArea area = Ui.monospace(24, 96);
        area.setText(text.toString());
        area.setCaretPosition(0);

        Object[] options = {"Copy", "Save to run folder", "Close"};
        int answer = JOptionPane.showOptionDialog(this, new JScrollPane(area),
                "Standalone garak config", JOptionPane.DEFAULT_OPTION,
                JOptionPane.PLAIN_MESSAGE, null, options, options[2]);
        if (answer == 0) {
            Toolkit.getDefaultToolkit().getSystemClipboard()
                    .setContents(new StringSelection(area.getText()), null);
        } else if (answer == 1) {
            saveStandalone(standalone);
        }
    }

    private void saveStandalone(ConfigWriter.Standalone standalone) {
        try {
            Path directory = context.settings().resolveRunsDirectory();
            Files.createDirectories(directory);
            Path file = directory.resolve("standalone-generator.json");
            Json.write(file, standalone.config());
            JOptionPane.showMessageDialog(this, "Written to " + file);
        } catch (IOException e) {
            JOptionPane.showMessageDialog(this, "Could not write the config: " + e.getMessage(),
                    "Export failed", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void openReport() {
        Optional<Path> digest = context.controller().digest();
        Optional<Path> directory = context.controller().reportDirectory();
        Path target = digest.orElse(directory.orElse(null));
        if (target == null) {
            JOptionPane.showMessageDialog(this, "No run has produced a report yet.");
            return;
        }
        try {
            if (Desktop.isDesktopSupported()) {
                Desktop.getDesktop().open(target.toFile());
            } else {
                JOptionPane.showMessageDialog(this, target.toString());
            }
        } catch (IOException | UnsupportedOperationException e) {
            JOptionPane.showMessageDialog(this, "Report is at:\n" + target);
        }
    }

    // -------------------------------------------------------- controller callbacks

    @Override
    public void onState(RunController.State state, String message) {
        Ui.onEdt(() -> {
            stateLabel.setText(switch (state) {
                case IDLE -> "Idle";
                case STARTING -> "Starting…";
                case RUNNING -> "Running";
                case STOPPING -> "Stopping…";
                case FINISHED -> "Finished";
                case FAILED -> "Failed";
            } + (message == null || message.isBlank() ? "" : " — " + message));

            boolean busy = state == RunController.State.STARTING
                    || state == RunController.State.RUNNING
                    || state == RunController.State.STOPPING;
            startButton.setEnabled(!busy);
            stopButton.setEnabled(busy);
            if (!busy) {
                progress.setIndeterminate(false);
                refreshPreflight();
            }
        });
    }

    @Override
    public void onLog(String line) {
        Ui.onEdt(() -> {
            log.append(line);
            log.append("\n");
            if (log.getDocument().getLength() > LOG_LIMIT) {
                try {
                    log.getDocument().remove(0, LOG_LIMIT / 4);
                } catch (javax.swing.text.BadLocationException e) {
                    log.setText("");
                }
            }
            log.setCaretPosition(log.getDocument().getLength());
        });
    }

    @Override
    public void onProgress(RunController.Progress update) {
        Ui.onEdt(() -> {
            if (update.probesTotal() > 0) {
                progress.setIndeterminate(false);
                progress.setMaximum(update.probesTotal());
                progress.setValue(Math.min(update.probesDone(), update.probesTotal()));
                progress.setString(update.currentProbe().isBlank()
                        ? update.probesDone() + " / " + update.probesTotal() + " probes"
                        : shortProbe(update.currentProbe()) + "  ("
                                + update.probesDone() + "/" + update.probesTotal() + ")");
            }
            StringBuilder text = new StringBuilder();
            text.append(update.promptsSent()).append(" requests · ")
                    .append(update.evaluated()).append(" scored · ")
                    .append(update.findings()).append(" findings");
            if (update.skipped() > 0) {
                text.append(" · ").append(update.skipped()).append(" skipped");
            }
            if (update.rateLimited() > 0) {
                text.append(" · ").append(update.rateLimited()).append(" rate limited");
            }
            counters.setText(text.toString());
        });
    }

    @Override
    public void onFinding(Finding finding) {
        // Findings are rendered by ResultsPanel; nothing to do here.
    }

    private static String shortProbe(String probe) {
        return probe.startsWith("probes.") ? probe.substring("probes.".length()) : probe;
    }
}
