// Copyright 2026 the garak Bridge authors
// SPDX-License-Identifier: Apache-2.0

package burp.garak.ui;

import burp.garak.GarakContext;
import burp.garak.bridge.TrialSender;
import burp.garak.capture.Calibrator;
import burp.garak.capture.RequestAnalyzer;
import burp.garak.garakproc.GarakLocator;
import burp.garak.garakproc.PluginCatalog;
import burp.garak.garakproc.RunController;
import burp.garak.model.Finding;
import burp.garak.model.InsertionPoint;
import burp.garak.model.RunConfig;
import burp.garak.model.ScanDepth;
import burp.garak.model.TargetProfile;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;

/**
 * The whole job on one screen, as three steps that lead into each other.
 *
 * <p>The extension works the request out on its own, offers a cheap check that proves it
 * got it right, and only then recommends a real scan. Each stage's next action is the one
 * big button, so there is nothing to configure before starting and nothing to remember
 * about the order. Everything the older tabs exposed is still there behind "Advanced".
 */
public final class ScanPanel extends JPanel implements RunController.Listener,
        GarakContext.ProfileListener {

    /** Probes the quick test always includes: trivial, and it proves the plumbing. */
    private static final String PLUMBING_PROBE = "probes.test.Blank";

    /** Real probes sampled into the quick test, so it previews the scan that follows. */
    private static final int SMOKE_SAMPLE_PROBES = 2;

    private enum Stage {
        NO_TARGET, ANALYSED, CHECKED, TESTED, BUSY
    }

    private final GarakContext context;
    private final Consumer<Boolean> onAdvancedToggled;
    private final Runnable onOpenSettings;
    private final ResultsPanel resultsPanel;

    private final JComboBox<TargetProfile> targetChooser = new JComboBox<>();
    private final JCheckBox advanced = new JCheckBox("Advanced");

    private final StepRow step1 = new StepRow("1", "Read the request");
    private final StepRow step2 = new StepRow("2", "Check it against the live endpoint");
    private final StepRow step3 = new StepRow("3", "Quick test scan");
    private final StepRow step4 = new StepRow("4", "Full scan");

    private final JComboBox<String> presetChooser = new JComboBox<>();
    private final JComboBox<ScanDepth> depthChooser = new JComboBox<>(ScanDepth.values());
    private final JLabel estimate = Ui.hint(" ");

    private final JButton actionButton = new JButton("Run");
    private final JButton stopButton = new JButton("Stop");
    private final JProgressBar progress = new JProgressBar();
    private final JLabel counters = Ui.hint(" ");
    private final JTextArea activity = Ui.monospace(12, 100);

    private List<PluginCatalog.Preset> presets = List.of();
    private volatile boolean checking;
    private volatile boolean lastRunWasSmoke;
    private boolean populating;

    public ScanPanel(GarakContext context, ResultsPanel resultsPanel,
                     Consumer<Boolean> onAdvancedToggled, Runnable onOpenSettings) {
        super(new BorderLayout(6, 6));
        this.context = context;
        this.resultsPanel = resultsPanel;
        this.onAdvancedToggled = onAdvancedToggled;
        this.onOpenSettings = onOpenSettings;

        add(header(), BorderLayout.NORTH);
        add(output(), BorderLayout.CENTER);

        context.addProfileListener(this);
        context.controller().addListener(this);
        reloadPresets();
        refresh();
    }

    // -------------------------------------------------------------------- layout

    private JComponent header() {
        targetChooser.addActionListener(event -> {
            if (populating) {
                return;
            }
            if (targetChooser.getSelectedItem() instanceof TargetProfile profile) {
                context.setActive(profile);
            }
        });
        advanced.setToolTipText("Show the target, probe, run and settings tabs");
        advanced.addActionListener(event -> onAdvancedToggled.accept(advanced.isSelected()));

        JPanel top = Ui.row(Ui.bold("Target:"), targetChooser);
        top.add(Box.createHorizontalGlue());
        top.add(advanced);

        JPanel steps = new JPanel();
        steps.setLayout(new BoxLayout(steps, BoxLayout.Y_AXIS));
        steps.setBorder(BorderFactory.createEmptyBorder(4, 8, 4, 8));
        steps.add(step1);
        steps.add(step2);
        steps.add(step3);
        steps.add(step4);
        steps.add(fullScanControls());

        actionButton.setFont(actionButton.getFont().deriveFont(Font.BOLD));
        actionButton.addActionListener(event -> takeNextAction());
        stopButton.addActionListener(event -> context.controller().stop());
        stopButton.setEnabled(false);
        progress.setStringPainted(true);
        progress.setPreferredSize(new Dimension(300, 18));

        JPanel action = Ui.row(actionButton, stopButton, Ui.gap(10), progress, counters);

        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.add(top);
        panel.add(steps);
        panel.add(action);
        return panel;
    }

    /** The only two choices a scan actually needs: what to test, and how hard. */
    private JComponent fullScanControls() {
        presetChooser.addActionListener(event -> {
            if (!populating) {
                applyPreset();
            }
        });
        depthChooser.addActionListener(event -> {
            if (!populating) {
                applyDepth();
            }
        });
        depthChooser.setSelectedItem(ScanDepth.STANDARD);

        JPanel row = Ui.row(
                Ui.label("        Test for:"), presetChooser,
                Ui.gap(8), Ui.label("Depth:"), depthChooser,
                Ui.gap(8), estimate);
        row.setAlignmentX(Component.LEFT_ALIGNMENT);
        return row;
    }

    private JComponent output() {
        activity.setEditable(false);
        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Findings", resultsPanel);
        tabs.addTab("Activity", new JScrollPane(activity));
        return tabs;
    }

    // ------------------------------------------------------------------- staging

    private Stage stage() {
        if (context.controller().isBusy() || checking) {
            return Stage.BUSY;
        }
        Optional<TargetProfile> active = context.active();
        if (active.isEmpty() || !active.get().isRunnable()) {
            return active.isEmpty() ? Stage.NO_TARGET : Stage.ANALYSED;
        }
        TargetProfile profile = active.get();
        if (!profile.isChecked()) {
            return Stage.ANALYSED;
        }
        return profile.smokeTestedAt > 0 ? Stage.TESTED : Stage.CHECKED;
    }

    private void takeNextAction() {
        Stage stage = stage();
        // Only the scanning steps need garak; checking the endpoint does not, so that
        // stays available while garak is still being set up.
        if ((stage == Stage.CHECKED || stage == Stage.TESTED) && !garakReady()) {
            onOpenSettings.run();
            return;
        }
        switch (stage) {
            case ANALYSED -> runCheck();
            case CHECKED -> runScan(true);
            case TESTED -> runScan(false);
            default -> {
            }
        }
    }

    /** Recomputes every step's state from the profile. The single source of UI truth. */
    void refresh() {
        Ui.onEdt(() -> {
            Optional<TargetProfile> active = context.active();
            Stage stage = stage();

            if (active.isEmpty()) {
                step1.set(StepRow.State.WAITING, "Nothing captured yet",
                        "Right-click a chat request anywhere in Burp and choose "
                                + "\"Send chat request to garak\".");
                step2.set(StepRow.State.WAITING, "", "");
                step3.set(StepRow.State.WAITING, "", "");
                step4.set(StepRow.State.WAITING, "", "");
                actionButton.setText("Waiting for a request");
                actionButton.setEnabled(false);
                stopButton.setEnabled(false);
                updateEstimate();
                return;
            }

            TargetProfile profile = active.get();
            renderStep1(profile);
            renderStep2(profile);
            renderStep3(profile);
            renderStep4(profile);

            boolean busy = stage == Stage.BUSY;
            boolean needsGarak = stage == Stage.CHECKED || stage == Stage.TESTED;
            stopButton.setEnabled(context.controller().isBusy());
            actionButton.setEnabled(!busy && profile.isRunnable());
            actionButton.setText(switch (stage) {
                case BUSY -> checking ? "Checking…" : "Running…";
                case ANALYSED -> "Check this endpoint  ▶";
                case CHECKED -> "Run quick test scan  ▶";
                case TESTED -> "Run full scan  ▶";
                case NO_TARGET -> "Waiting for a request";
            });
            if (!profile.isRunnable()) {
                actionButton.setText("Mark the message text first");
            } else if (needsGarak && !garakReady() && !busy) {
                actionButton.setText("Set up garak  ▶");
            }
            updateEstimate();
        });
    }

    private void renderStep1(TargetProfile profile) {
        if (!profile.isRunnable()) {
            step1.set(StepRow.State.PROBLEM, "Could not find the message field",
                    "Tick Advanced, open the Target tab, select the message text in the "
                            + "request and press \"Mark selection as prompt\".");
            return;
        }
        step1.set(StepRow.State.DONE, profile.baseUrl(),
                "Prompt goes to  " + profile.insertionPoints.get(0).describe()
                        + "     ·     Reply read from  " + profile.extractor.describe());
    }

    private void renderStep2(TargetProfile profile) {
        if (checking) {
            step2.set(StepRow.State.RUNNING, "Sending two test prompts…", "");
            return;
        }
        if (!profile.isChecked()) {
            step2.set(StepRow.State.NEXT, "Not checked yet",
                    "Sends a couple of harmless prompts to confirm the message really "
                            + "reaches the model and the reply is read correctly.");
            return;
        }
        String detail = "Typical reply " + profile.measuredLatencyMs + " ms"
                + "     ·     throttled to " + context.runConfig().maxConcurrent
                + " at a time, " + context.runConfig().delayMs + " ms apart";
        step2.set(profile.isProven() ? StepRow.State.DONE : StepRow.State.WARN,
                profile.checkedSummary, detail);
    }

    private void renderStep3(TargetProfile profile) {
        if (profile.smokeTestedAt > 0) {
            step3.set(StepRow.State.DONE, profile.smokeSummary,
                    "garak ran end to end against this target.");
            return;
        }
        if (!profile.isChecked()) {
            step3.set(StepRow.State.WAITING, "", "");
            return;
        }
        if (!garakReady()) {
            step3.set(StepRow.State.PROBLEM, "garak has not been found yet",
                    "Press the button below to point the extension at your garak install.");
            return;
        }
        step3.set(StepRow.State.NEXT, "Recommended before a long run",
                "A dozen or so real prompts, under a minute. Proves garak itself is wired up "
                        + "before you commit to a full scan.");
    }

    private void renderStep4(TargetProfile profile) {
        if (profile.smokeTestedAt > 0) {
            step4.set(StepRow.State.NEXT, "Ready", "");
        } else if (profile.isChecked()) {
            step4.set(StepRow.State.WAITING, "After the quick test", "");
        } else {
            step4.set(StepRow.State.WAITING, "", "");
        }
    }

    private boolean garakReady() {
        return context.installation().map(GarakLocator.Installation::isUsable).orElse(false);
    }

    // --------------------------------------------------------------- step 2: check

    /**
     * Proves the configuration against the live endpoint before any real scan.
     *
     * <p>Also the only opportunity to measure the endpoint, so the throttle is set from
     * what was observed rather than from a guess.
     */
    private void runCheck() {
        Optional<TargetProfile> active = context.active();
        if (active.isEmpty()) {
            return;
        }
        TargetProfile profile = active.get();
        checking = true;
        refresh();
        log("Checking " + profile.baseUrl() + " …");

        Thread worker = new Thread(() -> {
            List<InsertionPoint> candidates = candidatesFor(profile);
            TrialSender sender = new TrialSender(context.api(), profile,
                    context.runConfig().requestTimeoutMs);
            Calibrator.Outcome outcome = Calibrator.calibrate(candidates, sender, this::log);

            if (outcome.usable()) {
                profile.insertionPoints = new ArrayList<>(List.of(outcome.point()));
                profile.extractor = outcome.extractor();
                profile.measuredLatencyMs = outcome.latencyMs();
                context.runConfig().applyAutoThrottle(outcome.latencyMs());
                context.saveRunConfig();
            }
            profile.checkedConfidence = outcome.confidence().name();
            profile.checkedSummary = outcome.headline();
            profile.checkedAt = System.currentTimeMillis();
            // A fresh check invalidates any earlier quick test: the rules may have changed.
            if (!outcome.proven()) {
                profile.smokeTestedAt = 0;
            }
            context.profileEdited();

            log(outcome.headline() + "  (" + outcome.requestsUsed() + " requests)");
            outcome.notes().forEach(note -> log("  " + note));
            if (!outcome.sampleReply().isBlank()) {
                log("  the endpoint replied: \"" + Ui.ellipsis(outcome.sampleReply(), 160) + "\"");
            }

            checking = false;
            Ui.onEdt(() -> {
                refresh();
                if (!outcome.usable()) {
                    JOptionPane.showMessageDialog(this,
                            outcome.headline() + "\n\n" + String.join("\n", outcome.notes()),
                            "Check failed", JOptionPane.WARNING_MESSAGE);
                }
            });
        }, "garak-check");
        worker.setDaemon(true);
        worker.start();
    }

    /** The insertion rule already chosen, then the analyser's other guesses as fallbacks. */
    private List<InsertionPoint> candidatesFor(TargetProfile profile) {
        List<InsertionPoint> candidates = new ArrayList<>(profile.insertionPoints);
        for (RequestAnalyzer.Candidate candidate : RequestAnalyzer.detect(profile.request())) {
            if (candidate.score() <= 0) {
                continue;
            }
            boolean known = candidates.stream().anyMatch(existing ->
                    existing.kind == candidate.point().kind
                            && existing.locator.equals(candidate.point().locator));
            if (!known) {
                candidates.add(candidate.point());
            }
        }
        return candidates;
    }

    // ------------------------------------------------------------ steps 3 and 4: scan

    private void runScan(boolean smoke) {
        Optional<TargetProfile> active = context.active();
        Optional<GarakLocator.Installation> installation = context.installation();
        if (active.isEmpty() || installation.isEmpty()) {
            return;
        }
        TargetProfile profile = active.get();

        RunConfig config = context.runConfig().copy();
        if (smoke) {
            ScanDepth.SMOKE.applyTo(config);
            config.probes = smokeProbes();
            config.createAuditIssues = false; // a smoke run is not a finding worth filing
        } else {
            selectedDepth().applyTo(config);
            config.probes = new ArrayList<>(context.runConfig().probes);
            if (!confirmFullScan(profile, config)) {
                return;
            }
        }
        if (config.probes.isEmpty()) {
            JOptionPane.showMessageDialog(this,
                    "No probes selected. Pick something under \"Test for\".");
            return;
        }

        lastRunWasSmoke = smoke;
        activity.setText("");
        progress.setIndeterminate(true);
        context.controller().start(profile, config, installation.get(),
                context.settings(), context.catalogue());
        refresh();
    }

    /**
     * The quick test always includes a trivial probe to prove the plumbing, plus a couple
     * of the probes the full scan will actually use, so it is a preview and not a
     * different exercise.
     */
    private List<String> smokeProbes() {
        List<String> probes = new ArrayList<>();
        if (context.catalogue().byName(PLUMBING_PROBE).isPresent()) {
            probes.add(PLUMBING_PROBE);
        }
        for (String probe : context.runConfig().probes) {
            if (probes.size() >= SMOKE_SAMPLE_PROBES + 1) {
                break;
            }
            if (!probes.contains(probe)) {
                probes.add(probe);
            }
        }
        if (probes.isEmpty()) {
            probes.addAll(context.catalogue().probes().stream()
                    .filter(PluginCatalog.Probe::isReadyToRun)
                    .limit(2)
                    .map(PluginCatalog.Probe::name)
                    .toList());
        }
        return probes;
    }

    private boolean confirmFullScan(TargetProfile profile, RunConfig config) {
        String message = String.format(
                "Send up to %,d adversarial prompts to %s?%n%n"
                        + "Probes: %d · depth %s%n"
                        + "%d at a time, %d ms apart%n"
                        + "Estimated time: %s%n%n"
                        + "Every request goes through Burp and will appear in your history.",
                config.estimatedRequests(), profile.baseUrl(), config.probes.size(),
                selectedDepth().label, config.maxConcurrent, config.delayMs,
                humanDuration(config.estimatedSeconds()));
        return JOptionPane.showConfirmDialog(this, message, "Start full scan",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE)
                == JOptionPane.OK_OPTION;
    }

    // ------------------------------------------------------------------- presets

    /** Rebuilds the preset list; called when the probe catalogue is (re)loaded. */
    public void reloadPresets() {
        Ui.onEdt(() -> {
            populating = true;
            try {
                presets = PluginCatalog.presets();
                DefaultComboBoxModel<String> model = new DefaultComboBoxModel<>();
                presets.forEach(preset -> model.addElement(preset.name()));
                model.addElement("Custom selection…");
                presetChooser.setModel(model);

                // Default to prompt injection: the highest-value general starting point.
                int recommended = 1;
                if (presets.size() > recommended) {
                    presetChooser.setSelectedIndex(recommended);
                }
            } finally {
                populating = false;
            }
            if (context.runConfig().probes.isEmpty()) {
                applyPreset();
            }
            updateEstimate();
        });
    }

    private void applyPreset() {
        int index = presetChooser.getSelectedIndex();
        if (index < 0 || index >= presets.size()) {
            return; // "Custom selection…": leave whatever the Probes tab holds
        }
        List<String> resolved = context.catalogue().resolve(presets.get(index));
        if (!resolved.isEmpty()) {
            context.runConfig().probes = new ArrayList<>(resolved);
            context.saveRunConfig();
        }
        updateEstimate();
    }

    private void applyDepth() {
        selectedDepth().applyTo(context.runConfig());
        context.saveRunConfig();
        updateEstimate();
    }

    private ScanDepth selectedDepth() {
        Object selected = depthChooser.getSelectedItem();
        return selected instanceof ScanDepth depth ? depth : ScanDepth.STANDARD;
    }

    private void updateEstimate() {
        RunConfig config = context.runConfig().copy();
        selectedDepth().applyTo(config);
        if (config.probes.isEmpty()) {
            estimate.setText("no probes selected");
            return;
        }
        estimate.setText(String.format("%d probes · up to %,d requests · about %s",
                config.probes.size(), config.estimatedRequests(),
                humanDuration(config.estimatedSeconds())));
    }

    private static String humanDuration(long seconds) {
        if (seconds < 90) {
            return seconds + " seconds";
        }
        if (seconds < 5400) {
            return (seconds / 60) + " minutes";
        }
        return String.format("%.1f hours", seconds / 3600.0);
    }

    // ----------------------------------------------------------------- callbacks

    @Override
    public void onProfilesChanged() {
        Ui.onEdt(() -> {
            populating = true;
            try {
                DefaultComboBoxModel<TargetProfile> model = new DefaultComboBoxModel<>();
                context.profiles().forEach(model::addElement);
                targetChooser.setModel(model);
                context.active().ifPresent(targetChooser::setSelectedItem);
            } finally {
                populating = false;
            }
            refresh();
        });
    }

    @Override
    public void onState(RunController.State state, String message) {
        if (state == RunController.State.FINISHED || state == RunController.State.FAILED) {
            Ui.onEdt(() -> {
                progress.setIndeterminate(false);
                recordRunOutcome(state, message);
                refresh();
            });
        } else {
            refresh();
        }
    }

    private void recordRunOutcome(RunController.State state, String message) {
        Optional<TargetProfile> active = context.active();
        if (active.isEmpty()) {
            return;
        }
        TargetProfile profile = active.get();
        int findings = context.controller().findings().size();

        if (lastRunWasSmoke) {
            if (state == RunController.State.FINISHED) {
                profile.smokeTestedAt = System.currentTimeMillis();
                profile.smokeSummary = findings == 0
                        ? "Passed — garak ran end to end, nothing flagged at this size"
                        : "Passed — " + findings + " finding"
                                + (findings == 1 ? "" : "s") + " already";
                context.profileEdited();
                log("Quick test passed. " + (findings > 0
                        ? "It already found something; a full scan will find more."
                        : "Nothing flagged yet, which is expected at this size."));
            } else {
                log("Quick test did not complete: " + message);
            }
        } else if (state == RunController.State.FINISHED) {
            log("Full scan complete: " + message);
        }
    }

    @Override
    public void onLog(String line) {
        log(line);
    }

    @Override
    public void onProgress(RunController.Progress update) {
        Ui.onEdt(() -> {
            if (update.probesTotal() > 0) {
                progress.setIndeterminate(false);
                progress.setMaximum(update.probesTotal());
                progress.setValue(Math.min(update.probesDone(), update.probesTotal()));
                progress.setString(update.probesDone() + " / " + update.probesTotal() + " probes");
            }
            counters.setText(update.promptsSent() + " requests · "
                    + update.findings() + " findings");
        });
    }

    @Override
    public void onFinding(Finding finding) {
        // Rendered by ResultsPanel, which is embedded in this panel's Findings tab.
    }

    private void log(String line) {
        Ui.onEdt(() -> {
            activity.append(line + "\n");
            activity.setCaretPosition(activity.getDocument().getLength());
        });
    }

    /** Keeps the checkbox in step with the tab state when it is changed elsewhere. */
    public void setAdvancedSelected(boolean selected) {
        Ui.onEdt(() -> advanced.setSelected(selected));
    }

    // ---------------------------------------------------------------- step widget

    /** One numbered step: a state marker, a headline, and a line of detail. */
    private static final class StepRow extends JPanel {

        enum State { WAITING, NEXT, RUNNING, DONE, WARN, PROBLEM }

        private final JLabel marker = new JLabel();
        private final JLabel title;
        private final JLabel headline = new JLabel();
        private final JLabel detail = Ui.hint(" ");

        StepRow(String number, String name) {
            super(new BorderLayout(6, 0));
            setBorder(BorderFactory.createEmptyBorder(3, 0, 3, 0));
            setAlignmentX(Component.LEFT_ALIGNMENT);

            marker.setPreferredSize(new Dimension(18, 16));
            title = Ui.bold(number + " · " + name);

            JPanel left = Ui.row(marker, title);
            JPanel right = new JPanel();
            right.setLayout(new BoxLayout(right, BoxLayout.Y_AXIS));
            right.add(headline);
            right.add(detail);

            add(left, BorderLayout.WEST);
            add(right, BorderLayout.CENTER);
        }

        void set(State state, String headlineText, String detailText) {
            marker.setText(switch (state) {
                case DONE -> "✓";
                case WARN -> "!";
                case PROBLEM -> "✕";
                case RUNNING -> "…";
                case NEXT -> "▸";
                case WAITING -> "·";
            });
            headline.setText(headlineText == null ? "" : headlineText);
            detail.setText(detailText == null || detailText.isEmpty() ? " " : detailText);

            // Steps not yet reachable recede rather than disappear, so the shape of the
            // whole process stays visible from the first screen.
            float alpha = state == State.WAITING ? 0.45f : 1f;
            title.setEnabled(alpha == 1f);
            headline.setEnabled(alpha == 1f);
            detail.setEnabled(alpha == 1f);
        }
    }
}
