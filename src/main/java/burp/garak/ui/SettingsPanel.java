// Copyright 2026 the garak Bridge authors
// SPDX-License-Identifier: Apache-2.0

package burp.garak.ui;

import burp.garak.GarakContext;
import burp.garak.model.Settings;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSpinner;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SpinnerNumberModel;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.io.IOException;
import java.util.function.Consumer;

/** Where garak lives, where runs are written, and how the bridge is exposed. */
public final class SettingsPanel extends JPanel {

    private final GarakContext context;
    private final Consumer<Void> onCatalogueChanged;

    private final JTextField garakPath = new JTextField(46);
    private final JTextField runsDirectory = new JTextField(46);
    private final JSpinner bridgePort =
            new JSpinner(new SpinnerNumberModel(0, 0, 65535, 1));
    private final JSpinner proxyPort =
            new JSpinner(new SpinnerNumberModel(8080, 1, 65535, 1));
    private final JCheckBox keepRuns = new JCheckBox("Keep run folders after the run finishes", true);

    private final JButton detectButton = new JButton("Detect garak");
    private final JTextArea installationReport = Ui.monospace(10, 80);
    private final JLabel bridgeStatus = Ui.hint("Bridge: stopped");

    public SettingsPanel(GarakContext context, Consumer<Void> onCatalogueChanged) {
        super(new BorderLayout(6, 6));
        this.context = context;
        this.onCatalogueChanged = onCatalogueChanged;

        add(form(), BorderLayout.NORTH);
        add(report(), BorderLayout.CENTER);

        load();
    }

    private JPanel form() {
        detectButton.addActionListener(event -> detect());

        JPanel garakRow = Ui.row(
                Ui.label("garak path:"), garakPath,
                Ui.button("Browse…", event -> browse(garakPath, JFileChooser.FILES_ONLY)),
                detectButton);

        JPanel runsRow = Ui.row(
                Ui.label("Runs folder:"), runsDirectory,
                Ui.button("Browse…", event -> browse(runsDirectory, JFileChooser.DIRECTORIES_ONLY)),
                keepRuns);

        JPanel portsRow = Ui.row(
                Ui.label("Bridge port (0 = pick one):"), bridgePort,
                Ui.button("Start bridge", event -> startBridge()),
                Ui.button("Stop bridge", event -> stopBridge()),
                Ui.gap(10), bridgeStatus);

        JPanel proxyRow = Ui.row(
                Ui.label("Burp proxy port (for standalone config export):"), proxyPort);

        JPanel panel = new JPanel();
        panel.setLayout(new javax.swing.BoxLayout(panel, javax.swing.BoxLayout.Y_AXIS));
        panel.add(Ui.hint("Point this at a garak executable, or at the Python interpreter of "
                + "the environment garak is installed in (it will be run as 'python -m garak'). "
                + "Leave blank to use garak from PATH."));
        panel.add(garakRow);
        panel.add(runsRow);
        panel.add(portsRow);
        panel.add(proxyRow);
        panel.add(Ui.row(Ui.button("Save settings", event -> save())));

        for (JTextField field : new JTextField[]{garakPath, runsDirectory}) {
            field.addActionListener(event -> save());
        }
        return panel;
    }

    private JScrollPane report() {
        installationReport.setEditable(false);
        JScrollPane scroll = new JScrollPane(installationReport);
        scroll.setBorder(BorderFactory.createTitledBorder("garak installation"));
        scroll.setPreferredSize(new Dimension(600, 240));
        return scroll;
    }

    // -------------------------------------------------------------------- state

    private void load() {
        Settings settings = context.settings();
        garakPath.setText(settings.garakPath);
        runsDirectory.setText(settings.runsDirectory);
        bridgePort.setValue(settings.bridgePort);
        proxyPort.setValue(settings.burpProxyPort);
        keepRuns.setSelected(settings.keepRunDirectories);
        updateBridgeStatus();
        renderInstallation();
    }

    private void save() {
        Settings settings = context.settings();
        settings.garakPath = garakPath.getText().trim();
        settings.runsDirectory = runsDirectory.getText().trim();
        settings.bridgePort = (Integer) bridgePort.getValue();
        settings.burpProxyPort = (Integer) proxyPort.getValue();
        settings.keepRunDirectories = keepRuns.isSelected();
        context.saveSettings();
    }

    /**
     * Probes the configured path off the UI thread: garak's startup imports torch and can
     * take the better part of a minute the first time.
     */
    private void detect() {
        save();
        detectButton.setEnabled(false);
        installationReport.setText("Running 'garak --version'…\n"
                + "This can take a while on a cold start; garak imports torch and transformers.");

        Thread worker = new Thread(() -> {
            context.refreshInstallation();
            Ui.onEdt(() -> {
                detectButton.setEnabled(true);
                renderInstallation();
                onCatalogueChanged.accept(null);
            });
        }, "garak-detect");
        worker.setDaemon(true);
        worker.start();
    }

    private void renderInstallation() {
        StringBuilder text = new StringBuilder();
        context.installation().ifPresentOrElse(installation -> {
            if (installation.isUsable()) {
                text.append("Found garak ").append(installation.version()).append('\n');
                text.append("Command:     ").append(String.join(" ", installation.command())).append('\n');
                if (!installation.interpreter().isEmpty()) {
                    text.append("Interpreter: ").append(installation.interpreter()).append('\n');
                }
                if (installation.packageDir() != null) {
                    text.append("Package:     ").append(installation.packageDir()).append('\n');
                }
                text.append("Probe list:  ").append(context.catalogue().probes().size())
                        .append(" probes from ").append(context.catalogue().source()).append('\n');
                text.append("Flags:       ")
                        .append(installation.supportsTargetType() ? "--target_type" : "--model_type")
                        .append(", ")
                        .append(installation.supportsSpec() ? "--spec" : "--probes")
                        .append('\n');
            } else {
                text.append("garak was not found.\n");
            }
            if (!installation.problems().isEmpty()) {
                text.append('\n');
                installation.problems().forEach(problem ->
                        text.append("• ").append(problem).append('\n'));
            }
            if (!installation.banner().isEmpty()) {
                text.append("\n--- garak --version ---\n").append(installation.banner()).append('\n');
            }
        }, () -> text.append("Not checked yet. Press \"Detect garak\".\n\n")
                .append("garak needs Python 3.11 or newer and pulls in torch and transformers, "
                        + "so a fresh install is several gigabytes:\n\n")
                .append("    uv venv --python 3.12 ~/.garak-venv\n")
                .append("    ~/.garak-venv/bin/python -m pip install garak\n\n")
                .append("Then set the path above to ~/.garak-venv/bin/garak\n"));

        installationReport.setText(text.toString());
        installationReport.setCaretPosition(0);
    }

    // ------------------------------------------------------------------- bridge

    private void startBridge() {
        save();
        try {
            context.bridge().start(context.settings().bridgePort, 12);
        } catch (IOException e) {
            installationReport.setText("Could not start the bridge: " + e.getMessage()
                    + "\n\nIf a port is set explicitly, something else may already be using it. "
                    + "Set the port to 0 to let the OS pick a free one.");
        }
        updateBridgeStatus();
    }

    private void stopBridge() {
        if (context.controller().isBusy()) {
            installationReport.setText("A run is in progress; stop it before stopping the bridge.");
            return;
        }
        context.bridge().stop();
        updateBridgeStatus();
    }

    void updateBridgeStatus() {
        bridgeStatus.setText(context.bridge().isRunning()
                ? "Bridge: listening on " + context.bridge().endpoint()
                : "Bridge: stopped (it starts automatically when a scan begins)");
    }

    private void browse(JTextField target, int mode) {
        JFileChooser chooser = new JFileChooser();
        chooser.setFileSelectionMode(mode);
        if (!target.getText().isBlank()) {
            chooser.setSelectedFile(new java.io.File(target.getText()));
        }
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            target.setText(chooser.getSelectedFile().getAbsolutePath());
            save();
        }
    }
}
