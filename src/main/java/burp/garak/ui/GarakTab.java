// Copyright 2026 the garak Bridge authors
// SPDX-License-Identifier: Apache-2.0

package burp.garak.ui;

import burp.garak.GarakContext;
import burp.garak.garakproc.RunController;
import burp.garak.model.Finding;

import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import java.awt.BorderLayout;
import java.awt.Component;

/**
 * The extension's suite tab.
 *
 * <p>One tab by default -- Scan -- which runs the whole job. The panels that expose the
 * individual knobs are still here and still authoritative; they are just kept out of the
 * way until asked for, because the common case needs none of them.
 */
public final class GarakTab extends JPanel implements RunController.Listener {

    private final JTabbedPane tabs = new JTabbedPane();
    private final ScanPanel scanPanel;
    private final TargetPanel targetPanel;
    private final ProbePanel probePanel;
    private final RunPanel runPanel;
    private final ResultsPanel resultsPanel;
    private final SettingsPanel settingsPanel;

    private boolean advancedShown;

    public GarakTab(GarakContext context) {
        super(new BorderLayout());

        resultsPanel = new ResultsPanel(context);
        targetPanel = new TargetPanel(context);
        probePanel = new ProbePanel(context);
        runPanel = new RunPanel(context);
        settingsPanel = new SettingsPanel(context, ignored -> reloadCatalogue());
        scanPanel = new ScanPanel(context, resultsPanel, this::setAdvancedShown,
                this::showSettings);

        tabs.addTab("Scan", scanPanel);
        add(tabs, BorderLayout.CENTER);

        context.controller().addListener(this);
        probePanel.reload();
    }

    /**
     * Adds or removes the detail tabs.
     *
     * <p>The results table lives inside the Scan tab and Swing components have one parent,
     * so the advanced view deliberately does not duplicate it: findings stay in one place
     * whichever mode is showing.
     */
    private void setAdvancedShown(boolean shown) {
        if (shown == advancedShown) {
            return;
        }
        advancedShown = shown;
        if (shown) {
            tabs.addTab("Target", targetPanel);
            tabs.addTab("Probes", probePanel);
            tabs.addTab("Run settings", runPanel);
            tabs.addTab("Settings", settingsPanel);
        } else {
            for (int i = tabs.getTabCount() - 1; i >= 1; i--) {
                tabs.removeTabAt(i);
            }
            tabs.setSelectedIndex(0);
        }
        scanPanel.setAdvancedSelected(shown);
    }

    /** Opens the settings tab, for the "garak not found" path. */
    public void showSettings() {
        Ui.onEdt(() -> {
            setAdvancedShown(true);
            tabs.setSelectedComponent(settingsPanel);
        });
    }

    /** Brings a freshly captured target to the front, so the capture visibly landed. */
    public void showTarget() {
        Ui.onEdt(() -> {
            tabs.setSelectedIndex(0);
            scanPanel.refresh();
        });
    }

    public Component settingsComponent() {
        return settingsPanel;
    }

    /** Reloads the probe list and presets after garak is (re)detected. */
    public void reloadCatalogue() {
        Ui.onEdt(() -> {
            probePanel.reload();
            scanPanel.reloadPresets();
            scanPanel.refresh();
        });
    }

    @Override
    public void onState(RunController.State state, String message) {
        // Progress is shown on the Scan tab, which is always visible.
    }

    @Override
    public void onLog(String line) {
        // Handled by ScanPanel and RunPanel.
    }

    @Override
    public void onProgress(RunController.Progress progress) {
        // Handled by ScanPanel and RunPanel.
    }

    @Override
    public void onFinding(Finding finding) {
        // Handled by ResultsPanel.
    }
}
