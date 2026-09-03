// Copyright 2026 the garak Bridge authors
// SPDX-License-Identifier: Apache-2.0

package burp.garak.ui;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import burp.garak.GarakContext;
import burp.garak.garakproc.RunController;
import burp.garak.issues.AuditIssueFactory;
import burp.garak.model.Exchange;
import burp.garak.model.Finding;
import burp.garak.model.TargetProfile;

import javax.swing.BorderFactory;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.RowFilter;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.BorderLayout;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * Findings, each one openable as the request and response that produced it.
 *
 * <p>This is the point of running garak from inside Burp rather than beside it: a detector
 * hit is not a line in a JSON file, it is an HTTP exchange that can be inspected, sent to
 * Repeater, and reproduced by hand.
 */
public final class ResultsPanel extends JPanel implements RunController.Listener {

    private final GarakContext context;

    private final FindingsModel model = new FindingsModel();
    private final JTable table = new JTable(model);
    private final TableRowSorter<FindingsModel> sorter = new TableRowSorter<>(model);

    private final JTextField filter = new JTextField(20);
    private final JCheckBox onlyWithTraffic = new JCheckBox("Only findings with traffic");
    private final JLabel summary = Ui.hint("No findings yet.");

    private final JTextArea promptView = Ui.monospace(8, 80);
    private final JTextArea outputView = Ui.monospace(8, 80);
    private final HttpRequestEditor requestEditor;
    private final HttpResponseEditor responseEditor;

    public ResultsPanel(GarakContext context) {
        super(new BorderLayout(6, 6));
        this.context = context;

        requestEditor = context.api().userInterface()
                .createHttpRequestEditor(EditorOptions.READ_ONLY);
        responseEditor = context.api().userInterface()
                .createHttpResponseEditor(EditorOptions.READ_ONLY);

        add(toolbar(), BorderLayout.NORTH);
        add(split(), BorderLayout.CENTER);

        context.controller().addListener(this);
    }

    // ------------------------------------------------------------------- layout

    private JPanel toolbar() {
        filter.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent event) {
                applyFilter();
            }

            @Override
            public void removeUpdate(DocumentEvent event) {
                applyFilter();
            }

            @Override
            public void changedUpdate(DocumentEvent event) {
                applyFilter();
            }
        });
        onlyWithTraffic.addActionListener(event -> applyFilter());

        JPanel panel = Ui.row(
                Ui.label("Filter:"), filter, onlyWithTraffic,
                Ui.gap(12),
                Ui.button("Send to Burp Issues", event -> pushIssues()),
                Ui.button("Export CSV", event -> exportCsv()),
                Ui.button("Clear", event -> clear()));
        panel.add(Ui.gap(12));
        panel.add(summary);
        return panel;
    }

    private JSplitPane split() {
        table.setRowSorter(sorter);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
        table.setFillsViewportHeight(true);
        table.getSelectionModel().addListSelectionListener(event -> {
            if (!event.getValueIsAdjusting()) {
                showSelected();
            }
        });
        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent event) {
                maybePopup(event);
            }

            @Override
            public void mouseReleased(MouseEvent event) {
                maybePopup(event);
            }
        });

        table.getColumnModel().getColumn(0).setPreferredWidth(170);
        table.getColumnModel().getColumn(1).setPreferredWidth(140);
        table.getColumnModel().getColumn(2).setPreferredWidth(40);
        table.getColumnModel().getColumn(3).setPreferredWidth(50);
        table.getColumnModel().getColumn(4).setPreferredWidth(260);
        table.getColumnModel().getColumn(5).setPreferredWidth(300);
        table.getColumnModel().getColumn(6).setPreferredWidth(60);

        promptView.setEditable(false);
        outputView.setEditable(false);

        JTabbedPane detail = new JTabbedPane();
        detail.addTab("Prompt", new JScrollPane(promptView));
        detail.addTab("Model reply", new JScrollPane(outputView));
        detail.addTab("Request", requestEditor.uiComponent());
        detail.addTab("Response", responseEditor.uiComponent());
        detail.setSelectedIndex(1);

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                new JScrollPane(table), detail);
        split.setResizeWeight(0.45);
        split.setBorder(BorderFactory.createEmptyBorder());
        return split;
    }

    private void maybePopup(MouseEvent event) {
        if (!event.isPopupTrigger()) {
            return;
        }
        int row = table.rowAtPoint(event.getPoint());
        if (row < 0) {
            return;
        }
        table.setRowSelectionInterval(row, row);
        Optional<Finding> finding = selectedFinding();
        if (finding.isEmpty()) {
            return;
        }

        JPopupMenu menu = new JPopupMenu();
        JMenuItem repeater = new JMenuItem("Send request to Repeater");
        repeater.addActionListener(action -> sendToRepeater(finding.get()));
        repeater.setEnabled(exchangeFor(finding.get()).filter(Exchange::hasTraffic).isPresent());
        menu.add(repeater);

        JMenuItem copyPrompt = new JMenuItem("Copy prompt");
        copyPrompt.addActionListener(action -> copy(finding.get().prompt));
        menu.add(copyPrompt);

        JMenuItem copyOutput = new JMenuItem("Copy model reply");
        copyOutput.addActionListener(action -> copy(finding.get().output));
        menu.add(copyOutput);

        menu.show(table, event.getX(), event.getY());
    }

    // ------------------------------------------------------------------ actions

    private void showSelected() {
        Optional<Finding> selected = selectedFinding();
        if (selected.isEmpty()) {
            promptView.setText("");
            outputView.setText("");
            return;
        }
        Finding finding = selected.get();
        promptView.setText(finding.prompt);
        promptView.setCaretPosition(0);
        outputView.setText(finding.output);
        outputView.setCaretPosition(0);

        Optional<Exchange> exchange = exchangeFor(finding);
        if (exchange.isPresent() && exchange.get().hasTraffic()) {
            HttpRequestResponse traffic = exchange.get().requestResponse;
            requestEditor.setRequest(traffic.request());
            responseEditor.setResponse(traffic.response() == null
                    ? HttpResponse.httpResponse("") : traffic.response());
        } else {
            requestEditor.setRequest(HttpRequest.httpRequest(
                    "The HTTP exchange for this finding is no longer in memory.\r\n"
                            + "Traffic is kept for the current run only.\r\n"));
            responseEditor.setResponse(HttpResponse.httpResponse(""));
        }
    }

    private void sendToRepeater(Finding finding) {
        exchangeFor(finding).filter(Exchange::hasTraffic).ifPresent(exchange -> {
            String name = "garak " + shortProbe(finding.probe);
            context.api().repeater().sendToRepeater(exchange.requestResponse.request(), name);
        });
    }

    private void pushIssues() {
        List<Finding> findings = model.findings;
        if (findings.isEmpty()) {
            JOptionPane.showMessageDialog(this, "There are no findings to publish.");
            return;
        }
        Optional<TargetProfile> profile = context.active();
        if (profile.isEmpty()) {
            return;
        }
        if (!AuditIssueFactory.isSupported(context.api())) {
            JOptionPane.showMessageDialog(this,
                    "This Burp edition has no Issues view, so findings stay in this tab.\n"
                            + "Use Export CSV, or open garak's own HTML report from the Run tab.",
                    "Issues not available", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        int published = AuditIssueFactory.publish(context.api(), profile.get(), findings,
                context.store());
        JOptionPane.showMessageDialog(this, published
                + " issue(s) added to the site map for " + profile.get().baseUrl());
    }

    private void exportCsv() {
        if (model.findings.isEmpty()) {
            JOptionPane.showMessageDialog(this, "There are no findings to export.");
            return;
        }
        Path directory = context.controller().reportDirectory()
                .orElse(context.settings().resolveRunsDirectory());
        Path file = directory.resolve("findings.csv");
        try {
            Files.createDirectories(directory);
            StringBuilder csv = new StringBuilder(
                    "probe,detector,tier,score,goal,tags,prompt,output\n");
            for (Finding finding : model.findings) {
                csv.append(cell(finding.probe)).append(',')
                        .append(cell(finding.detector)).append(',')
                        .append(finding.tier).append(',')
                        .append(finding.score).append(',')
                        .append(cell(finding.goal)).append(',')
                        .append(cell(finding.tags)).append(',')
                        .append(cell(finding.prompt)).append(',')
                        .append(cell(finding.output)).append('\n');
            }
            Files.writeString(file, csv.toString(), StandardCharsets.UTF_8);
            JOptionPane.showMessageDialog(this, "Written to " + file);
        } catch (IOException e) {
            JOptionPane.showMessageDialog(this, "Could not write the CSV: " + e.getMessage(),
                    "Export failed", JOptionPane.ERROR_MESSAGE);
        }
    }

    /** RFC 4180 quoting: wrap in quotes, double any quote inside. */
    private static String cell(String value) {
        String text = value == null ? "" : value;
        return '"' + text.replace("\"", "\"\"") + '"';
    }

    private void clear() {
        model.clear();
        promptView.setText("");
        outputView.setText("");
        updateSummary();
    }

    private void copy(String text) {
        Toolkit.getDefaultToolkit().getSystemClipboard()
                .setContents(new StringSelection(text == null ? "" : text), null);
    }

    private void applyFilter() {
        String needle = filter.getText().trim().toLowerCase(Locale.ROOT);
        sorter.setRowFilter(new RowFilter<>() {
            @Override
            public boolean include(Entry<? extends FindingsModel, ? extends Integer> entry) {
                Finding finding = model.findings.get(entry.getIdentifier());
                if (onlyWithTraffic.isSelected()
                        && exchangeFor(finding).filter(Exchange::hasTraffic).isEmpty()) {
                    return false;
                }
                if (needle.isEmpty()) {
                    return true;
                }
                return (finding.probe + " " + finding.detector + " " + finding.goal + " "
                        + finding.tags + " " + finding.prompt + " " + finding.output)
                        .toLowerCase(Locale.ROOT).contains(needle);
            }
        });
        updateSummary();
    }

    private Optional<Finding> selectedFinding() {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) {
            return Optional.empty();
        }
        int modelRow = table.convertRowIndexToModel(viewRow);
        return modelRow < 0 || modelRow >= model.findings.size()
                ? Optional.empty() : Optional.of(model.findings.get(modelRow));
    }

    private Optional<Exchange> exchangeFor(Finding finding) {
        if (finding.exchangeId >= 0) {
            Optional<Exchange> byId = context.store().byId(finding.exchangeId);
            if (byId.isPresent()) {
                return byId;
            }
        }
        return context.store().find(finding.prompt, finding.attemptIdx);
    }

    private void updateSummary() {
        int total = model.findings.size();
        int shown = table.getRowCount();
        long withTraffic = model.findings.stream()
                .filter(finding -> exchangeFor(finding).filter(Exchange::hasTraffic).isPresent())
                .count();
        summary.setText(total == 0
                ? "No findings yet."
                : shown + " shown of " + total + " findings · " + withTraffic
                        + " linked to captured traffic");
    }

    private static String shortProbe(String probe) {
        return probe.startsWith("probes.") ? probe.substring("probes.".length()) : probe;
    }

    // -------------------------------------------------------- controller callbacks

    @Override
    public void onState(RunController.State state, String message) {
        if (state == RunController.State.STARTING) {
            Ui.onEdt(this::clear);
        }
    }

    @Override
    public void onLog(String line) {
        // The run log lives on the Run tab.
    }

    @Override
    public void onProgress(RunController.Progress progress) {
        // Counters live on the Run tab.
    }

    @Override
    public void onFinding(Finding finding) {
        Ui.onEdt(() -> {
            model.add(finding);
            if (table.getSelectedRow() < 0 && table.getRowCount() > 0) {
                table.setRowSelectionInterval(0, 0);
            }
            updateSummary();
        });
    }

    // ---------------------------------------------------------------- table model

    private final class FindingsModel extends AbstractTableModel {

        private final String[] columns =
                {"Probe", "Detector", "Tier", "Score", "Goal", "Model reply", "Traffic"};
        private final List<Finding> findings = new ArrayList<>();

        void add(Finding finding) {
            findings.add(finding);
            fireTableRowsInserted(findings.size() - 1, findings.size() - 1);
        }

        void clear() {
            int size = findings.size();
            findings.clear();
            if (size > 0) {
                fireTableRowsDeleted(0, size - 1);
            }
        }

        @Override
        public int getRowCount() {
            return findings.size();
        }

        @Override
        public int getColumnCount() {
            return columns.length;
        }

        @Override
        public String getColumnName(int column) {
            return columns[column];
        }

        @Override
        public Object getValueAt(int row, int column) {
            Finding finding = findings.get(row);
            return switch (column) {
                case 0 -> shortProbe(finding.probe);
                case 1 -> finding.detector;
                case 2 -> finding.tier > 0 ? String.valueOf(finding.tier) : "";
                case 3 -> String.format("%.2f", finding.score);
                case 4 -> Ui.ellipsis(finding.goal, 90);
                case 5 -> finding.outputSummary(120);
                default -> exchangeFor(finding).filter(Exchange::hasTraffic).isPresent()
                        ? "yes" : "";
            };
        }
    }
}
