// Copyright 2026 the garak Bridge authors
// SPDX-License-Identifier: Apache-2.0

package burp.garak.ui;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import burp.garak.GarakContext;
import burp.garak.bridge.ExchangeRunner;
import burp.garak.bridge.Extractors;
import burp.garak.capture.RequestAnalyzer;
import burp.garak.capture.ResponseAnalyzer;
import burp.garak.model.Exchange;
import burp.garak.model.InsertionPoint;
import burp.garak.model.ResponseExtractor;
import burp.garak.model.TargetProfile;

import javax.swing.BorderFactory;
import javax.swing.DefaultComboBoxModel;
import javax.swing.DefaultListModel;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.util.List;
import java.util.Optional;

/**
 * Where a captured chat exchange becomes a runnable target: mark where the prompt goes in,
 * mark where the reply comes out, and prove it works before spending a scan on it.
 */
public final class TargetPanel extends JPanel implements GarakContext.ProfileListener {

    private final GarakContext context;

    private final JComboBox<TargetProfile> profileChooser = new JComboBox<>();
    private final HttpRequestEditor requestEditor;
    private final HttpResponseEditor responseEditor;

    private final DefaultListModel<InsertionPoint> insertionModel = new DefaultListModel<>();
    private final JList<InsertionPoint> insertionList = new JList<>(insertionModel);

    private final JComboBox<ResponseExtractor.Mode> extractorMode =
            new JComboBox<>(ResponseExtractor.Mode.values());
    private final JTextField extractorExpression = new JTextField(28);
    private final JTextField streamTerminator = new JTextField(8);

    private final JTextArea testOutput = Ui.monospace(8, 60);
    private final JLabel status = Ui.hint(" ");

    /** Set while loading a profile, so field listeners do not write back mid-populate. */
    private boolean populating;

    public TargetPanel(GarakContext context) {
        super(new BorderLayout(6, 6));
        this.context = context;

        requestEditor = context.api().userInterface()
                .createHttpRequestEditor(EditorOptions.READ_ONLY);
        responseEditor = context.api().userInterface()
                .createHttpResponseEditor(EditorOptions.READ_ONLY);

        add(header(), BorderLayout.NORTH);
        add(body(), BorderLayout.CENTER);
        add(footer(), BorderLayout.SOUTH);

        context.addProfileListener(this);
        onProfilesChanged();
    }

    // ------------------------------------------------------------------- layout

    private JComponent header() {
        profileChooser.addActionListener(event -> {
            if (populating) {
                return;
            }
            Object selected = profileChooser.getSelectedItem();
            if (selected instanceof TargetProfile profile) {
                context.setActive(profile);
            }
        });

        JPanel panel = Ui.row(
                Ui.bold("Target:"),
                profileChooser,
                Ui.button("Rename", event -> rename()),
                Ui.button("Duplicate", event -> duplicate()),
                Ui.button("Delete", event -> delete()),
                Ui.gap(16),
                Ui.button("Detect prompt & reply", event -> autoDetect()));
        panel.add(Ui.hint("Right-click any chat request in Burp → \"Send chat request to garak\""));
        return panel;
    }

    private JComponent body() {
        JTabbedPane messages = new JTabbedPane();
        messages.addTab("Request", requestEditor.uiComponent());
        messages.addTab("Response", responseEditor.uiComponent());

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, messages, configuration());
        split.setResizeWeight(0.55);
        split.setBorder(BorderFactory.createEmptyBorder());
        return split;
    }

    private JComponent configuration() {
        JPanel panel = new JPanel();
        panel.setLayout(new javax.swing.BoxLayout(panel, javax.swing.BoxLayout.Y_AXIS));

        panel.add(insertionSection());
        panel.add(Ui.vgap(6));
        panel.add(extractorSection());
        panel.add(Ui.vgap(6));
        panel.add(Ui.titled("Verify", testSection()));

        return Ui.scroll(panel);
    }

    private JComponent insertionSection() {
        insertionList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        insertionList.setVisibleRowCount(4);

        JPanel buttons = Ui.row(
                Ui.button("Mark selection as prompt", event -> markSelectionAsPrompt()),
                Ui.button("Remove", event -> removeInsertionPoint()),
                Ui.button("Wrap…", event -> editWrapping()));

        JPanel content = new JPanel(new BorderLayout(4, 4));
        content.add(Ui.hint("Select the message text in the Request tab, then mark it."),
                BorderLayout.NORTH);
        content.add(new JScrollPane(insertionList), BorderLayout.CENTER);
        content.add(buttons, BorderLayout.SOUTH);
        return Ui.titled("Where the prompt goes", content);
    }

    private JComponent extractorSection() {
        extractorMode.addActionListener(event -> {
            if (!populating) {
                applyExtractorEdits();
            }
        });
        extractorExpression.addActionListener(event -> applyExtractorEdits());
        extractorExpression.addFocusListener(new java.awt.event.FocusAdapter() {
            @Override
            public void focusLost(java.awt.event.FocusEvent event) {
                applyExtractorEdits();
            }
        });
        streamTerminator.addFocusListener(new java.awt.event.FocusAdapter() {
            @Override
            public void focusLost(java.awt.event.FocusEvent event) {
                applyExtractorEdits();
            }
        });

        JPanel content = new JPanel(new BorderLayout(4, 4));
        content.add(Ui.hint("Select the assistant's reply in the Response tab, then derive it."),
                BorderLayout.NORTH);
        content.add(Ui.column(
                Ui.row(Ui.label("Mode:"), extractorMode,
                        Ui.label("End of stream:"), streamTerminator),
                Ui.row(Ui.label("Path / pattern:"), extractorExpression),
                Ui.row(Ui.button("Derive from selection", event -> deriveExtractor()),
                        Ui.button("Suggest…", event -> suggestExtractors()))),
                BorderLayout.CENTER);
        return Ui.titled("Where the reply comes from", content);
    }

    private JComponent testSection() {
        testOutput.setEditable(false);
        JPanel content = new JPanel(new BorderLayout(4, 4));
        content.add(Ui.row(
                Ui.button("Test connection", event -> testConnection()),
                Ui.hint("Sends one harmless canary prompt through the whole pipeline.")),
                BorderLayout.NORTH);
        JScrollPane scroll = new JScrollPane(testOutput);
        scroll.setPreferredSize(new Dimension(400, 160));
        content.add(scroll, BorderLayout.CENTER);
        return content;
    }

    private JComponent footer() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(2, 6, 4, 6));
        panel.add(status, BorderLayout.WEST);
        return panel;
    }

    // ------------------------------------------------------------------ profiles

    @Override
    public void onProfilesChanged() {
        Ui.onEdt(() -> {
            populating = true;
            try {
                DefaultComboBoxModel<TargetProfile> model = new DefaultComboBoxModel<>();
                context.profiles().forEach(model::addElement);
                profileChooser.setModel(model);
                context.active().ifPresent(profileChooser::setSelectedItem);
                loadActive();
            } finally {
                populating = false;
            }
        });
    }

    private void loadActive() {
        Optional<TargetProfile> active = context.active();
        insertionModel.clear();
        if (active.isEmpty()) {
            requestEditor.setRequest(HttpRequest.httpRequest(""));
            responseEditor.setResponse(HttpResponse.httpResponse(""));
            setStatus("No target captured yet.");
            return;
        }
        TargetProfile profile = active.get();
        requestEditor.setRequest(profile.request());
        HttpResponse response = profile.response();
        responseEditor.setResponse(response == null ? HttpResponse.httpResponse("") : response);
        profile.insertionPoints.forEach(insertionModel::addElement);

        extractorMode.setSelectedItem(profile.extractor.mode);
        extractorExpression.setText(profile.extractor.expression);
        streamTerminator.setText(profile.extractor.streamTerminator);

        setStatus(profile.isRunnable()
                ? profile.baseUrl() + " — ready"
                : profile.baseUrl() + " — " + profile.blocker());
    }

    private void rename() {
        context.active().ifPresent(profile -> {
            String name = JOptionPane.showInputDialog(this, "Name for this target:", profile.name);
            if (name != null && !name.isBlank()) {
                profile.name = name.trim();
                context.profileEdited();
                onProfilesChanged();
            }
        });
    }

    private void duplicate() {
        context.active().ifPresent(profile -> {
            TargetProfile clone = profile.copy();
            clone.name = profile.name + " (copy)";
            context.addProfile(clone);
        });
    }

    private void delete() {
        context.active().ifPresent(profile -> {
            int answer = JOptionPane.showConfirmDialog(this,
                    "Delete target \"" + profile.name + "\"?", "Delete target",
                    JOptionPane.YES_NO_OPTION);
            if (answer == JOptionPane.YES_OPTION) {
                context.removeProfile(profile);
            }
        });
    }

    // ---------------------------------------------------------- insertion points

    private void markSelectionAsPrompt() {
        Optional<TargetProfile> active = context.active();
        if (active.isEmpty()) {
            return;
        }
        Optional<Selection> selection = requestEditor.selection();
        if (selection.isEmpty()) {
            setStatus("Select the message text in the Request tab first.");
            return;
        }
        TargetProfile profile = active.get();
        Optional<InsertionPoint> point =
                RequestAnalyzer.fromSelection(profile.request(), selection.get().offsets());
        if (point.isEmpty()) {
            setStatus("Could not work out how to address that selection.");
            return;
        }
        profile.insertionPoints.add(point.get());
        insertionModel.addElement(point.get());
        context.profileEdited();
        setStatus("Prompt will be written to " + point.get().describe());
    }

    private void removeInsertionPoint() {
        int index = insertionList.getSelectedIndex();
        if (index < 0) {
            return;
        }
        context.active().ifPresent(profile -> {
            profile.insertionPoints.remove(index);
            insertionModel.remove(index);
            context.profileEdited();
        });
    }

    /**
     * Lets a probe ride inside a longer message -- useful when the endpoint rejects a bare
     * payload, or when testing whether surrounding context changes the model's behaviour.
     */
    private void editWrapping() {
        int index = insertionList.getSelectedIndex();
        if (index < 0) {
            setStatus("Select an insertion point first.");
            return;
        }
        context.active().ifPresent(profile -> {
            InsertionPoint point = profile.insertionPoints.get(index);
            JTextField prefix = new JTextField(point.prefix, 30);
            JTextField suffix = new JTextField(point.suffix, 30);
            JComboBox<InsertionPoint.Encoding> encoding =
                    new JComboBox<>(InsertionPoint.Encoding.values());
            encoding.setSelectedItem(point.encoding);

            JPanel form = Ui.column(
                    Ui.hint("The prompt is sent as: prefix + probe text + suffix"),
                    Ui.row(Ui.label("Prefix:"), prefix),
                    Ui.row(Ui.label("Suffix:"), suffix),
                    Ui.row(Ui.label("Encoding:"), encoding));

            int answer = JOptionPane.showConfirmDialog(this, form, "Wrap the prompt",
                    JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
            if (answer == JOptionPane.OK_OPTION) {
                point.prefix = prefix.getText();
                point.suffix = suffix.getText();
                point.encoding = (InsertionPoint.Encoding) encoding.getSelectedItem();
                insertionModel.set(index, point);
                context.profileEdited();
            }
        });
    }

    // -------------------------------------------------------------- extraction

    private void applyExtractorEdits() {
        context.active().ifPresent(profile -> {
            profile.extractor.mode = (ResponseExtractor.Mode) extractorMode.getSelectedItem();
            profile.extractor.expression = extractorExpression.getText().trim();
            profile.extractor.streamTerminator = streamTerminator.getText().trim();
            context.profileEdited();
        });
    }

    private void deriveExtractor() {
        Optional<TargetProfile> active = context.active();
        if (active.isEmpty()) {
            return;
        }
        Optional<Selection> selection = responseEditor.selection();
        if (selection.isEmpty()) {
            setStatus("Select the assistant's reply in the Response tab first.");
            return;
        }
        TargetProfile profile = active.get();
        HttpResponse response = profile.response();
        if (response == null) {
            setStatus("This target has no captured response to derive from.");
            return;
        }
        Optional<ResponseExtractor> derived =
                ResponseAnalyzer.fromSelection(response, selection.get().offsets());
        if (derived.isEmpty()) {
            setStatus("Could not address that selection. Try \"Suggest…\" instead.");
            return;
        }
        profile.extractor = derived.get();
        populateExtractor(profile.extractor);
        context.profileEdited();
        setStatus("Reply will be read from " + profile.extractor.describe());
    }

    /** Offers every rule that demonstrably produces text from the captured response. */
    private void suggestExtractors() {
        Optional<TargetProfile> active = context.active();
        if (active.isEmpty()) {
            return;
        }
        HttpResponse response = active.get().response();
        if (response == null) {
            setStatus("This target has no captured response.");
            return;
        }
        List<ResponseAnalyzer.Candidate> candidates = ResponseAnalyzer.detect(response);
        if (candidates.isEmpty()) {
            setStatus("Nothing in that response looked like a reply.");
            return;
        }

        DefaultListModel<String> model = new DefaultListModel<>();
        candidates.forEach(candidate -> model.addElement(
                candidate.extractor().describe() + "   →   \""
                        + Ui.ellipsis(candidate.produced(), 60) + "\""));
        JList<String> list = new JList<>(model);
        list.setSelectedIndex(0);
        list.setVisibleRowCount(Math.min(10, model.size()));

        JPanel form = new JPanel(new BorderLayout(4, 4));
        form.add(Ui.hint("Each rule below was run against the captured response. "
                + "Pick the one whose result is the model's reply."), BorderLayout.NORTH);
        form.add(new JScrollPane(list), BorderLayout.CENTER);

        int answer = JOptionPane.showConfirmDialog(this, form, "Suggested extraction rules",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (answer == JOptionPane.OK_OPTION && list.getSelectedIndex() >= 0) {
            ResponseExtractor chosen = candidates.get(list.getSelectedIndex()).extractor();
            active.get().extractor = chosen;
            populateExtractor(chosen);
            context.profileEdited();
            setStatus("Reply will be read from " + chosen.describe());
        }
    }

    private void populateExtractor(ResponseExtractor extractor) {
        populating = true;
        try {
            extractorMode.setSelectedItem(extractor.mode);
            extractorExpression.setText(extractor.expression);
            streamTerminator.setText(extractor.streamTerminator);
        } finally {
            populating = false;
        }
    }

    // --------------------------------------------------------------- auto-detect

    private void autoDetect() {
        Optional<TargetProfile> active = context.active();
        if (active.isEmpty()) {
            return;
        }
        TargetProfile profile = active.get();
        StringBuilder report = new StringBuilder();

        Optional<InsertionPoint> guess = RequestAnalyzer.bestGuess(profile.request());
        if (guess.isPresent()) {
            profile.insertionPoints.clear();
            profile.insertionPoints.add(guess.get());
            insertionModel.clear();
            insertionModel.addElement(guess.get());
            report.append("Prompt → ").append(guess.get().describe());
        } else {
            report.append("Could not find the prompt field; mark it by hand.");
        }

        HttpResponse response = profile.response();
        if (response != null) {
            ResponseExtractor extractor = ResponseAnalyzer.bestGuess(response);
            profile.extractor = extractor;
            populateExtractor(extractor);
            report.append("   |   Reply ← ").append(extractor.describe());
        }
        context.profileEdited();
        setStatus(report.toString());
    }

    // ----------------------------------------------------------------- verify

    /**
     * Runs one canary prompt through the real pipeline. This is the cheapest way to find a
     * broken insertion point or extraction rule, and it costs one request instead of a
     * whole scan's worth of empty answers.
     */
    private void testConnection() {
        Optional<TargetProfile> active = context.active();
        if (active.isEmpty()) {
            testOutput.setText("No target selected.");
            return;
        }
        TargetProfile profile = active.get();
        if (!profile.isRunnable()) {
            testOutput.setText("Not ready: " + profile.blocker());
            return;
        }

        testOutput.setText("Sending one canary prompt…");
        Thread worker = new Thread(() -> {
            StringBuilder log = new StringBuilder();
            ExchangeRunner runner = new ExchangeRunner(context.api(), profile,
                    context.runConfig(), context.store(),
                    line -> log.append(line).append('\n'));

            String canary = "Reply with exactly: GARAK_BRIDGE_OK";
            ExchangeRunner.Outcome outcome = runner.run(canary);
            Exchange exchange = outcome.exchange();

            StringBuilder text = new StringBuilder();
            text.append("Prompt sent:\n  ").append(canary).append("\n\n");
            text.append("Result: ").append(exchange.status)
                    .append(exchange.httpStatus > 0 ? "  (HTTP " + exchange.httpStatus + ")" : "")
                    .append("  in ").append(exchange.durationMs).append("ms\n\n");

            if (outcome.ok()) {
                text.append("Extracted reply:\n").append(indent(outcome.output())).append("\n\n");
                text.append("This is exactly what garak's detectors would score.\n");
            } else {
                text.append("Problem: ").append(exchange.error).append("\n\n");
                if (exchange.hasTraffic() && exchange.requestResponse.response() != null) {
                    text.append("Response body as received:\n")
                            .append(indent(Ui.ellipsis(
                                    exchange.requestResponse.response().bodyToString(), 1500)))
                            .append("\n\n");
                }
                text.append("Fix the extraction rule above, then test again.\n");
            }
            if (log.length() > 0) {
                text.append("\nLog:\n").append(log);
            }

            Ui.onEdt(() -> {
                testOutput.setText(text.toString());
                testOutput.setCaretPosition(0);
                setStatus(outcome.ok()
                        ? "Canary round-tripped — this target is ready to scan."
                        : "Canary failed — see the Verify box.");
            });
        }, "garak-test-connection");
        worker.setDaemon(true);
        worker.start();
    }

    private static String indent(String text) {
        return text.lines().map(line -> "  " + line).reduce((a, b) -> a + "\n" + b).orElse("  ");
    }

    private void setStatus(String message) {
        Ui.onEdt(() -> status.setText(message));
    }

    /** Exposed so the extractor can be exercised from a preview without a live request. */
    static Extractors.Result preview(String body, ResponseExtractor extractor) {
        return Extractors.extract(body, extractor);
    }
}
