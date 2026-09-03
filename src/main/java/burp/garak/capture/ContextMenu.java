// Copyright 2026 the garak Bridge authors
// SPDX-License-Identifier: Apache-2.0

package burp.garak.capture;

import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import burp.garak.GarakContext;
import burp.garak.model.InsertionPoint;
import burp.garak.model.PreludeStep;
import burp.garak.model.ResponseExtractor;
import burp.garak.model.TargetProfile;

import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import java.awt.Component;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

/**
 * The way a request gets into this extension: right-click it in Burp.
 *
 * <p>Capture and refinement are the same gesture. Sending a request in creates a target and
 * guesses its prompt field and reply location; selecting text in a request or response and
 * using the menu again corrects that guess exactly, without leaving the message editor.
 */
public final class ContextMenu implements ContextMenuItemsProvider {

    private final GarakContext context;
    private final Runnable onCaptured;

    public ContextMenu(GarakContext context, Runnable onCaptured) {
        this.context = context;
        this.onCaptured = onCaptured;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> items = new ArrayList<>();

        Optional<HttpRequestResponse> subject = subjectOf(event);
        if (subject.isEmpty()) {
            return items;
        }

        JMenuItem capture = new JMenuItem("Send chat request to garak");
        capture.addActionListener(action -> capture(subject.get()));
        items.add(capture);

        Optional<MessageEditorHttpRequestResponse> editor = event.messageEditorRequestResponse();
        Optional<TargetProfile> active = context.active();

        if (editor.isPresent() && active.isPresent()) {
            MessageEditorHttpRequestResponse message = editor.get();
            Optional<Range> selection = message.selectionOffsets();

            if (selection.isPresent()) {
                if (message.selectionContext()
                        == MessageEditorHttpRequestResponse.SelectionContext.REQUEST) {
                    JMenuItem markPrompt = new JMenuItem(
                            "garak: send prompts here (\"" + active.get().name + "\")");
                    markPrompt.addActionListener(action ->
                            markPrompt(message.requestResponse().request(), selection.get()));
                    items.add(markPrompt);
                } else {
                    JMenuItem markReply = new JMenuItem(
                            "garak: read the reply from here (\"" + active.get().name + "\")");
                    markReply.addActionListener(action ->
                            markReply(message.requestResponse().response(), selection.get()));
                    items.add(markReply);
                }
            }
        }

        if (active.isPresent()) {
            JMenuItem prelude = new JMenuItem(
                    "garak: add as prelude step for \"" + active.get().name + "\"");
            prelude.addActionListener(action -> addPrelude(subject.get()));
            items.add(prelude);
        }

        return items;
    }

    /** The one request this menu invocation is about, from whichever Burp view raised it. */
    private static Optional<HttpRequestResponse> subjectOf(ContextMenuEvent event) {
        Optional<MessageEditorHttpRequestResponse> editor = event.messageEditorRequestResponse();
        if (editor.isPresent()) {
            return Optional.of(editor.get().requestResponse());
        }
        List<HttpRequestResponse> selected = event.selectedRequestResponses();
        return selected.isEmpty() ? Optional.empty() : Optional.of(selected.get(0));
    }

    // ------------------------------------------------------------------ capture

    private void capture(HttpRequestResponse traffic) {
        HttpRequest request = traffic.request();
        if (request == null) {
            return;
        }
        TargetProfile profile = new TargetProfile();
        profile.setRequest(request);
        profile.setResponse(traffic.response());
        profile.name = nameFor(request);

        // Guess immediately: the common shapes need no configuration, and a wrong guess is
        // visible and correctable on the Target tab, where the request is already shown.
        RequestAnalyzer.bestGuess(request).ifPresent(profile.insertionPoints::add);
        HttpResponse response = traffic.response();
        if (response != null) {
            profile.extractor = ResponseAnalyzer.bestGuess(response);
        }

        context.addProfile(profile);
        onCaptured.run();

        // The Scan tab shows the outcome; the log is just a breadcrumb.
        context.log(profile.insertionPoints.isEmpty()
                ? "garak: captured " + profile.name + ", but no message field was recognised - "
                        + "mark it by hand on the garak tab"
                : "garak: captured " + profile.name + " - prompt → "
                        + profile.insertionPoints.get(0).describe() + ", reply ← "
                        + profile.extractor.describe());
    }

    private void markPrompt(HttpRequest request, Range selection) {
        context.active().ifPresent(profile -> {
            Optional<InsertionPoint> point = RequestAnalyzer.fromSelection(request, selection);
            if (point.isEmpty()) {
                warn("Could not work out how to address that selection.");
                return;
            }
            profile.insertionPoints.clear();
            profile.insertionPoints.add(point.get());
            context.profileEdited();
            onCaptured.run();
            context.log("garak: prompts will be written to " + point.get().describe());
        });
    }

    private void markReply(HttpResponse response, Range selection) {
        if (response == null) {
            warn("There is no response to read the reply from.");
            return;
        }
        context.active().ifPresent(profile -> {
            Optional<ResponseExtractor> extractor =
                    ResponseAnalyzer.fromSelection(response, selection);
            if (extractor.isEmpty()) {
                warn("Could not work out how to address that selection. "
                        + "Try \"Suggest…\" on the Target tab.");
                return;
            }
            profile.extractor = extractor.get();
            context.profileEdited();
            onCaptured.run();
            context.log("garak: replies will be read from " + extractor.get().describe());
        });
    }

    /**
     * Adds a request that must run before each prompt -- creating a conversation, or
     * fetching a CSRF token. The captured values are bound by editing the step afterwards.
     */
    private void addPrelude(HttpRequestResponse traffic) {
        context.active().ifPresent(profile -> {
            HttpRequest request = traffic.request();
            if (request == null) {
                return;
            }
            PreludeStep step = new PreludeStep();
            step.name = "step " + (profile.prelude.size() + 1) + " · " + request.path();
            step.requestBase64 = Base64.getEncoder()
                    .encodeToString(request.toByteArray().getBytes());
            if (request.httpService() != null) {
                step.host = request.httpService().host();
                step.port = request.httpService().port();
                step.secure = request.httpService().secure();
            }

            // Offer the obvious capture straight away: whatever id the response carries.
            HttpResponse response = traffic.response();
            if (response != null) {
                ResponseAnalyzer.detect(response).stream().findFirst().ifPresent(candidate ->
                        step.captures.add(new PreludeStep.Capture("value",
                                candidate.extractor())));
            }

            profile.prelude.add(step);
            context.profileEdited();
            onCaptured.run();
            context.log("garak: added prelude step '" + step.name + "' to " + profile.name
                    + ". Reference its captured value as {{value}} in the main request.");
        });
    }

    private static String nameFor(HttpRequest request) {
        String host = request.httpService() == null ? "target" : request.httpService().host();
        String path = request.path();
        if (path == null || path.isEmpty()) {
            path = "/";
        }
        int query = path.indexOf('?');
        if (query > 0) {
            path = path.substring(0, query);
        }
        return host + path;
    }

    private void warn(String message) {
        JOptionPane.showMessageDialog(null, message, "garak", JOptionPane.WARNING_MESSAGE);
    }
}
