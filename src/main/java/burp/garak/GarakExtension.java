// Copyright 2026 the garak Bridge authors
// SPDX-License-Identifier: Apache-2.0

package burp.garak;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import burp.garak.capture.ContextMenu;
import burp.garak.issues.AuditIssueFactory;
import burp.garak.ui.GarakTab;

import java.util.ArrayList;
import java.util.List;

/**
 * garak Bridge — run garak's LLM probes against a chat endpoint captured in Burp.
 *
 * <p>garak's REST generator can only make one stateless call per prompt, which is not what
 * a real chat feature looks like. So garak is pointed at a loopback bridge inside this
 * extension; the bridge injects each prompt into the request the user actually captured and
 * replays it through Burp's own HTTP stack. Every adversarial request therefore appears in
 * Burp's history, and every finding can be opened as the exchange that produced it.
 */
public final class GarakExtension implements BurpExtension {

    private static final String NAME = "garak Bridge";

    private final List<Registration> registrations = new ArrayList<>();
    private GarakContext context;

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName(NAME);

        context = new GarakContext(api);
        context.load();

        GarakTab tab = new GarakTab(context);
        registrations.add(api.userInterface().registerSuiteTab("garak", tab));
        registrations.add(api.userInterface().registerContextMenuItemsProvider(
                new ContextMenu(context, tab::showTarget)));

        api.extension().registerUnloadingHandler(this::unload);

        api.logging().logToOutput(NAME + " loaded.");
        api.logging().logToOutput("Burp " + api.burpSuite().version()
                + " (" + api.burpSuite().version().edition().displayName() + ")");
        if (!AuditIssueFactory.isSupported(api)) {
            api.logging().logToOutput("This edition has no Issues view; findings will stay in "
                    + "the garak tab, where they can be exported or sent to Repeater.");
        }
        api.logging().logToOutput("Right-click a chat request and choose "
                + "\"Send chat request to garak\" to begin.");

        // Detecting garak runs its --version, which imports torch and can take a minute.
        // Doing it in the background keeps extension loading instant.
        Thread detect = new Thread(() -> {
            context.refreshInstallation();
            tab.reloadCatalogue();
            context.installation().ifPresent(installation -> api.logging().logToOutput(
                    "garak: " + installation.describe()));
        }, "garak-startup-detect");
        detect.setDaemon(true);
        detect.start();
    }

    /**
     * Leaves nothing running. An abandoned garak process would keep sending adversarial
     * prompts at the target with no UI left to stop it, and an abandoned listener would
     * hold the bridge port until Burp exits.
     */
    private void unload() {
        if (context != null) {
            context.controller().stop();
            context.bridge().stop();
        }
        registrations.forEach(registration -> {
            if (registration.isRegistered()) {
                registration.deregister();
            }
        });
        registrations.clear();
    }
}
