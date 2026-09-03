// Copyright 2026 the garak Bridge authors
// SPDX-License-Identifier: Apache-2.0

package burp.garak;

import burp.api.montoya.MontoyaApi;
import burp.garak.bridge.BridgeServer;
import burp.garak.bridge.ExchangeStore;
import burp.garak.garakproc.GarakLocator;
import burp.garak.garakproc.PluginCatalog;
import burp.garak.garakproc.RunController;
import burp.garak.model.RunConfig;
import burp.garak.model.Settings;
import burp.garak.model.TargetProfile;
import burp.garak.util.Json;
import com.google.gson.JsonElement;
import com.google.gson.reflect.TypeToken;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * State shared across the extension's panels, and the only place that touches persistence.
 *
 * <p>Target profiles live in project data because they embed a captured request for one
 * host with one session; settings live in global preferences because a garak path is a
 * property of the machine, not of the engagement.
 */
public final class GarakContext {

    private static final String PROFILES_KEY = "garak.bridge.profiles";
    private static final String ACTIVE_KEY = "garak.bridge.activeProfile";
    private static final String RUNCONFIG_KEY = "garak.bridge.runConfig";
    private static final String SETTINGS_KEY = "garak.bridge.settings";

    /** Notified when the profile list or the active profile changes. */
    public interface ProfileListener {
        void onProfilesChanged();
    }

    private final MontoyaApi api;
    private final BridgeServer bridge;
    private final ExchangeStore store;
    private final RunController controller;

    private final List<TargetProfile> profiles = new ArrayList<>();
    private final List<ProfileListener> listeners = new CopyOnWriteArrayList<>();

    private Settings settings = new Settings();
    private RunConfig runConfig = new RunConfig();
    private TargetProfile active;
    private GarakLocator.Installation installation;
    private PluginCatalog catalogue = PluginCatalog.empty();

    public GarakContext(MontoyaApi api) {
        this.api = api;
        this.bridge = new BridgeServer(this::log);
        this.store = new ExchangeStore();
        this.controller = new RunController(api, bridge, store);
    }

    // ------------------------------------------------------------------ accessors

    public MontoyaApi api() {
        return api;
    }

    public BridgeServer bridge() {
        return bridge;
    }

    public ExchangeStore store() {
        return store;
    }

    public RunController controller() {
        return controller;
    }

    public Settings settings() {
        return settings;
    }

    public RunConfig runConfig() {
        return runConfig;
    }

    public List<TargetProfile> profiles() {
        return profiles;
    }

    public Optional<TargetProfile> active() {
        return Optional.ofNullable(active);
    }

    public PluginCatalog catalogue() {
        return catalogue;
    }

    public Optional<GarakLocator.Installation> installation() {
        return Optional.ofNullable(installation);
    }

    public void log(String message) {
        api.logging().logToOutput(message);
    }

    // -------------------------------------------------------------------- mutation

    public void addProfile(TargetProfile profile) {
        profiles.add(profile);
        active = profile;
        saveProfiles();
        fireProfilesChanged();
    }

    public void removeProfile(TargetProfile profile) {
        profiles.remove(profile);
        if (active == profile) {
            active = profiles.isEmpty() ? null : profiles.get(0);
        }
        saveProfiles();
        fireProfilesChanged();
    }

    public void setActive(TargetProfile profile) {
        active = profile;
        saveProfiles();
        fireProfilesChanged();
    }

    /** Persists whatever changed in the active profile, without changing selection. */
    public void profileEdited() {
        saveProfiles();
    }

    public void addProfileListener(ProfileListener listener) {
        listeners.add(listener);
    }

    private void fireProfilesChanged() {
        listeners.forEach(ProfileListener::onProfilesChanged);
    }

    // ------------------------------------------------------------------ garak setup

    /**
     * Re-probes the configured garak path and reloads the probe catalogue.
     * Slow (garak's startup imports torch), so callers should run it off the UI thread.
     */
    public GarakLocator.Installation refreshInstallation() {
        installation = GarakLocator.probe(settings.garakPath);
        if (installation.hasCatalogue()) {
            catalogue = PluginCatalog.fromPluginCache(installation.pluginCache());
        } else if (installation.isUsable()) {
            catalogue = PluginCatalog.fromListProbes(installation.command());
        } else {
            catalogue = PluginCatalog.empty();
        }
        return installation;
    }

    // ----------------------------------------------------------------- persistence

    public void load() {
        String storedSettings = api.persistence().preferences().getString(SETTINGS_KEY);
        if (storedSettings != null && !storedSettings.isBlank()) {
            try {
                Settings loaded = Json.GSON.fromJson(storedSettings, Settings.class);
                if (loaded != null) {
                    settings = loaded;
                    if (settings.runDefaults == null) {
                        settings.runDefaults = new RunConfig();
                    }
                }
            } catch (RuntimeException e) {
                log("could not read stored settings, using defaults: " + e.getMessage());
            }
        }

        String storedRunConfig = api.persistence().extensionData().getString(RUNCONFIG_KEY);
        if (storedRunConfig != null && !storedRunConfig.isBlank()) {
            try {
                RunConfig loaded = Json.GSON.fromJson(storedRunConfig, RunConfig.class);
                if (loaded != null) {
                    runConfig = loaded;
                }
            } catch (RuntimeException e) {
                runConfig = settings.runDefaults.copy();
            }
        } else {
            runConfig = settings.runDefaults.copy();
        }

        String storedProfiles = api.persistence().extensionData().getString(PROFILES_KEY);
        if (storedProfiles != null && !storedProfiles.isBlank()) {
            try {
                List<TargetProfile> loaded = Json.GSON.fromJson(storedProfiles,
                        new TypeToken<List<TargetProfile>>() {
                        }.getType());
                if (loaded != null) {
                    profiles.addAll(loaded);
                }
            } catch (RuntimeException e) {
                log("could not read stored target profiles: " + e.getMessage());
            }
        }

        String activeId = api.persistence().extensionData().getString(ACTIVE_KEY);
        active = profiles.stream()
                .filter(profile -> profile.id.equals(activeId))
                .findFirst()
                .orElse(profiles.isEmpty() ? null : profiles.get(0));
    }

    public void saveSettings() {
        try {
            api.persistence().preferences().setString(SETTINGS_KEY, Json.GSON.toJson(settings));
        } catch (RuntimeException e) {
            log("could not save settings: " + e.getMessage());
        }
    }

    public void saveRunConfig() {
        try {
            api.persistence().extensionData()
                    .setString(RUNCONFIG_KEY, Json.GSON.toJson(runConfig));
        } catch (RuntimeException e) {
            log("could not save run config: " + e.getMessage());
        }
    }

    private void saveProfiles() {
        try {
            api.persistence().extensionData().setString(PROFILES_KEY, Json.GSON.toJson(profiles));
            api.persistence().extensionData().setString(ACTIVE_KEY, active == null ? "" : active.id);
        } catch (RuntimeException e) {
            log("could not save target profiles: " + e.getMessage());
        }
    }

    /** Reads Burp's first proxy listener port, for the standalone config export. */
    public int burpProxyPort() {
        try {
            String optionsJson = api.burpSuite()
                    .exportProjectOptionsAsJson("proxy.request_listeners");
            Optional<JsonElement> parsed = Json.parse(optionsJson);
            if (parsed.isPresent()) {
                Optional<String> port = burp.garak.util.JsonPathLite
                        .evalToString(parsed.get(), "$.proxy.request_listeners[0].listener_port");
                if (port.isPresent() && !port.get().isBlank()) {
                    return Integer.parseInt(port.get().trim());
                }
            }
        } catch (RuntimeException e) {
            // fall through to the configured default
        }
        return settings.burpProxyPort;
    }
}
