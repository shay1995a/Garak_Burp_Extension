// Copyright 2026 the garak Bridge authors
// SPDX-License-Identifier: Apache-2.0

package burp.garak.model;

import java.nio.file.Path;

/** Extension-wide preferences, stored globally rather than per Burp project. */
public class Settings {

    /**
     * Path to a {@code garak} executable, or to the Python interpreter of the environment
     * garak is installed in. Empty means "look for garak on PATH".
     */
    public String garakPath = "";

    /** Where run directories are created. Empty means the default under the home directory. */
    public String runsDirectory = "";

    /** Bridge listen port. 0 lets the OS pick, which avoids clashes and is the default. */
    public int bridgePort;

    /** Burp proxy listener port, used only when exporting a standalone garak config. */
    public int burpProxyPort = 8080;

    /** Defaults copied into each new run. */
    public RunConfig runDefaults = new RunConfig();

    /** Keep run directories after the run finishes, so reports can be reopened. */
    public boolean keepRunDirectories = true;

    public Path resolveRunsDirectory() {
        if (runsDirectory != null && !runsDirectory.isBlank()) {
            return Path.of(runsDirectory);
        }
        return Path.of(System.getProperty("user.home", "."), ".garak-bridge", "runs");
    }
}
