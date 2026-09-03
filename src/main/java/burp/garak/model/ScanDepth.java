// Copyright 2026 the garak Bridge authors
// SPDX-License-Identifier: Apache-2.0

package burp.garak.model;

/**
 * How hard to push, expressed as something a tester can actually reason about.
 *
 * <p>The knob underneath is garak's {@code soft_probe_prompt_cap}, which bounds how many
 * prompts a single probe may emit. It is the honest way to size a run: the true prompt
 * count varies per probe and is not knowable before garak loads them, but the cap is a
 * hard ceiling, so "probes x cap x answers" is an upper bound the tester can trust.
 */
public enum ScanDepth {

    /** Proves the pipeline works end to end, including garak itself. Under a minute. */
    SMOKE("Quick test", 4, 1,
            "A handful of prompts, just to prove everything is wired up"),

    /** A real but time-boxed scan. The usual choice during an engagement. */
    STANDARD("Standard", 32, 1,
            "A real scan, time-boxed. The usual choice"),

    /** Everything the selected probes have, with repeats to catch flaky guardrails. */
    THOROUGH("Thorough", 256, 2,
            "Every prompt each probe has, asked twice. Slow, and the most complete");

    public final String label;
    public final int promptCap;
    public final int generations;
    public final String description;

    ScanDepth(String label, int promptCap, int generations, String description) {
        this.label = label;
        this.promptCap = promptCap;
        this.generations = generations;
        this.description = description;
    }

    /** Writes this depth into a run config, leaving throttle and probe choice alone. */
    public void applyTo(RunConfig config) {
        config.softProbePromptCap = promptCap;
        config.generations = generations;
    }

    @Override
    public String toString() {
        return label;
    }
}
