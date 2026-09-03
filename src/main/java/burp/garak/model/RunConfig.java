// Copyright 2026 the garak Bridge authors
// SPDX-License-Identifier: Apache-2.0

package burp.garak.model;

import java.util.ArrayList;
import java.util.List;

/**
 * Everything that governs one garak run: what to probe, and how hard to hit the target.
 *
 * <p>The throttle settings matter more here than in a normal scan. garak's defaults are
 * tuned for an API you own -- {@code generations: 5} against a probe capped at 256 prompts
 * is over a thousand requests for a single probe -- which is not a reasonable default
 * against someone's production chat feature. The defaults below are deliberately gentler.
 */
public class RunConfig {

    /** Fully qualified probe names, e.g. {@code probes.dan.DanInTheWild}. */
    public List<String> probes = new ArrayList<>();

    /** Answers requested per prompt. garak's own default is 5; one is plenty to find a hit. */
    public int generations = 1;

    /** Upper bound on prompts a single probe may emit. garak's default is 256. */
    public int softProbePromptCap = 64;

    /** Fixed seed keeps a run reproducible; -1 leaves garak to choose. */
    public int seed = -1;

    /** Probe attempts garak runs in parallel. The bridge throttle is the real limiter. */
    public int parallelAttempts = 4;

    // ------------------------------------------------------------- throttling

    /** Requests the bridge will have in flight against the target at once. */
    public int maxConcurrent = 2;

    /** Minimum gap between two requests leaving the bridge. */
    public int delayMs = 250;

    /** Random extra delay on top, to avoid a machine-gun cadence. */
    public int jitterMs = 250;

    /** How long to wait for the target to answer one prompt. */
    public int requestTimeoutMs = 60_000;

    /** Attempts per prompt before the bridge gives up and tells garak to back off. */
    public int retries = 2;

    /**
     * Consecutive failures that trip the circuit breaker. Past this the run stops rather
     * than spending the remaining budget feeding garak errors it will score as answers.
     */
    public int circuitBreakerThreshold = 10;

    // ---------------------------------------------------------------- reporting

    /** Push findings into Burp's Issues view when the edition supports it. */
    public boolean createAuditIssues = true;

    /** Allow a target outside Burp's configured scope. Off by default, on purpose. */
    public boolean allowOutOfScope;

    /** Ceiling the auto-throttle aims for: roughly three requests a second at the target. */
    private static final int TARGET_GAP_MS = 350;

    /**
     * Sets the throttle from the endpoint's measured reply time, so the tester does not
     * have to reason about it.
     *
     * <p>A slow endpoint throttles itself — two workers waiting five seconds each are
     * already gentle — so delay is only added when the endpoint is fast enough to be
     * hammered. The reply timeout is scaled off the same measurement, because a model that
     * normally takes twenty seconds will occasionally take sixty.
     */
    public void applyAutoThrottle(long measuredLatencyMs) {
        maxConcurrent = 2;
        long naturalGap = Math.max(0, measuredLatencyMs) / maxConcurrent;
        delayMs = (int) Math.max(0, TARGET_GAP_MS - naturalGap);
        jitterMs = Math.max(100, delayMs / 2);
        requestTimeoutMs = (int) Math.min(180_000, Math.max(30_000, measuredLatencyMs * 6));
    }

    public RunConfig copy() {
        RunConfig clone = new RunConfig();
        clone.probes = new ArrayList<>(probes);
        clone.generations = generations;
        clone.softProbePromptCap = softProbePromptCap;
        clone.seed = seed;
        clone.parallelAttempts = parallelAttempts;
        clone.maxConcurrent = maxConcurrent;
        clone.delayMs = delayMs;
        clone.jitterMs = jitterMs;
        clone.requestTimeoutMs = requestTimeoutMs;
        clone.retries = retries;
        clone.circuitBreakerThreshold = circuitBreakerThreshold;
        clone.createAuditIssues = createAuditIssues;
        clone.allowOutOfScope = allowOutOfScope;
        return clone;
    }

    /**
     * Rough upper bound on requests to the target, for the pre-flight summary.
     * Real counts run lower: many probes emit far fewer prompts than the cap.
     */
    public long estimatedRequests() {
        return (long) Math.max(1, probes.size()) * softProbePromptCap * Math.max(1, generations);
    }

    /** Rough wall-clock estimate in seconds, given the throttle. */
    public long estimatedSeconds() {
        double perRequestMs = delayMs + (jitterMs / 2.0);
        double concurrency = Math.max(1, maxConcurrent);
        return (long) (estimatedRequests() * perRequestMs / concurrency / 1000.0);
    }
}
