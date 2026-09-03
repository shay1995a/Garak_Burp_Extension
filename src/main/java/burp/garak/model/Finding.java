// Copyright 2026 the garak Bridge authors
// SPDX-License-Identifier: Apache-2.0

package burp.garak.model;

/**
 * One hit from garak's hit log: a prompt that got past a detector.
 *
 * <p>Fields mirror the records garak writes to {@code <prefix>.hitlog.jsonl}, plus
 * {@link #exchangeId}, which this extension resolves so a finding can be traced back to
 * the exact HTTP exchange that produced it.
 */
public class Finding {

    /** Probe that generated the prompt, e.g. {@code dan.DanInTheWild}. */
    public String probe = "";

    /** Detector that scored it, e.g. {@code dan.DAN}. */
    public String detector = "";

    /** The probe's stated objective, straight from garak. */
    public String goal = "";

    /** The adversarial prompt that was sent. */
    public String prompt = "";

    /** What the target answered. */
    public String output = "";

    /** Detector score. garak logs a hit when it fails the eval threshold. */
    public double score;

    /** Strings the probe expected to see, when the detector works that way. */
    public String triggers = "";

    public String attemptId = "";
    public int attemptSeq;

    /** Index of this generation within the attempt; picks the right exchange when generations > 1. */
    public int attemptIdx;

    /** Resolved by correlation against the bridge's exchange store; -1 when unmatched. */
    public long exchangeId = -1;

    /** OWASP LLM / AVID tags carried over from the probe catalogue, for issue naming. */
    public String tags = "";

    /** Probe tier from garak's catalogue, 1 (highest quality) to 4; 0 when unknown. */
    public int tier;

    /** Stable key for grouping findings into one Burp issue. */
    public String issueKey() {
        return probe + "/" + detector;
    }

    /** First line of the model output, for the table's summary column. */
    public String outputSummary(int limit) {
        String text = output.replace('\n', ' ').replace('\r', ' ').trim();
        return text.length() <= limit ? text : text.substring(0, limit - 1) + "…";
    }

    public String promptSummary(int limit) {
        String text = prompt.replace('\n', ' ').replace('\r', ' ').trim();
        return text.length() <= limit ? text : text.substring(0, limit - 1) + "…";
    }
}
