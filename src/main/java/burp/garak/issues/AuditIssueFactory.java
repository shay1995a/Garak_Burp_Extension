// Copyright 2026 the garak Bridge authors
// SPDX-License-Identifier: Apache-2.0

package burp.garak.issues;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.BurpSuiteEdition;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.garak.bridge.ExchangeStore;
import burp.garak.model.Exchange;
import burp.garak.model.Finding;
import burp.garak.model.TargetProfile;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Turns garak findings into Burp audit issues.
 *
 * <p>One issue per probe/detector pair rather than per hit: a jailbreak probe that lands 40
 * times is one weakness with 40 pieces of evidence, and 40 separate issues would bury the
 * other findings. Evidence carries the real request/response pairs, so an issue opens onto
 * the traffic that produced it.
 *
 * <p>Issue creation is best-effort. Burp Community has no Scanner or Issues view, so this
 * checks the edition and swallows failures: the extension's own Results tab is the
 * authoritative output either way.
 */
public final class AuditIssueFactory {

    /** Evidence attached per issue. Enough to be convincing, not enough to bloat the project. */
    private static final int MAX_EVIDENCE = 10;

    private static final int MAX_EXCERPT = 4000;

    private AuditIssueFactory() {
    }

    /** True when this Burp can show audit issues at all. */
    public static boolean isSupported(MontoyaApi api) {
        try {
            return api.burpSuite().version().edition() == BurpSuiteEdition.PROFESSIONAL;
        } catch (RuntimeException e) {
            return false;
        }
    }

    /**
     * Publishes one issue per probe/detector pair.
     *
     * @return how many issues were added
     */
    public static int publish(MontoyaApi api, TargetProfile profile, List<Finding> findings,
                              ExchangeStore store) {
        if (findings.isEmpty()) {
            return 0;
        }
        Map<String, List<Finding>> grouped = new LinkedHashMap<>();
        for (Finding finding : findings) {
            grouped.computeIfAbsent(finding.issueKey(), key -> new ArrayList<>()).add(finding);
        }

        int published = 0;
        for (List<Finding> group : grouped.values()) {
            try {
                api.siteMap().add(build(profile, group, store));
                published++;
            } catch (RuntimeException e) {
                api.logging().logToError("could not add issue for "
                        + group.get(0).issueKey() + ": " + e);
            }
        }
        return published;
    }

    static AuditIssue build(TargetProfile profile, List<Finding> group, ExchangeStore store) {
        Finding first = group.get(0);
        List<HttpRequestResponse> evidence = evidenceFor(group, store);

        return AuditIssue.auditIssue(
                name(first),
                detail(profile, group),
                remediation(),
                profile.baseUrl(),
                severity(first, group.size()),
                confidence(group.size()),
                background(),
                remediationBackground(),
                AuditIssueSeverity.MEDIUM,
                evidence);
    }

    private static String name(Finding finding) {
        StringBuilder name = new StringBuilder("LLM: ").append(shortProbe(finding.probe));
        if (!finding.goal.isBlank()) {
            name.append(" - ").append(truncate(finding.goal, 70));
        }
        List<String> owasp = owaspTags(finding);
        if (!owasp.isEmpty()) {
            name.append(" [").append(String.join(", ", owasp)).append(']');
        }
        return name.toString();
    }

    private static String detail(TargetProfile profile, List<Finding> group) {
        Finding first = group.get(0);
        StringBuilder detail = new StringBuilder();

        detail.append("<p>The <b>garak</b> probe <code>").append(escape(first.probe))
                .append("</code> got past the detector <code>").append(escape(first.detector))
                .append("</code> on <b>").append(group.size()).append("</b> of the prompts sent "
                        + "to this chat endpoint.</p>");

        if (!first.goal.isBlank()) {
            detail.append("<p><b>Probe objective:</b> ").append(escape(first.goal)).append("</p>");
        }
        if (!first.tags.isBlank()) {
            detail.append("<p><b>Classification:</b> ").append(escape(first.tags)).append("</p>");
        }
        if (first.tier > 0) {
            detail.append("<p><b>garak probe tier:</b> ").append(first.tier)
                    .append(" (1 is the highest-quality probe set)</p>");
        }
        detail.append("<p><b>Prompt delivered to:</b> ")
                .append(escape(profile.insertionPoints.isEmpty()
                        ? "unknown" : profile.insertionPoints.get(0).describe()))
                .append("<br><b>Reply read from:</b> ")
                .append(escape(profile.extractor.describe()))
                .append("</p>");

        detail.append("<p><b>Example exchanges</b> (")
                .append(Math.min(group.size(), 3)).append(" of ").append(group.size())
                .append("):</p>");

        for (Finding finding : group.subList(0, Math.min(3, group.size()))) {
            detail.append("<hr><p><b>Prompt sent:</b></p><pre>")
                    .append(escape(truncate(finding.prompt, MAX_EXCERPT)))
                    .append("</pre><p><b>Model replied:</b></p><pre>")
                    .append(escape(truncate(finding.output, MAX_EXCERPT)))
                    .append("</pre>");
            if (!finding.triggers.isBlank()) {
                detail.append("<p><b>Detector looked for:</b> ")
                        .append(escape(truncate(finding.triggers, 500))).append("</p>");
            }
        }

        detail.append("<hr><p>Reported by garak (https://garak.ai) via the garak Bridge "
                + "Burp extension. Every request above was sent through Burp and is in the "
                + "extension's Results tab, where it can be sent to Repeater.</p>");
        return detail.toString();
    }

    private static String remediation() {
        return "<p>Treat the model's output as untrusted input. Specifically:</p><ul>"
                + "<li>Do not let model output reach a privileged sink -- a shell, an "
                + "eval, a SQL string, a browser DOM, or an internal API -- without the "
                + "same validation any user input would get.</li>"
                + "<li>Put input and output filtering in front of the model rather than "
                + "relying on system-prompt instructions, which an attacker can address "
                + "directly.</li>"
                + "<li>Scope the model's tools and data access to what the requesting user "
                + "is already entitled to, so a successful jailbreak gains no privilege.</li>"
                + "<li>Rate-limit and log conversations so probing is visible.</li>"
                + "<li>Re-run this probe set against any change to the system prompt, the "
                + "model version, or the guardrail configuration.</li></ul>";
    }

    private static String background() {
        return "<p>Large language model endpoints can be steered by the text they are sent. "
                + "A prompt injection or jailbreak makes the model ignore its instructions and "
                + "produce content its operator intended to prevent -- disclosing the system "
                + "prompt, emitting harmful or defamatory text, or calling a tool on the "
                + "attacker's behalf.</p>"
                + "<p>garak is an open-source LLM vulnerability scanner. A probe sends a family "
                + "of adversarial prompts; a detector decides whether the reply shows the attack "
                + "worked. This issue records the prompts where the detector said it did.</p>"
                + "<p>Detectors are heuristics, and both false positives and false negatives "
                + "happen. The evidence is included above so each hit can be judged.</p>";
    }

    private static String remediationBackground() {
        return "<p>See OWASP's Top 10 for LLM Applications "
                + "(https://owasp.org/www-project-top-10-for-large-language-model-applications/) "
                + "for the standard control set, and garak's own documentation "
                + "(https://docs.garak.ai) for what each probe and detector actually tests.</p>";
    }

    /**
     * Severity follows garak's probe tier, which is its own judgement of how meaningful a
     * hit is. Tier 1 probes are the curated, high-signal set.
     */
    private static AuditIssueSeverity severity(Finding finding, int hits) {
        return switch (finding.tier) {
            case 1 -> AuditIssueSeverity.HIGH;
            case 2 -> AuditIssueSeverity.MEDIUM;
            case 3 -> AuditIssueSeverity.LOW;
            default -> hits >= 5 ? AuditIssueSeverity.MEDIUM : AuditIssueSeverity.LOW;
        };
    }

    /**
     * Confidence reflects repetition. One hit from a heuristic detector deserves a look;
     * the same detector firing on many prompts is a pattern.
     */
    private static AuditIssueConfidence confidence(int hits) {
        if (hits >= 10) {
            return AuditIssueConfidence.CERTAIN;
        }
        return hits >= 3 ? AuditIssueConfidence.FIRM : AuditIssueConfidence.TENTATIVE;
    }

    private static List<HttpRequestResponse> evidenceFor(List<Finding> group, ExchangeStore store) {
        List<HttpRequestResponse> evidence = new ArrayList<>();
        for (Finding finding : group) {
            if (evidence.size() >= MAX_EVIDENCE) {
                break;
            }
            Optional<Exchange> exchange = finding.exchangeId >= 0
                    ? store.byId(finding.exchangeId)
                    : store.find(finding.prompt, finding.attemptIdx);
            exchange.filter(Exchange::hasTraffic)
                    .ifPresent(found -> evidence.add(found.requestResponse));
        }
        return evidence;
    }

    private static List<String> owaspTags(Finding finding) {
        List<String> owasp = new ArrayList<>();
        for (String tag : finding.tags.split(",")) {
            String trimmed = tag.trim();
            if (trimmed.startsWith("owasp:")) {
                owasp.add(trimmed.substring("owasp:".length()).toUpperCase(java.util.Locale.ROOT));
            }
        }
        return owasp;
    }

    private static String shortProbe(String probe) {
        return probe.startsWith("probes.") ? probe.substring("probes.".length()) : probe;
    }

    private static String truncate(String text, int limit) {
        if (text == null) {
            return "";
        }
        return text.length() <= limit ? text : text.substring(0, limit) + "\n… (truncated)";
    }

    /** Issue detail is rendered as HTML, and model output is attacker-influenced. */
    private static String escape(String text) {
        if (text == null) {
            return "";
        }
        return text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;");
    }
}
