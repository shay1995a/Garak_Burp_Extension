// Copyright 2026 the garak Bridge authors
// SPDX-License-Identifier: Apache-2.0

package burp.garak.capture;

import burp.garak.bridge.Extractors;
import burp.garak.model.InsertionPoint;
import burp.garak.model.ResponseExtractor;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.function.Consumer;

/**
 * Proves — against the live endpoint — that the prompt reaches the model and the reply
 * comes back, then picks the pair of rules that demonstrably work.
 *
 * <h2>Why guessing from the captured response is not enough</h2>
 *
 * {@link RequestAnalyzer} and {@link ResponseAnalyzer} can only reason about one captured
 * exchange, and a wrong insertion point is invisible there: writing the prompt into the
 * wrong JSON field still produces a perfectly valid 200 with a perfectly valid reply. The
 * scan then runs to completion and scores several thousand answers to a question nobody
 * asked.
 *
 * <p>So this sends two <em>different</em> benign prompts through each candidate rule and
 * compares the answers. If the model echoes the token it was given, both ends are proven.
 * If the two answers merely differ, the prompt is provably reaching the model. If the two
 * answers are identical, the prompt is not getting through and the next candidate is tried.
 *
 * <p>The search is expressed against {@link Sender} rather than Burp's HTTP API so the
 * whole decision procedure can be tested without a running Burp.
 */
public final class Calibrator {

    /** Two questions with different answers, so even a deflecting model replies differently. */
    static final String TOKEN_A = "ALFA7Q2X";
    static final String TOKEN_B = "BRAVO9M4K";
    static final String PROMPT_A =
            "In one short sentence, what colour is a clear daytime sky? "
                    + "End your reply with the token " + TOKEN_A + ".";
    static final String PROMPT_B =
            "In one short sentence, how many legs does a spider have? "
                    + "End your reply with the token " + TOKEN_B + ".";

    /** Candidate rules tried before giving up, to bound the traffic this generates. */
    private static final int MAX_INSERTION_CANDIDATES = 5;
    private static final int MAX_EXTRACTOR_CANDIDATES = 8;

    /** One trial request, abstracted away from Burp so the search is testable. */
    public interface Sender {
        Reply send(InsertionPoint point, String prompt);
    }

    /** What came back from a trial request. */
    public record Reply(int status, String body, String contentType, long latencyMs, String error) {
        public boolean ok() {
            return error.isEmpty() && status >= 200 && status < 300;
        }

        public static Reply failed(String error) {
            return new Reply(0, "", "", 0, error);
        }
    }

    /** How sure we are that the configuration actually works. */
    public enum Confidence {
        /** The model echoed the token it was given: prompt in and reply out are both proven. */
        ECHOED,
        /** Two different prompts produced two different replies: the prompt is getting through. */
        REPLIES_DIFFER,
        /**
         * A reply was read, but it did not change with the prompt. Either the prompt is not
         * reaching the model, or the model answers everything identically.
         */
        UNCONFIRMED,
        /** Nothing usable came back. */
        FAILED
    }

    public record Outcome(
            Confidence confidence,
            InsertionPoint point,
            ResponseExtractor extractor,
            String headline,
            List<String> notes,
            long latencyMs,
            int requestsUsed,
            String sampleReply) {

        /** True when the target is safe to scan. */
        public boolean usable() {
            return confidence == Confidence.ECHOED
                    || confidence == Confidence.REPLIES_DIFFER
                    || confidence == Confidence.UNCONFIRMED;
        }

        /** True when the prompt is proven to reach the model. */
        public boolean proven() {
            return confidence == Confidence.ECHOED || confidence == Confidence.REPLIES_DIFFER;
        }
    }

    private Calibrator() {
    }

    /**
     * Tries each candidate rule against the live endpoint, best guess first, and returns
     * the first pair that demonstrably works.
     *
     * <p>Costs two requests per insertion candidate: every extraction rule is evaluated
     * against the same two responses, so widening the extractor search is free.
     */
    public static Outcome calibrate(List<InsertionPoint> insertionCandidates, Sender sender,
                                    Consumer<String> progress) {
        List<String> notes = new ArrayList<>();
        if (insertionCandidates.isEmpty()) {
            return new Outcome(Confidence.FAILED, null, null,
                    "Could not find where the message goes in this request",
                    List.of("Select the message text in the request and mark it by hand."),
                    0, 0, "");
        }

        List<InsertionPoint> candidates =
                insertionCandidates.subList(0, Math.min(MAX_INSERTION_CANDIDATES,
                        insertionCandidates.size()));

        int requests = 0;
        Outcome fallback = null;
        List<Long> latencies = new ArrayList<>();

        for (int i = 0; i < candidates.size(); i++) {
            InsertionPoint point = candidates.get(i);
            progress.accept("Trying " + point.describe()
                    + (candidates.size() > 1 ? "  (" + (i + 1) + " of " + candidates.size() + ")" : ""));

            Reply first = sender.send(point, PROMPT_A);
            requests++;
            if (!first.ok()) {
                notes.add(point.describe() + " — " + describeFailure(first));
                continue;
            }
            latencies.add(first.latencyMs());

            Reply second = sender.send(point, PROMPT_B);
            requests++;
            if (!second.ok()) {
                notes.add(point.describe() + " — " + describeFailure(second));
                continue;
            }
            latencies.add(second.latencyMs());

            Outcome outcome = judge(point, first, second, requests, median(latencies));
            if (outcome.proven()) {
                outcome.notes().addAll(0, notes);
                return outcome;
            }
            if (outcome.confidence() == Confidence.UNCONFIRMED && fallback == null) {
                fallback = outcome;
            }
            notes.add(point.describe() + " — "
                    + (outcome.confidence() == Confidence.UNCONFIRMED
                    ? "the reply did not change with the prompt"
                    : "no readable reply"));
        }

        if (fallback != null) {
            return new Outcome(fallback.confidence(), fallback.point(), fallback.extractor(),
                    fallback.headline(), merge(notes, fallback.notes()), fallback.latencyMs(),
                    requests, fallback.sampleReply());
        }
        return new Outcome(Confidence.FAILED, candidates.get(0), null,
                "Could not get a readable reply out of this endpoint",
                merge(notes, List.of("Check the request still works in Repeater — the captured "
                        + "session may have expired.")),
                median(latencies), requests, "");
    }

    /**
     * Decides what a pair of trial replies proves. Split out from the network loop so the
     * verdict logic can be exercised directly.
     */
    static Outcome judge(InsertionPoint point, Reply first, Reply second, int requestsUsed,
                         long latencyMs) {
        List<ResponseAnalyzer.Candidate> extractors =
                ResponseAnalyzer.detect(first.body(), first.contentType());

        ResponseExtractor bestUnconfirmed = null;
        String bestUnconfirmedText = "";

        int considered = 0;
        for (ResponseAnalyzer.Candidate candidate : extractors) {
            if (++considered > MAX_EXTRACTOR_CANDIDATES) {
                break;
            }
            ResponseExtractor extractor = candidate.extractor();

            Extractors.Result textA = Extractors.extract(first.body(), extractor);
            Extractors.Result textB = Extractors.extract(second.body(), extractor);
            if (!textA.ok() || !textB.ok() || textA.text().isBlank() || textB.text().isBlank()) {
                continue;
            }

            // Strongest signal: the model repeated the token we gave it, and only that
            // prompt carried that token.
            boolean echoedA = contains(textA.text(), TOKEN_A);
            boolean echoedB = contains(textB.text(), TOKEN_B);
            if (echoedA && echoedB) {
                return new Outcome(Confidence.ECHOED, point, extractor,
                        "Confirmed — the model repeated the token we sent it",
                        new ArrayList<>(List.of(
                                "Prompt reaches " + point.describe(),
                                "Reply read from " + extractor.describe())),
                        latencyMs, requestsUsed, textA.text());
            }

            // Next best: two different questions produced two different answers, so the
            // prompt is definitely getting through even if the model ignored the token.
            if (!normalise(textA.text()).equals(normalise(textB.text()))) {
                return new Outcome(Confidence.REPLIES_DIFFER, point, extractor,
                        "Confirmed — the endpoint answered two different prompts differently",
                        new ArrayList<>(List.of(
                                "Prompt reaches " + point.describe(),
                                "Reply read from " + extractor.describe())),
                        latencyMs, requestsUsed, textA.text());
            }

            if (bestUnconfirmed == null) {
                bestUnconfirmed = extractor;
                bestUnconfirmedText = textA.text();
            }
        }

        if (bestUnconfirmed != null) {
            return new Outcome(Confidence.UNCONFIRMED, point, bestUnconfirmed,
                    "A reply was read, but it did not change when the prompt changed",
                    new ArrayList<>(List.of(
                            "Reply read from " + bestUnconfirmed.describe(),
                            "Either the prompt is not reaching the model, or this endpoint "
                                    + "answers everything the same way. A scan will run, but "
                                    + "check one request in Repeater first.")),
                    latencyMs, requestsUsed, bestUnconfirmedText);
        }

        return new Outcome(Confidence.FAILED, point, null,
                "No readable reply", new ArrayList<>(), latencyMs, requestsUsed, "");
    }

    // ------------------------------------------------------------------- helpers

    private static String describeFailure(Reply reply) {
        if (!reply.error().isEmpty()) {
            return reply.error();
        }
        if (reply.status() == 401 || reply.status() == 403) {
            return "HTTP " + reply.status() + "; the captured session has probably expired";
        }
        return "HTTP " + reply.status();
    }

    private static boolean contains(String text, String token) {
        return text.toUpperCase(Locale.ROOT).contains(token);
    }

    /**
     * Ignores whitespace and case when comparing replies. A model that pads its answer
     * differently between calls has still answered differently in substance.
     */
    private static String normalise(String text) {
        return text.replaceAll("\\s+", " ").trim().toLowerCase(Locale.ROOT);
    }

    static long median(List<Long> values) {
        if (values.isEmpty()) {
            return 0;
        }
        List<Long> sorted = new ArrayList<>(values);
        sorted.sort(Long::compare);
        return sorted.get(sorted.size() / 2);
    }

    private static List<String> merge(List<String> first, List<String> second) {
        List<String> merged = new ArrayList<>(second);
        merged.addAll(first);
        return merged;
    }
}
