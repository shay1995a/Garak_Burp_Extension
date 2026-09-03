// Copyright 2026 the garak Bridge authors
// SPDX-License-Identifier: Apache-2.0

package burp.garak.model;

import java.util.ArrayList;
import java.util.List;

/**
 * A request run before the prompt-carrying one, so that stateful chats work.
 *
 * <p>Covers the cases garak's own REST generator cannot reach: creating a conversation and
 * carrying its id, harvesting a CSRF token, refreshing a short-lived bearer token. Values
 * pulled out by {@link Capture} become {@code {{name}}} variables usable in later prelude
 * steps and in the main request.
 */
public class PreludeStep {

    /** A value lifted out of this step's response and bound to a variable name. */
    public static class Capture {
        /** Variable name, referenced elsewhere as {@code {{name}}}. */
        public String name = "";

        /** How to pull the value out of this step's response. */
        public ResponseExtractor from = ResponseExtractor.jsonPath("$.id");

        public Capture() {
        }

        public Capture(String name, ResponseExtractor from) {
            this.name = name;
            this.from = from;
        }

        public Capture copy() {
            return new Capture(name, from.copy());
        }
    }

    /** How often the step runs. */
    public enum Cadence {
        /** Once when the run starts -- a login, or a token that outlives the run. */
        PER_RUN,
        /** Before every prompt -- a fresh conversation id, or a single-use CSRF token. */
        PER_PROMPT
    }

    public String name = "prelude";

    public Cadence cadence = Cadence.PER_PROMPT;

    /** Base64 of the raw request bytes. */
    public String requestBase64 = "";

    /** Empty means "same service as the main request". */
    public String host = "";
    public int port;
    public boolean secure;

    public List<Capture> captures = new ArrayList<>();

    /** Response codes that mean the step worked. Anything else fails the prompt. */
    public List<Integer> okCodes = new ArrayList<>(List.of(200, 201, 204));

    public PreludeStep copy() {
        PreludeStep clone = new PreludeStep();
        clone.name = name;
        clone.cadence = cadence;
        clone.requestBase64 = requestBase64;
        clone.host = host;
        clone.port = port;
        clone.secure = secure;
        clone.okCodes = new ArrayList<>(okCodes);
        clone.captures = new ArrayList<>();
        for (Capture capture : captures) {
            clone.captures.add(capture.copy());
        }
        return clone;
    }

    @Override
    public String toString() {
        return name + " (" + cadence.name().toLowerCase().replace('_', ' ') + ", "
                + captures.size() + " capture" + (captures.size() == 1 ? "" : "s") + ")";
    }
}
