// Copyright 2026 the garak Bridge authors
// SPDX-License-Identifier: Apache-2.0

package burp.garak.model;

import burp.api.montoya.http.message.HttpRequestResponse;

/**
 * One prompt's trip to the target, recorded by the bridge.
 *
 * <p>Holding the live {@link HttpRequestResponse} is what lets a finding open the real
 * request and response in Burp's own editors, and be sent to Repeater. Long runs keep
 * thousands of these, so the bridge stores them via {@code copyToTempFile()} and lets Burp
 * page them to disk rather than holding every body on the heap.
 */
public class Exchange {

    public enum Status {
        OK,
        /** Extraction produced nothing usable; reported to garak as a skipped generation. */
        SKIPPED,
        /** Target rate-limited us; garak was told to back off. */
        RATE_LIMITED,
        /** Prelude, transport or extraction failed. */
        FAILED
    }

    public final long id;
    public final String prompt;

    public String output = "";
    public Status status = Status.OK;
    public String error = "";
    public long durationMs;
    public long timestamp = System.currentTimeMillis();
    public int httpStatus;

    /** Null when the request never made it out (a prelude failure, say). */
    public HttpRequestResponse requestResponse;

    /** Which probe was running when this went out, filled in from run progress. */
    public String probe = "";

    public Exchange(long id, String prompt) {
        this.id = id;
        this.prompt = prompt;
    }

    public boolean hasTraffic() {
        return requestResponse != null;
    }

    public String describe() {
        return "#" + id + "  " + status + (httpStatus > 0 ? "  HTTP " + httpStatus : "")
                + "  " + durationMs + "ms";
    }
}
