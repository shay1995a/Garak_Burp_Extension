// Copyright 2026 the garak Bridge authors
// SPDX-License-Identifier: Apache-2.0

package burp.garak.model;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

/**
 * Everything needed to turn a garak prompt into a request against one chat endpoint,
 * and to turn the answer back into text.
 *
 * <p>This is the unit the user captures, tunes and saves. Request and response bytes are
 * held base64-encoded so the whole profile round-trips through Burp's project persistence
 * as JSON.
 */
public class TargetProfile {

    public enum Transport {
        HTTP,
        /** Prompt and reply travel over a WebSocket opened from the captured upgrade request. */
        WEBSOCKET
    }

    public String id = UUID.randomUUID().toString();

    public String name = "chat endpoint";

    public Transport transport = Transport.HTTP;

    public String host = "";
    public int port = 443;
    public boolean secure = true;

    /** Base64 of the captured request bytes -- the template every prompt is spliced into. */
    public String requestBase64 = "";

    /** Base64 of the captured response, kept for the editor view and re-detection. */
    public String responseBase64 = "";

    public List<InsertionPoint> insertionPoints = new ArrayList<>();

    public ResponseExtractor extractor = new ResponseExtractor();

    public List<PreludeStep> prelude = new ArrayList<>();

    /**
     * Headers dropped before replay. Conditional and caching headers are the usual
     * culprits: a captured {@code If-None-Match} turns every probe into a 304 with no body.
     */
    public List<String> dropHeaders = new ArrayList<>(List.of("If-None-Match", "If-Modified-Since"));

    /** Free-text note, shown in the profile list. */
    public String notes = "";

    // ----------------------------------------------------- calibration outcome

    /**
     * Result of the last live check, as a {@code Calibrator.Confidence} name. Empty means
     * the target has never been checked against the endpoint, only guessed at.
     */
    public String checkedConfidence = "";

    /** One-line summary of the last check, for the status line. */
    public String checkedSummary = "";

    /** Measured reply time, which drives the auto-throttle. */
    public long measuredLatencyMs;

    /** When the last check ran; 0 if never. */
    public long checkedAt;

    /** When a quick test scan last completed for this target; 0 if never. */
    public long smokeTestedAt;

    /** One-line summary of that quick test scan. */
    public String smokeSummary = "";

    /** True once the endpoint has confirmed the prompt actually reaches the model. */
    public boolean isProven() {
        return "ECHOED".equals(checkedConfidence) || "REPLIES_DIFFER".equals(checkedConfidence);
    }

    /** True once a check has run and produced something usable. */
    public boolean isChecked() {
        return checkedAt > 0 && !"FAILED".equals(checkedConfidence)
                && !checkedConfidence.isEmpty();
    }

    // ------------------------------------------------------------ conversions

    public HttpService service() {
        return HttpService.httpService(host, port, secure);
    }

    public byte[] requestBytes() {
        return decode(requestBase64);
    }

    public byte[] responseBytes() {
        return decode(responseBase64);
    }

    /** The captured request, rebuilt as a live Montoya object. */
    public HttpRequest request() {
        return HttpRequest.httpRequest(service(), ByteArray.byteArray(requestBytes()));
    }

    /** The captured response, or null when the profile was built from a request alone. */
    public HttpResponse response() {
        byte[] bytes = responseBytes();
        return bytes.length == 0 ? null : HttpResponse.httpResponse(ByteArray.byteArray(bytes));
    }

    public void setRequest(HttpRequest request) {
        HttpService service = request.httpService();
        if (service != null) {
            host = service.host();
            port = service.port();
            secure = service.secure();
        }
        requestBase64 = encode(request.toByteArray().getBytes());
    }

    public void setResponse(HttpResponse response) {
        responseBase64 = response == null ? "" : encode(response.toByteArray().getBytes());
    }

    public String baseUrl() {
        String scheme = secure ? "https" : "http";
        boolean defaultPort = (secure && port == 443) || (!secure && port == 80);
        return scheme + "://" + host + (defaultPort ? "" : ":" + port);
    }

    /** True once the profile has enough detail to actually run. */
    public boolean isRunnable() {
        return !host.isEmpty() && !requestBase64.isEmpty() && !insertionPoints.isEmpty();
    }

    /** Why {@link #isRunnable()} is false, for display next to a disabled Run button. */
    public String blocker() {
        if (host.isEmpty() || requestBase64.isEmpty()) {
            return "no request captured";
        }
        if (insertionPoints.isEmpty()) {
            return "no insertion point set - select the prompt text in the request and mark it";
        }
        return "";
    }

    public TargetProfile copy() {
        TargetProfile clone = new TargetProfile();
        clone.id = UUID.randomUUID().toString();
        clone.name = name;
        clone.transport = transport;
        clone.host = host;
        clone.port = port;
        clone.secure = secure;
        clone.requestBase64 = requestBase64;
        clone.responseBase64 = responseBase64;
        clone.extractor = extractor.copy();
        clone.notes = notes;
        clone.dropHeaders = new ArrayList<>(dropHeaders);
        clone.checkedConfidence = checkedConfidence;
        clone.checkedSummary = checkedSummary;
        clone.measuredLatencyMs = measuredLatencyMs;
        clone.checkedAt = checkedAt;
        clone.smokeTestedAt = smokeTestedAt;
        clone.smokeSummary = smokeSummary;
        clone.insertionPoints = new ArrayList<>();
        for (InsertionPoint point : insertionPoints) {
            clone.insertionPoints.add(point.copy());
        }
        clone.prelude = new ArrayList<>();
        for (PreludeStep step : prelude) {
            clone.prelude.add(step.copy());
        }
        return clone;
    }

    private static String encode(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    private static byte[] decode(String text) {
        if (text == null || text.isEmpty()) {
            return new byte[0];
        }
        try {
            return Base64.getDecoder().decode(text);
        } catch (IllegalArgumentException e) {
            return new byte[0];
        }
    }

    @Override
    public String toString() {
        return name + "  [" + host + "]";
    }
}
