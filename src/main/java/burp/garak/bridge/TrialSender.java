// Copyright 2026 the garak Bridge authors
// SPDX-License-Identifier: Apache-2.0

package burp.garak.bridge;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.garak.capture.Calibrator;
import burp.garak.model.InsertionPoint;
import burp.garak.model.TargetProfile;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * The live half of {@link Calibrator}: sends one trial prompt through a candidate insertion
 * point and reports what came back.
 *
 * <p>Goes through {@code api.http().sendRequest} like everything else, so calibration
 * traffic appears in Burp's history alongside the scan and can be inspected afterwards.
 */
public final class TrialSender implements Calibrator.Sender {

    private final MontoyaApi api;
    private final TargetProfile profile;
    private final int timeoutMs;
    private final List<HttpRequestResponse> traffic = new ArrayList<>();

    public TrialSender(MontoyaApi api, TargetProfile profile, int timeoutMs) {
        this.api = api;
        this.profile = profile;
        this.timeoutMs = timeoutMs;
    }

    /** The exchanges this calibration produced, so the UI can show the real traffic. */
    public List<HttpRequestResponse> traffic() {
        return traffic;
    }

    @Override
    public Calibrator.Reply send(InsertionPoint point, String prompt) {
        // Build against a copy carrying only the candidate being tested, so one candidate's
        // result is never contaminated by another insertion point on the same profile.
        TargetProfile trial = profile.copy();
        trial.insertionPoints = new ArrayList<>(List.of(point));

        RequestBuilder.Built built = RequestBuilder.build(trial, prompt, Map.of());
        long started = System.currentTimeMillis();
        HttpRequestResponse exchange;
        try {
            exchange = api.http().sendRequest(built.request(),
                    RequestOptions.requestOptions().withResponseTimeout(timeoutMs));
        } catch (RuntimeException e) {
            return Calibrator.Reply.failed("could not send the request: " + e);
        }
        long latency = System.currentTimeMillis() - started;

        traffic.add(exchange);

        HttpResponse response = exchange.response();
        if (response == null) {
            return Calibrator.Reply.failed("no response within " + timeoutMs + "ms");
        }
        String contentType = response.headerValue("Content-Type");
        return new Calibrator.Reply(response.statusCode(), response.bodyToString(),
                contentType == null ? "" : contentType, latency, "");
    }
}
