// Copyright 2026 the garak Bridge authors
// SPDX-License-Identifier: Apache-2.0

package burp.garak;

import burp.garak.bridge.BridgeServer;
import burp.garak.bridge.ExchangeRunner;
import burp.garak.model.Exchange;

/**
 * Starts the bridge with a canned handler and prints its endpoint, so the wire protocol
 * can be exercised by the same client garak uses (python-requests / urllib3).
 *
 * <p>Not part of the extension jar. Run via tools/run-tests.sh.
 */
public final class BridgeSmokeTest {

    public static void main(String[] args) throws Exception {
        BridgeServer server = new BridgeServer(message -> System.err.println("[bridge] " + message));
        server.setHandler(prompt -> {
            Exchange exchange = new Exchange(1, prompt);
            if (prompt.contains("RATELIMIT")) {
                return new ExchangeRunner.Outcome(429, "", exchange);
            }
            if (prompt.contains("SKIPME")) {
                return new ExchangeRunner.Outcome(204, "", exchange);
            }
            return new ExchangeRunner.Outcome(200, "echo:" + prompt, exchange);
        });
        server.start(0, 8);

        System.out.println(server.endpoint());
        System.out.println(server.token());
        System.out.flush();

        // Held open by the harness; killed once the client-side checks finish.
        Thread.sleep(120_000);
        server.stop();
    }
}
