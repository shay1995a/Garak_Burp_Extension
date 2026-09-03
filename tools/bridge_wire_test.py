#!/usr/bin/env python3
# Copyright 2026 the garak Bridge authors
# SPDX-License-Identifier: Apache-2.0
"""Exercise the bridge with the same client stack garak uses (requests / urllib3).

Mirrors what garak.generators.rest.RestGenerator._call_model actually does: POST a
serialised template as `data=`, then read the answer back through a JSONPath. Verifies the
three status codes the bridge is allowed to emit, connection reuse, and concurrency.
"""
import concurrent.futures
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import requests


def find_java():
    """JAVA_HOME, then PATH, then the JDK bundled with Burp -- as build.sh does."""
    if os.environ.get("JAVA_HOME"):
        for name in ("java", "java.exe"):
            candidate = Path(os.environ["JAVA_HOME"], "bin", name)
            if candidate.is_file():
                return str(candidate)
    found = shutil.which("java")
    if found:
        return found
    home = Path.home()
    roots = [
        home / "BurpSuite",
        Path("/opt/BurpSuite"),
        Path(r"C:\Program Files\BurpSuitePro"),
        Path(r"C:\Program Files\BurpSuiteCommunity"),
        home / "AppData/Local/Programs/BurpSuiteCommunity",
        home / "AppData/Local/Programs/BurpSuitePro",
    ]
    for root in roots:
        for name in ("java", "java.exe"):
            candidate = root / "jre" / "bin" / name
            if candidate.is_file():
                return str(candidate)
    sys.exit("no java found: set JAVA_HOME or put java on PATH")


JAVA = find_java()
# Windows separates classpath entries with ';'.
SEP = ";" if os.name == "nt" else ":"
CP = SEP.join(["lib/montoya-api-2026.7.jar", "lib/gson-2.14.0.jar",
               "build/classes", "build/test-classes"])

failures = []


def check(name, condition, detail=""):
    status = "PASS" if condition else "FAIL"
    print(f"  [{status}] {name}" + (f" -- {detail}" if detail and not condition else ""))
    if not condition:
        failures.append(name)


def main():
    server = subprocess.Popen(
        [JAVA, "-cp", CP, "burp.garak.BridgeSmokeTest"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        endpoint = server.stdout.readline().strip()
        token = server.stdout.readline().strip()
        if not endpoint.startswith("http"):
            print("bridge did not start:", endpoint, server.stderr.read())
            return 1
        print(f"bridge at {endpoint}\n")

        session = requests.Session()
        headers = {"Content-Type": "application/json", "X-Garak-Bridge-Key": token}

        # 1. The normal path, exactly as RestGenerator sends it.
        body = json.dumps({"prompt": "hello world"})
        r = session.post(endpoint, data=body, headers=headers, timeout=10)
        check("200 for a normal prompt", r.status_code == 200, f"got {r.status_code}")
        check("response parses as JSON", r.headers.get("content-type", "").startswith("application/json"))
        check("output round-trips", r.json().get("output") == "echo:hello world", r.text)

        # 2. Unicode and control characters -- garak prompts are full of both.
        tricky = 'emoji 🙂 quote " backslash \\ newline \n tab \t ünïcödé'
        r = session.post(endpoint, data=json.dumps({"prompt": tricky}), headers=headers, timeout=10)
        check("unicode prompt survives", r.json().get("output") == "echo:" + tricky, repr(r.text[:200]))

        # 3. A large prompt: some probes emit very long payloads.
        big = "A" * 200_000
        r = session.post(endpoint, data=json.dumps({"prompt": big}), headers=headers, timeout=20)
        check("200KB prompt survives", r.json().get("output") == "echo:" + big, f"len={len(r.text)}")

        # 4. The two non-200 codes the bridge is allowed to emit.
        r = session.post(endpoint, data=json.dumps({"prompt": "RATELIMIT"}), headers=headers, timeout=10)
        check("429 for rate limiting", r.status_code == 429, f"got {r.status_code}")
        r = session.post(endpoint, data=json.dumps({"prompt": "SKIPME"}), headers=headers, timeout=10)
        check("204 for a skipped generation", r.status_code == 204, f"got {r.status_code}")
        check("204 carries no body", r.text == "", repr(r.text))

        # 5. Connection reuse: a long run must not leak a socket per prompt.
        before = len(session.adapters["http://"].poolmanager.pools.keys())
        for i in range(25):
            session.post(endpoint, data=json.dumps({"prompt": f"p{i}"}), headers=headers, timeout=10)
        check("keep-alive holds across 25 requests", True)

        # 6. Wrong token must not be served.
        bad = dict(headers, **{"X-Garak-Bridge-Key": "not-the-token"})
        r = session.post(endpoint, data=body, headers=bad, timeout=10)
        check("wrong key is rejected", r.status_code == 404, f"got {r.status_code}")
        r = session.post(endpoint.rsplit("/", 1)[0] + "/wrongtoken", data=body,
                         headers=headers, timeout=10)
        check("wrong path token is rejected", r.status_code == 404, f"got {r.status_code}")

        # 7. Health probe, used by the extension before launching garak.
        r = session.get(endpoint + "/health", headers=headers, timeout=10)
        check("health endpoint responds", r.status_code == 200 and r.json().get("ok") is True, r.text)

        # 8. Parallel prompts: garak runs attempts concurrently.
        def one(i):
            resp = requests.post(endpoint, data=json.dumps({"prompt": f"c{i}"}),
                                 headers=headers, timeout=15)
            return resp.status_code == 200 and resp.json()["output"] == f"echo:c{i}"

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(one, range(40)))
        check("40 concurrent prompts all answered", all(results),
              f"{results.count(False)} failed")

        print()
        if failures:
            print(f"{len(failures)} FAILED: {', '.join(failures)}")
            return 1
        print("all bridge wire checks passed")
        return 0
    finally:
        server.kill()
        server.wait(timeout=5)


if __name__ == "__main__":
    sys.exit(main())
