#!/usr/bin/env bash
# Copyright 2026 the garak Bridge authors
# SPDX-License-Identifier: Apache-2.0
# Build, then run the offline test suite and the bridge wire test.
#
# The unit tests cover everything that does not need a live Burp: path handling,
# response extraction, garak config generation and report decoding. The wire test
# drives the bridge with python-requests, which is the client garak itself uses.
set -euo pipefail
cd "$(dirname "$0")/.."

MONTOYA=lib/montoya-api-2026.7.jar
GSON=lib/gson-2.14.0.jar
CACHE=${GARAK_PLUGIN_CACHE:-}

find_java() {
    if [[ -n "${JAVA_HOME:-}" && -x "$JAVA_HOME/bin/java" ]]; then echo "$JAVA_HOME/bin"; return; fi
    if command -v javac >/dev/null 2>&1; then dirname "$(command -v javac)"; return; fi
    for burp in "$HOME/BurpSuite/jre/bin" /opt/BurpSuite/jre/bin; do
        [[ -x "$burp/javac" ]] && { echo "$burp"; return; }
    done
    echo "no JDK found" >&2; exit 1
}
JB=$(find_java)

bash build.sh >/dev/null
mkdir -p build/test-classes
"$JB/javac" --release 17 -nowarn \
    -cp "$MONTOYA:$GSON:build/classes" \
    -d build/test-classes $(find src/test/java -name '*.java')

# If garak is installed locally, test against its real probe catalogue.
if [[ -z "$CACHE" ]]; then
    for python in "$(command -v garak 2>/dev/null || true)" python3; do
        [[ -z "$python" ]] && continue
        found=$("$python" -c 'import garak,os;print(os.path.join(os.path.dirname(garak.__file__),"resources","plugin_cache.json"))' 2>/dev/null || true)
        [[ -n "$found" && -f "$found" ]] && { CACHE=$found; break; }
    done
fi

echo "================== jar load test =================="
"$JB/java" -cp "$MONTOYA:$GSON:build/classes:build/test-classes" burp.garak.JarLoadTest

echo
echo "=================== unit tests ==================="
"$JB/java" -cp "$MONTOYA:$GSON:build/classes:build/test-classes" burp.garak.Tests "$CACHE"

echo
echo "================ bridge wire test ================"
python3 tools/bridge_wire_test.py

echo
echo "============== garak contract test ==============="
"$JB/java" -cp "$MONTOYA:$GSON:build/classes:build/test-classes" burp.garak.GarakContractTest
