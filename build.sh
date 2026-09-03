#!/usr/bin/env bash
# Copyright 2026 the garak Bridge authors
# SPDX-License-Identifier: Apache-2.0
# Build the garak Bridge Burp extension.
#
# Needs a JDK that can target release 17. Looks at $JAVA_HOME, then javac on
# PATH, then the JDK bundled with Burp Suite -- so this builds on a machine
# with no Java installed system-wide.
set -euo pipefail

cd "$(dirname "$0")"

MONTOYA=lib/montoya-api-2026.7.jar
GSON=lib/gson-2.14.0.jar
OUT=build/garak-bridge.jar
CLASSES=build/classes

find_javac() {
    if [[ -n "${JAVA_HOME:-}" && -x "$JAVA_HOME/bin/javac" ]]; then
        echo "$JAVA_HOME/bin/javac"; return
    fi
    if command -v javac >/dev/null 2>&1; then
        command -v javac; return
    fi
    for burp in "$HOME/BurpSuite/jre/bin/javac" /opt/BurpSuite/jre/bin/javac; do
        [[ -x "$burp" ]] && { echo "$burp"; return; }
    done
    echo "no javac found: install a JDK (e.g. pacman -S jdk21-openjdk) or set JAVA_HOME" >&2
    exit 1
}

JAVAC=$(find_javac)
echo "javac:  $JAVAC ($("$JAVAC" -version 2>&1))"

# Dependencies are not committed -- montoya-api is PortSwigger's to distribute -- so a
# fresh clone fetches them on first build.
if [[ ! -f "$MONTOYA" || ! -f "$GSON" ]]; then
    bash tools/fetch-deps.sh
fi
for jar in "$MONTOYA" "$GSON"; do
    [[ -f "$jar" ]] || { echo "could not obtain $jar" >&2; exit 1; }
done

rm -rf "$CLASSES"
mkdir -p "$CLASSES"

mapfile -t SOURCES < <(find src/main/java -name '*.java')
echo "source: ${#SOURCES[@]} files"

"$JAVAC" \
    --release 17 \
    -Xlint:all -Xlint:-serial -Xlint:-this-escape -Xlint:-classfile \
    -cp "$MONTOYA:$GSON" \
    -d "$CLASSES" \
    "${SOURCES[@]}"

# Gson is shaded in; Montoya is provided by Burp at runtime and must not be.
python3 tools/mkjar.py "$OUT" "$CLASSES" "$GSON"
echo "built:  $(pwd)/$OUT"
echo
echo "Load it in Burp: Extensions -> Installed -> Add -> Java -> $(pwd)/$OUT"
