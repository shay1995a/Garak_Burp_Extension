#!/usr/bin/env bash
# Copyright 2026 the garak Bridge authors
# SPDX-License-Identifier: Apache-2.0
# Download the two build dependencies from Maven Central into lib/.
#   montoya-api : Burp extension API, compile-time only (Burp provides it at runtime)
#   gson        : JSON parsing, shaded into the extension jar
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p lib

fetch() {
    local path=$1 dest=$2
    [[ -f "$dest" ]] && { echo "have    $dest"; return; }
    echo "fetch   $dest"
    curl -fsSL --retry 3 -o "$dest" "https://repo1.maven.org/maven2/$path"
}

fetch "net/portswigger/burp/extensions/montoya-api/2026.7/montoya-api-2026.7.jar" \
      "lib/montoya-api-2026.7.jar"
fetch "com/google/code/gson/gson/2.14.0/gson-2.14.0.jar" \
      "lib/gson-2.14.0.jar"
