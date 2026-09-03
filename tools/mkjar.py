#!/usr/bin/env python3
# Copyright 2026 the garak Bridge authors
# SPDX-License-Identifier: Apache-2.0
"""Package compiled classes plus shaded dependencies into a Burp extension jar.

Used instead of the JDK `jar` tool, which is absent from the JRE bundled with
Burp Suite. A jar is a zip with a manifest, so zipfile is enough.
"""
import sys
import zipfile
from pathlib import Path

MANIFEST = "Manifest-Version: 1.0\r\nCreated-By: garak-bridge build\r\n\r\n"

# Entries that must not survive into a merged jar: another jar's manifest, its
# signatures, and module descriptors that would no longer describe the contents.
def _skip(name: str) -> bool:
    if name.endswith("/"):
        return True
    if name == "META-INF/MANIFEST.MF" or name.startswith("META-INF/versions/"):
        return True
    if name.startswith("META-INF/") and name.rsplit(".", 1)[-1] in ("SF", "DSA", "RSA"):
        return True
    return name == "module-info.class"


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: mkjar.py <out.jar> <classes-dir> [dep.jar ...]", file=sys.stderr)
        return 2

    out, classes = Path(sys.argv[1]), Path(sys.argv[2])
    deps = [Path(p) for p in sys.argv[3:]]
    out.parent.mkdir(parents=True, exist_ok=True)

    seen = set()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as jar:
        jar.writestr("META-INF/MANIFEST.MF", MANIFEST)
        seen.add("META-INF/MANIFEST.MF")

        for path in sorted(classes.rglob("*")):
            if path.is_file():
                name = str(path.relative_to(classes))
                jar.write(path, name)
                seen.add(name)

        for dep in deps:
            with zipfile.ZipFile(dep) as src:
                for name in src.namelist():
                    if _skip(name) or name in seen:
                        continue
                    jar.writestr(name, src.read(name))
                    seen.add(name)

    print(f"{out}  ({out.stat().st_size // 1024} KiB, {len(seen)} entries)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
