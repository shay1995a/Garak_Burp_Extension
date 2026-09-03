# garak Bridge

[![build](https://github.com/shay1995a/Garak_Burp_Extension/actions/workflows/build.yml/badge.svg)](https://github.com/shay1995a/Garak_Burp_Extension/actions/workflows/build.yml)
[![licence: Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](LICENSE)

A Burp Suite extension for running [garak](https://garak.ai)'s LLM vulnerability probes
against a chat feature you captured in Burp.

Right-click a chat request → the extension works out the rest. It reads where the message
goes and where the reply comes back, offers a cheap check that *proves* it got that right
against the live endpoint, then recommends a scan. Every adversarial request goes out
through Burp's own HTTP stack, so it lands in your history — and every finding opens as the
exchange that produced it.

---

## Why a bridge

garak's `RestGenerator` makes one stateless HTTP call per prompt, built from a `$INPUT`
string template. Real chat features are not that: they stream, they carry conversation ids,
they rotate CSRF tokens, some speak WebSocket. Pointing garak straight at one usually means
scoring an empty string a thousand times.

So garak never talks to your target. It talks to a loopback bridge inside Burp:

```
garak ──POST {"prompt":"..."}──▶ 127.0.0.1:<port>/garak/<token>   (the bridge, in Burp)
                                          │  inject the prompt into YOUR captured request
                                          ▼
                                api.http().sendRequest()   → Burp history, upstream proxy,
                                          │                  session rules, client TLS
                                          ▼
                                    the target chat app
                                          │  extract the reply (JSON / SSE / regex / …)
garak ◀──{"output":"..."}─────────────────┘
```

garak gets one trivial, unchanging contract. Everything messy about the real endpoint is
handled on the Burp side, where the request already lives.

---

## Requirements

| | |
|---|---|
| Burp Suite | 2023.10 or newer (Montoya API). Community works; Professional additionally gets findings pushed into the Issues view. |
| garak | Installed by you, anywhere. The extension just needs a path. |
| Building | A JDK that can target release 17. The one bundled with Burp will do. |
| Platform | Windows, Linux and macOS. See [Windows](#windows) for the build script and the one setup difference. |

### Installing garak

garak needs Python 3.11+ and pulls in torch and transformers, so budget several gigabytes.
The system Python on many distros is now 3.14, where some of those wheels do not yet exist,
so pin a 3.12 environment:

```bash
uv venv --python 3.12 ~/.garak-venv
~/.garak-venv/bin/python -m pip install garak
```

Then point the extension at `~/.garak-venv/bin/garak` — or at
`~/.garak-venv/bin/python`, which it will run as `python -m garak`. Leave the path blank to
use `garak` from `PATH`.

---

## Build and load

```bash
./tools/fetch-deps.sh     # montoya-api + gson from Maven Central
./build.sh                # → build/garak-bridge.jar
```

On Windows:

```powershell
powershell -ExecutionPolicy Bypass -File .\build.ps1
```

Either script finds a JDK from `JAVA_HOME`, then `PATH`, then Burp's bundled one, and
fetches the two dependencies on first run — so both work on a machine with no Java
installed system-wide.

In Burp: **Extensions → Installed → Add → Java →** `build/garak-bridge.jar`.

A **garak** tab appears. It looks for garak on its own in the background; if it cannot find
it, the button on the Scan tab says **Set up garak** and takes you to the right place. (The
first probe imports torch, so it can take a minute.)

---

## Using it

Right-click a chat request anywhere in Burp — Proxy history, Repeater, the site map — and
choose **Send chat request to garak**. Everything after that happens on one screen, as four
steps that lead into each other. There is nothing to configure first.

```
Target: https://chat.example.com                              [ ] Advanced

 1 · Read the request                ✓  https://chat.example.com
       Prompt goes to  JSON $.messages[1].content   ·   Reply read from  JSON $.choices[0].message.content

 2 · Check it against the live endpoint   ✓  Confirmed — the model repeated the token we sent it
       Typical reply 840 ms   ·   throttled to 2 at a time, 0 ms apart

 3 · Quick test scan                 ✓  Passed — 1 finding already
       garak ran end to end against this target.

 4 · Full scan                       ▸  Ready
       Test for: [OWASP LLM01 - prompt injection ▾]  Depth: [Standard ▾]
       39 probes · up to 1,248 requests · about 11 minutes

        [  Run full scan  ▶  ]   [Stop]   ▓▓▓▓▓░░░░░  412 requests · 6 findings
```

**Step 1 happens by itself, and sends no traffic.** The extension reads the request and
works out where the message goes and where the reply comes back. It knows the common
shapes: `{"message": ...}`, an OpenAI `messages` array (it picks the last `role: "user"`
turn, not the system prompt), Anthropic, Gemini, `?q=` parameters, SSE streams, NDJSON.

**Step 2 is the suggested first move, and it costs about four requests.** This is the part
that matters, because a wrong guess in step 1 is invisible: writing the prompt into the
wrong JSON field still returns a perfectly valid 200 with a perfectly valid reply, and the
scan would run to completion scoring several thousand answers to a question nobody asked.

So the check sends two *different* harmless prompts through each candidate field and
compares the answers:

| What comes back | Verdict |
|---|---|
| the model repeats the token it was given | **Confirmed** — prompt in and reply out both proven |
| two different questions, two different answers | **Confirmed** — the prompt is definitely getting through |
| the same answer both times | **Unconfirmed** — either the prompt isn't arriving, or this endpoint answers everything alike. It says so, and lets you scan anyway |
| nothing readable | **Failed**, with the reason — an expired session is called out by name |

If the first candidate field fails, it tries the next, and settles on the one that
demonstrably works. It also times the endpoint and sets the throttle from what it measured,
so you never have to think about concurrency or delay.

**Step 3 is a real garak run at tiny scale** — a trivial probe plus a couple of the ones
your full scan will use, capped at four prompts each. Under a minute. It proves garak itself
is wired up before you commit to an hour.

**Step 4 is the full scan.** Two choices, both with sensible defaults:

- **Test for** — a preset (*OWASP LLM01 prompt injection* is the default), or *Custom
  selection…* to drive it from the Probes tab.
- **Depth** — *Quick test*, *Standard* or *Thorough*. This sets garak's
  `soft_probe_prompt_cap`, the honest way to size a run: the exact prompt count varies per
  probe and isn't knowable until garak loads them, but the cap is a hard ceiling, so the
  estimate shown is one you can trust as an upper bound.

The pre-flight dialog restates the request count and time before anything is sent, and the
run refuses to start against a host outside Burp's scope unless you override it.

### Reading the findings

Each finding is a probe/detector hit with the prompt, the model's reply, and **the real
request and response**, in Burp's own editors. Right-click → **Send request to Repeater** to
reproduce it by hand.

On Professional, **Send to Burp Issues** publishes one issue per probe/detector pair (not
per hit) with the real exchanges attached as evidence, severity from the probe's tier and
confidence from how often it fired. Also: CSV export, and garak's own HTML report.

### Advanced

Tick **Advanced** and four more tabs appear — Target, Probes, Run settings, Settings —
holding every knob: insertion points and encodings, the extraction rule and its `Suggest…`
list, the full 195-probe picker with tier and tag filters, generations, prompt caps,
concurrency, delay, jitter, retries, timeouts, the circuit breaker, and the standalone
config export. Nothing was removed; it is just out of the way.

Findings stay on the Scan tab in both modes.

## Windows

The extension itself is platform-neutral — it runs inside Burp's JVM, the bridge is a plain
loopback socket, and every path goes through `java.nio.file`. Two things do differ, and both
are handled:

**Finding garak.** `pip` on Windows installs a `garak.exe` wrapper rather than a script with
a shebang, and a PATH entry for `garak` is really `garak.exe`. So the locator searches
`PATHEXT` suffixes, and finds the interpreter three ways in order of cost: the path you
configured, a POSIX shebang, or — the Windows case — the `python.exe` sitting beside the
wrapper in `Scripts\`, or one level up for a global install.

If none of those work, it asks garak itself: `garak --list_config` prints its
`package_dir`, which needs no interpreter at all. That is what keeps the rich probe picker
(descriptions, tiers, OWASP tags) working on Windows instead of falling back to bare names
from `--list_probes`.

You can always sidestep the guessing by pointing the extension straight at
`...\venv\Scripts\python.exe`, which it runs as `python -m garak`. The Windows launcher
(`py.exe`) works too.

**Installing garak.**

```powershell
uv venv --python 3.12 $HOME\.garak-venv
$HOME\.garak-venv\Scripts\python.exe -m pip install garak
```

Point the extension at `%USERPROFILE%\.garak-venv\Scripts\garak.exe`.

**Not yet verified on Windows.** I built and tested this on Linux, so the Windows-specific
code paths above are covered by unit tests but have not been exercised against a real
Windows install. The one thing worth watching is live progress: the report tailer reads
garak's `report.jsonl` while Python is appending to it, which relies on CPython opening
files with shared access (it does) — if progress ever appears frozen while a run is clearly
working, that is the thing to look at. It opens and closes the file per poll rather than
holding a handle, precisely so it cannot block garak's writes.

The test scripts under `tools/` are bash and expect a POSIX shell; run them under WSL or
Git Bash. Nothing the extension does at runtime depends on them.

## Stateful chats

Some endpoints need something to happen before each prompt. Right-click that request and
choose **garak: add as prelude step**. It runs before every prompt (or once per run), and
whatever it captures becomes a `{{variable}}` you can use in the main request.

That covers the usual cases: minting a conversation id, harvesting a single-use CSRF token,
refreshing a short-lived bearer token.

Variables are substituted *before* the prompt is inserted, never after — garak prompts are
adversarial text that quite legitimately contains braces, and a probe payload must not be
able to address the extension's own variables.

---

## Running the same scan without Burp

**Export standalone config** on the Run tab writes a plain garak `-G` config pointing
straight at the target, optionally routed through Burp's proxy listener:

```bash
garak --target_type rest -G standalone-generator.json --probes dan
```

It also lists what that config *cannot* reproduce — streaming reassembly, preludes,
multiple insertion points — rather than quietly producing something that looks right and
tests nothing.

---

## How it talks to garak

Worth knowing if you are debugging a run.

**The bridge only ever answers 200, 429 or 204.** garak's `RestGenerator` turns any 4xx into
a `ConnectionError` and any 3xx into a `NotImplementedError`, either of which aborts the
whole run; and its retry decorator (`backoff.on_exception(backoff.fibo, …, max_value=70)`)
has no attempt or time limit, so a 5xx that never clears makes garak retry forever. The
bridge therefore does its own bounded retrying — where it can also apply your throttle — and
speaks only:

| Code | garak's reading | Used for |
|---|---|---|
| `200` | the answer | normal |
| `429` | `RateLimitHit` → Fibonacci backoff | target is rate-limiting us (capped, so a permanently limited target cannot hang the run) |
| `204` | in `skip_codes` → generation skipped | nothing usable; the run still finishes |

**Config files are JSON.** garak's `_load_config_files` tries `json.load` before falling
back to YAML, and an absolute `--config` path is used as given.

**Progress comes from tailing garak's report.** Both `report.jsonl` and `hitlog.jsonl` are
opened line-buffered, so they can be followed live. Findings are correlated back to HTTP
exchanges by prompt text, using the hit log's `attempt_idx` to pick the right send when
`generations > 1`.

**Extraction mirrors garak's own validation.** A path landing on an object or array is
rejected here for the same reason garak rejects it — it needs a single string — so a rule
that passes *Test connection* behaves the same once garak is driving it.

**`NO_PROXY` is set** on the garak subprocess, so an ambient `HTTP_PROXY` pointed at Burp
cannot loop the bridge call back through Burp.

---

## Development

```bash
./tools/run-tests.sh
```

Four suites, 189 checks, no test framework and no network:

- **jar load** — the jar as Burp's loader sees it: exactly one `BurpExtension`, constructible,
  Gson bundled, montoya-api *not* bundled (a copy would shadow Burp's own).
- **unit** — path handling, response extraction across JSON/SSE/NDJSON/regex/HTML,
  prompt and reply auto-detection, the endpoint check's verdict logic (including that it
  rejects a wrong insertion point and stays inside its request budget), auto-throttling,
  garak config generation, report decoding, Windows path and `--list_config` handling, and
  the real probe catalogue if garak is installed.
- **bridge wire** — the bridge driven by python-requests, the client garak itself uses:
  unicode, 200 KB prompts, keep-alive, concurrency, auth, and each status code.
- **garak contract** — `tools/fake_garak.py` reads the extension's generated configs the way
  garak does, drives the real bridge, and writes real-shaped reports that the real tailer
  parses. Covers everything except `api.http().sendRequest`, which cannot exist outside Burp.

For manual end-to-end testing, `tools/mock_chat_server.py` is a deliberately naive chat app
serving all four shapes — plain JSON, OpenAI, SSE, and a multi-step CSRF flow — with a model
that leaks its system prompt and complies with jailbreaks, so findings actually appear:

```bash
python3 tools/mock_chat_server.py --port 8099
curl -x http://127.0.0.1:8080 -s http://127.0.0.1:8099/api/chat \
     -H 'Content-Type: application/json' -d '{"message":"hello"}'
```

Then right-click that request in Burp and start at step 1.

### Layout

```
src/main/java/burp/garak/
  GarakExtension        entry point
  GarakContext          shared state; the only place that touches persistence
  model/                target profile, insertion point, extractor, prelude, run config
  capture/              context menu, prompt and reply auto-detection, live endpoint check
  bridge/               loopback server, request building, throttled sending, extraction
  garakproc/            locating garak, the probe catalogue, config writing, process, tailer
  ui/                   the guided Scan panel, plus the advanced sub-tabs
  issues/               findings → Burp audit issues
```

The bridge is a hand-rolled HTTP/1.1 server on a plain socket rather than
`com.sun.net.httpserver`, because the JRE bundled with Burp does not ship the
`jdk.httpserver` module — an extension importing it compiles and then fails to load.

---

## Caveats

- Some garak detectors download a model from Hugging Face on first use.
- Captured sessions expire. A 401 or 403 stops the run rather than retrying, because
  hammering an auth endpoint unattended is exactly what should not happen.
- Burp session handling rules apply to extension traffic only if **Extender** is in the
  rule's tool scope.
- Detectors are heuristics. Both false positives and false negatives happen — which is why
  every finding ships with the exchange that produced it.

## Authorised use only

This tool sends adversarial prompts — jailbreaks, prompt injections, attempts to extract
system prompts and training data — to whatever endpoint you point it at. Run it only
against systems you own or have written permission to test.

Two guardrails are built in and are meant to be read rather than clicked past: a run will
not start against a host outside Burp's target scope unless you explicitly override it, and
the pre-flight dialog states the request count and estimated duration before anything is
sent.

Findings come from heuristic detectors. Both false positives and false negatives happen,
which is why every finding ships with the request and response that produced it — verify
before you report.

## Licence

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

Third-party components, in full in [NOTICE](NOTICE):

- **Gson** (Google, Apache-2.0) — fetched at build time, shaded into the extension jar.
- **Burp Suite Montoya API** (PortSwigger) — compile-time only. Burp provides it at
  runtime and it is deliberately not bundled, so this repository does not redistribute it.
  Neither jar is committed here; `build.sh` and `build.ps1` fetch them on first run.

**garak** (NVIDIA, Apache-2.0) is neither included nor distributed with this project. The
extension drives a garak installation you provide, through its documented command line,
configuration format and report format. It is not affiliated with or endorsed by NVIDIA or
PortSwigger.

## Contributing

Issues and pull requests welcome. Before opening a PR:

```bash
./tools/run-tests.sh     # 189 checks; no network and no garak install needed
```

New behaviour should come with a check in `src/test/java/burp/garak/Tests.java`, or in
`GarakContractTest` if it touches the garak-facing contract. Anything Burp-only — anything
reaching `api.http()` — cannot be tested outside Burp; put the decision logic behind a
small interface the way `Calibrator.Sender` does, and test that.
