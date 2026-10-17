# od-clone.sh

An interactive, OPSEC-aware tool for cloning open directories over Tor, a proxy chain, or an already-active VPN — built for threat research, IOC collection, and preserving adversary-staged infrastructure before it disappears.

No flags, no arguments. Run it and answer the prompts.

```
./od-clone.sh
```

## Why this exists

Open directories (misconfigured web servers exposing attacker tooling, exfiltrated data, or staging infrastructure) are frequently short-lived. By the time you've confirmed something is worth pulling, manually clicking through `wget -r` runs, remembering to check your VPN/proxy, and tracking what changed between visits, the directory is often already gone — or you've hit it without adequate cover.

`od-clone.sh` is built around three things that matter for this specific job:

- **You never accidentally hit the target from your real IP — and the tool proves it, not just assumes it.** Whether you're on a VPN or using torsocks/proxychains, it pulls your actual egress IP and either has you visually confirm it (VPN) or automatically compares it against your unwrapped IP (proxy wrappers) before letting you proceed.
- **Every file has a chain-of-custody record.** A per-target `manifest.json` captures the URL, local path, SHA-256 hash, size, and timestamp for every file — useful if this ever needs to go to law enforcement or a victim notification.
- **Nothing happens without confirmation.** Every step — VPN/proxy verification, size estimate before download, hash re-verification — is an explicit prompt. There's no "skip checks" mode, on purpose.

## Features

- **VPN or proxy-wrapped**, your choice:
  - **VPN path** — pulls your current public IP/geolocation so you can visually confirm the egress isn't your real one before touching the target.
  - **torsocks/proxychains path** — goes a step further than a visual check: automatically fetches your egress IP both wrapped and unwrapped, and compares them. If they match, the wrapper isn't actually rerouting traffic (a real failure mode — Tor not running, a proxychains config pointing at a dead proxy) and you get an explicit **DANGER** warning before being allowed to proceed. This catches silent fail-open scenarios a visual check alone would miss.
- **Recursive directory discovery** — walks nested subdirectories automatically, following standard Apache/nginx-style autoindex listings.
- **Concurrent downloads** with a configurable worker count and a live progress bar.
- **Pre-download size estimate**, parsed from the listing pages already fetched during discovery — no extra requests to the target just to estimate size.
- **Multiple ports on one host in a single run** (e.g. `8080,8081,9000-9005`), each cloned into its own subdirectory.
- **JSON manifest per target** with SHA-256 hashes, sizes, and timestamps for every file.
- **Incremental re-cloning** — re-running against a target you've already cloned only pulls new files by default, and reports what's new vs. no longer listed since your last visit (`changes_<timestamp>.json`).
- **Opt-in hash re-verification** — for files you've already downloaded, re-fetch and SHA-256-compare against the live server to catch content that changed under the same filename (off by default; only touches files that already exist locally).
- **Graceful Ctrl+C handling** — kills every in-flight download (not just the coordinator process) and finalizes a partial manifest instead of leaving things half-written.
- **Real failure diagnostics** — every failed download attempt logs the actual HTTP status, not just a generic "failed." If every file in a batch fails, it breaks down *why* (403 wall, rate limiting, dead target, etc.) instead of leaving you to guess.
- **Automatic retry logic that knows when to give up** — permanent rejections (401/403/404/410) stop retrying immediately; transient failures (5xx, timeouts) get the full retry budget.

## Requirements

- macOS or Linux (bash)
- `curl` and `wget`
- **Either** `torsocks` and/or `proxychains` **or** an already-active VPN
- `sha256sum` (Linux) or `shasum` (macOS) — optional, only needed for the hash-verification feature

```bash
# macOS
brew install wget curl torsocks proxychains-ng

# Debian/Ubuntu
apt install wget curl torsocks proxychains4
```

## Usage

Just run it:

```bash
./od-clone.sh
```

You'll be walked through, in order:

1. **VPN check** — are you already on a VPN?
   - **Yes**: pulls your public IP/geolocation and asks you to visually confirm it's your VPN exit, not your real location.
   - **No**: detects torsocks/proxychains and lets you pick one, then **automatically verifies** the wrapper is actually rerouting traffic by comparing your direct and wrapped egress IPs — refusing to silently proceed if they match.
2. **Target** — a bare host/IP (you'll then be asked for port(s)), or a full URL if you want to target a specific subdirectory directly.
3. **Filename/pattern exclusions** — skip anything known to hang or that isn't a real file.
4. **Concurrency** — how many files to pull in parallel.
5. **Hash verification** — opt in if you want previously-downloaded files re-checked against the live server for content changes.
6. **Output directory** — where the clone goes.
7. **Size estimate + confirmation** — before any actual downloading starts.

Output lands in a directory per target:

```
od-clone_<host>_<timestamp>/
└── port_8080/
    ├── manifest.json          # url, local_path, sha256, size, timestamp per file (cumulative across runs)
    ├── .od-clone.log           # per-attempt log: real HTTP status, retries, failures
    └── files/
        └── <cloned files, preserving remote directory structure>
```

Cloned content lives under `files/` so a file the server happens to serve as `manifest.json` (or `.od-clone.log`) can never overwrite the tool's own records.

Re-run it against the same host/output later and it'll only pull what's new, and drop a `changes_<timestamp>.json` showing exactly what appeared or disappeared since your last pass. Files that failed on a previous run are retried automatically, and `manifest.json` keeps accumulating — entries for files you already have are carried forward, not replaced.

> **Upgrading from an older version:** clones made before the `files/` layout kept their files directly in the target directory. Re-running with hash verification enabled will re-download those into `files/`.

## A note on the proxy verification

Most tools that wrap `curl`/`wget` in torsocks or proxychains just assume the wrapper is working. It's a reasonable assumption right up until it's wrong — a stale proxychains config pointing at a dead SOCKS proxy, or torsocks silently no-op'ing because the Tor daemon isn't actually running, can mean your traffic goes out **unwrapped, under your real IP**, with no error at all.

`od-clone.sh` doesn't assume: it does two egress-IP lookups — one direct, one through the wrapper you just selected — and compares them. Same IP means the wrapper isn't doing anything, and you get a hard warning before continuing. This happens automatically the moment you pick torsocks or proxychains; there's no separate step to remember.

## A note on the failure diagnostics

If a download fails, `curl` only reports a nonzero exit code for connection-level problems — a 403 or 404 page comes back as a normal, "successful" response as far as the exit code is concerned. This tool checks the actual HTTP status on every attempt, so a permanently-rejected file (401/403/404/410) stops retrying immediately instead of burning your full retry budget on something that was never going to succeed, and a batch where *everything* failed gets a real breakdown of what happened instead of a silent pile of "skipped."

## Safety / OPSEC

- The tool will not proceed against a target without either a confirmed VPN or a verified-working proxy wrapper, short of you explicitly overriding that and confirming you understand the risk.
- Geolocation checks use `ipinfo.io`, `ifconfig.co`, and `api.ipify.org`. The VPN path and the direct half of the proxy comparison hit these services unwrapped by design — they're checking your actual egress, not the target, so this never exposes anything to the infrastructure you're investigating.
- The directory listing is treated as untrusted input. Entries containing a `..` path segment or control characters are ignored (with a warning), so a hostile server can't make the tool write outside the output directory.
- Downloads go to `<name>.part` and are renamed only once the transfer completes, so an interrupted run never leaves a truncated file that looks finished. Large files aren't subject to a fixed time limit — a transfer is only aborted if it stalls (under 1 KB/s for 60 seconds) — and retries within a run resume where they left off. Leftover `.part` files from an interrupted run are discarded and re-downloaded from scratch, since the remote file may have changed.
- Cloned files are untrusted adversary content. Nothing is ever executed, but handle the output directory accordingly (isolated VM or analysis host, no auto-open, no execute bits).
- The manifest's SHA-256 hashes and timestamps are meant to support downstream chain-of-custody needs (e.g. handing findings to law enforcement or notifying an affected party) — treat `manifest.json` as part of the evidence, not just metadata.

## Known limitations

- HTTP directory listings only — no support for FTP, SMB, or non-standard listing formats (custom templates, JSON-based indexes).
- Host-plus-port mode always builds `http://` URLs; to target HTTPS on a nonstandard port, enter the full URL (`https://host:port/`) instead.
- Recursion depth is bounded only by your system's process/stack limits — a pathologically deep directory tree could theoretically hit that ceiling.
- The proxy-route check confirms the wrapper changes your IP, not that it's routing through the specific network path you expect (e.g. a specific Tor exit country) — it catches "not working at all," not "working differently than intended."

## Companion tool: ioc-extract.py

A Python script meant to run against a completed clone's output directory — walks every file (filenames and content) and pulls out:

- Every public IPv4 address (private/loopback/CGNAT/reserved ranges and known certificate/LDAP OID false-positives filtered out), sorted by how many files it showed up in.
- Hardcoded secrets: cloud provider keys, NTLM/Kerberoast hash formats, mimikatz-style output, NetExec/CrackMapExec success lines, DB connection strings, private key blocks, and more.

```bash
python3 ioc-extract.py <clone_output_dir>
```

## Disclaimer

For authorized security research, threat intelligence collection, and defensive use only. You are responsible for ensuring you have authorization to access and collect from any target you point this at.
