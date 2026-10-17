# dirsnatch.sh

Interactive, OPSEC-aware cloning of open directories over Tor, a proxy chain, or a VPN. Built for threat research and for preserving adversary infrastructure before it disappears.

No flags. Run it and answer the prompts.

```
./dirsnatch.sh
```

## Why

Open directories (exposed attacker tooling, exfiltrated data, staging servers) are short-lived. By the time you've checked your VPN, run `wget -r`, and worked out what changed since your last visit, the directory is often gone, or you've touched it without cover.

`dirsnatch.sh` is built around three guarantees:

- **Your real IP never reaches the target, and the tool verifies it.** On a VPN, you confirm your egress IP. With torsocks or proxychains, it compares your wrapped and unwrapped IPs and refuses to continue silently if they match.
- **Every file has a chain-of-custody record.** `manifest.json` stores the URL, local path, SHA-256, size, and timestamp for each file.
- **Nothing runs without your confirmation.** There is no skip-checks mode, on purpose.

## Features

- **Proxy verification.** A wrapper that fails open (Tor not running, proxychains pointed at a dead proxy) sends traffic under your real IP with no error. The tool catches this by comparing egress IPs and warns you before proceeding.
- **Recursive discovery** of Apache/nginx-style autoindex listings.
- **Concurrent downloads** with a live progress bar.
- **Size estimate** before downloading, taken from listing pages already fetched.
- **Multiple ports per host** in one run (`8080,8081,9000-9005`), each in its own subdirectory.
- **Incremental re-cloning.** Re-runs pull only new files and write a `changes_<timestamp>.json` of what appeared or disappeared. Files that failed before are retried.
- **Optional hash re-verification** of existing files against the live server, to catch content changed under the same filename.
- **Clean Ctrl+C.** Kills every in-flight download and writes a partial manifest.
- **Useful failure output.** Logs the real HTTP status per attempt, stops retrying permanent rejections (401/403/404/410), and explains why when a whole batch fails.

## Requirements

- macOS or Linux (bash)
- `curl` and `wget`
- `torsocks` and/or `proxychains`, or an active VPN
- `sha256sum` or `shasum` (optional, for hash verification)

```bash
# macOS
brew install wget curl torsocks proxychains-ng

# Debian/Ubuntu
apt install wget curl torsocks proxychains4
```

## Usage

You'll be asked, in order:

1. **VPN?** If yes, it shows your public IP and location for you to confirm. If no, you pick torsocks or proxychains and it verifies the route.
2. **Target.** A host/IP (then ports), or a full URL for a specific subdirectory.
3. **Exclusions.** Filenames or patterns to skip.
4. **Concurrency.** Parallel downloads.
5. **Hash verification.** Re-check files you already have.
6. **Output directory.**
7. **Confirmation**, after the size estimate and before anything downloads.

Output:

```
dirsnatch_<host>_<timestamp>/
└── port_8080/
    ├── manifest.json     # cumulative record of every file
    ├── .dirsnatch.log    # per-attempt HTTP status, retries, failures
    └── files/            # cloned content, remote structure preserved
```

Content lives under `files/` so a remote file named `manifest.json` can't overwrite the tool's own records. Re-runs add to `manifest.json` rather than replacing it.

> **Upgrading:** clones from older versions keep files in the target root. Re-running them with hash verification on re-downloads those files into `files/`.

## Safety

- Without a confirmed VPN or verified proxy, the tool won't proceed unless you explicitly override it.
- Listings are treated as untrusted. Entries with a `..` path segment or control characters are ignored, so a hostile server can't write outside the output directory.
- Downloads go to `<name>.part` and are renamed only when complete, so an interrupted run never leaves a truncated file that looks finished. Transfers are aborted only if they stall (under 1 KB/s for 60 seconds), and retries resume. Leftover `.part` files are discarded on the next run.
- Cloned files are untrusted. Nothing is executed, but keep them on an isolated analysis host with no auto-open and no execute bits.
- IP lookups use `ipinfo.io`, `ifconfig.co`, and `api.ipify.org`, unwrapped by design. They check your egress, never the target.
- Treat `manifest.json` as evidence, not metadata.

## Limitations

- HTTP autoindex listings only. No FTP, SMB, or custom or JSON indexes.
- Host-plus-port mode builds `http://` URLs. For HTTPS, enter the full URL.
- Directory recursion depth is unbounded.
- The proxy check confirms your IP changed, not that traffic takes the path you intended (for example a specific Tor exit country).

## Disclaimer

For authorized security research, threat intelligence, and defensive use only. You are responsible for having authorization to access and collect from any target.
