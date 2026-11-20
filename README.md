# NOWAY Finder v1.0.0 — Android Mobile

NOWAY Finder as a standalone Android app: domain/subdomain discovery, related-host evidence, CDN identification and complete exports, running entirely on the phone.

## What it is

The Finder is a Python engine (domain discovery from public records, DNS/HTTP/TLS verification, evidence-backed CDN labels, CSV/TXT/JSON/ZIP exports) with a local web workspace. This Android app embeds that Python engine with Chaquopy and shows the workspace inside the app — no Termux, no computer, no account.

## How it works

- Opening the app starts the Finder server on the phone itself (`http://127.0.0.1:8765`, loopback only — nothing leaves the phone except the discovery requests you start).
- The Dashboard, Finder, Results, History and Settings screens are the same workspace as the desktop version.
- Findings are stored in the app's private storage (`finder.sqlite3`); exports open in the browser to download.

## Download

- `NOWAY-Finder-v1.0.0-Android.apk` — native Android 7.0+ application.
- `SHA256SUMS-Android.txt` — SHA-256 hash for the APK.

The APK is GitHub Actions debug-signed for direct sideloading with a pinned debug key, so future builds install as updates.

## What is new in this first Android build

- Finder 1.0.0 Python engine, unchanged, embedded with Chaquopy (Python 3.11).
- Android DNS fallback: Android has no `/etc/resolv.conf`, so when dnspython finds no system nameserver the app falls back to 1.1.1.1 / 8.8.8.8 for DNS verification.
- Export downloads open in the browser to save the file.

> Use only on systems, domains and address space you own or have explicit permission to test.
