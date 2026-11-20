# NOWAY Finder v1.0.0 — Android Mobile

First Android build of NOWAY Finder 1.0.0: the Python domain-discovery engine and its local web workspace, packaged as a standalone APK with Chaquopy (Python 3.11).

## Included

- Domain/subdomain discovery, related-host evidence, CDN identification and CSV/TXT/JSON/ZIP exports.
- Dashboard, Finder, Results, History and Settings, with SQLite evidence and job recovery.
- Android DNS fallback to 1.1.1.1 / 8.8.8.8 when the phone provides no system nameserver.
- Export downloads open in the browser to save the file.

## Download

- `NOWAY-Finder-v1.0.0-Android.apk` — native Android 7.0+ application.
- `SHA256SUMS-Android.txt` — SHA-256 hash for the APK.

The APK is GitHub Actions debug-signed for direct sideloading. It is signed with a pinned debug key committed in the project, so future builds install as updates.

> Use only on systems, domains and address space you own or have explicit permission to test.
