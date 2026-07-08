# APK Fraud Analyzer

A Python static analysis script for inspecting suspicious Android APKs. Built using [androguard](https://github.com/androguard/androguard) to quickly surface indicators of fraudulent or malicious apps (fake banking/government apps, droppers, etc.) without running or installing the APK.

## What it checks

- **File hashes** — MD5 and SHA256 of the APK
- **App identity** — package name, app label, version, min/target SDK
- **Signing certificate** — v1/v2/v3 signature status, subject/issuer, SHA256 fingerprint, and a flag for the public AOSP debug certificate (a strong red flag if present on a "real" app)
- **Manifest red flags** — presence of `debuggable` and `usesCleartextTraffic` attributes
- **Permissions** — full list of requested permissions
- **Components** — activities, services, and receivers declared in the manifest
- **Embedded URLs** — non-standard URLs found in the DEX bytecode (filtered to exclude common SDK/schema domains)
- **Dropper/crypto behavior evidence** — pattern matches for strings associated with encrypted payloads, package installation, VPN services, and AES/CBC usage

## Requirements

```bash
pip install androguard loguru
```

## Usage

```bash
python analyze_apk.py path/to/sample.apk
```

Or run without arguments to be prompted for a filename:

```bash
python analyze_apk.py
```

A report is saved automatically as `evidence_report_<apkname>.txt` in the working directory, so multiple samples won't overwrite each other's output.

## Example output (truncated)

```
======================================================================
FRAUD APK ANALYSIS REPORT
======================================================================
Target APK   : sample.apk

[1] FILE HASHES
MD5   : ...
SHA256: ...

[2] APP IDENTITY
Package name : com.example.fake
App label    : Example App
...
```

## Disclaimer

This tool is intended **for educational and defensive security research purposes only** — e.g. analyzing suspicious APKs you've received to understand their behavior before reporting or blocking them. Do not use it to analyze apps you do not have the right to inspect, and do not use any findings to build or distribute malware. The author assumes no liability for misuse.

## License

MIT (or update as you prefer)
