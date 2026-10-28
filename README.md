# VindexAV — Endpoint Security & Threat Detection Engine

VindexAV is an educational endpoint security and automated threat triage engine. It combines chunked cryptographic hash verification, multi-variable static heuristics, compiled YARA rules, watchdog real-time monitoring, and AES-Fernet quarantine vaults.

## Pipeline Architecture
1. **Hash Verification**: 1 MB chunked MD5 & SHA-256 computation compared against `signatures/known_hashes.txt` (including EICAR standard test hashes) and optional API fallbacks.
2. **Static Heuristics**: Shannon entropy evaluation (cutoff: 7.2), file header magic byte inspection vs extensions, double extension identification, and PE section and import directory parsing via `pefile`.
3. **YARA Pattern Matching**: Precompiled rules in `rules/*.yar` checking process launcher commands, keylogger imports, and ransom note semantics.
4. **Real-time Monitoring & Isolation**: Folder interception via `watchdog` that waits for file write settlement, evaluates threat criteria, and automatically encrypts malicious files into `quarantine_vault/`.

## Setup on Kali Linux
See execution instructions below.