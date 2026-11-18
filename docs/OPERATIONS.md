# Handling, limits and optional tools

[Монгол](OPERATIONS.mn.md) · [← README](../README.md)

## Handling & operational notes

- **Prefer an external drive** (`-OutputPath E:\Evidence`). Writing to the system drive can overwrite deleted-file evidence.
- **Do not reboot / shut down** the host before collection finishes.
- The output can contain **sensitive data** (registry hives, browser metadata). Encrypt the archive and transfer it securely.
- Some modules (`hives`, `memorydump`, `exportevtx`) are known to trigger EDR/AV. This is expected — **coordinate with your SOC and allow-list the tool in advance** rather than disabling EDR.
- What the collector will and will not do on a live endpoint is written down as eight numbered claims in **[AV / EDR safety](AV-SAFETY.md)**, each enforced by a CI check. If a commit breaks one, the build fails and names it.

### Getting past AV without evading it

This tool is intentionally **transparent** (no obfuscation / AMSI bypass). To run it without AV interference the correct, auditable way:

1. **Code-sign** the script (`Set-AuthenticodeSignature`).
2. **Publish its SHA-256** so responders can verify and allow-list it.
3. On the forensic host, add a **scoped Defender/EDR exclusion** for the tool, and remove it afterward.

**Verify what you downloaded.** Every release ships a `SHA256SUMS.txt` covering both collectors and both sample files. That file — not this README — is the source of truth for hashes, so nothing here goes stale:

```bash
sha256sum -c SHA256SUMS.txt                          # Linux
```

```powershell
(Get-FileHash .\Tatar.ps1 -Algorithm SHA256).Hash    # Windows - compare with SHA256SUMS.txt
```

Hash the files **as downloaded from the release**. `Tatar.ps1` ships with CRLF line endings (see `.gitattributes`), so a copy taken from a `git clone` on a system that rewrites line endings will hash differently while being the same source. The release asset is the one `SHA256SUMS.txt` describes.

Latest release: **[github.com/ochmunkh/Tatar-Triage/releases/latest](https://github.com/ochmunkh/Tatar-Triage/releases/latest)**

## Known limitations

- Does **not** extract or decrypt saved passwords.
- Full `$MFT` parsing requires an offline tool (e.g. MFTECmd / RawCopy); the script records NTFS/MFT metadata only.
- Browser artifacts are **metadata only** (no DB execution, no decryption).
- Without Administrator, some artifacts (event logs, hives, protected processes) are incomplete.
- Findings in `summary.txt` / `summary.json` are heuristic pattern matches — expect false positives from legitimate software; always validate.
- `Compress-Archive` on PowerShell 5.1 struggles with very large outputs (e.g. memory images); use 7-Zip for those.

## Optional external tools (`tools\`)

- `winpmem.exe` — memory imaging (for `-MemoryDump`)
- `autoruns64.exe` — Sysinternals Autoruns (for the `autoruns` module)

If present in a `tools\` subfolder they are used automatically; otherwise those steps are skipped.
