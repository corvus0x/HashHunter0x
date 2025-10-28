# HashHunter0x

HashHunter0x is a Python tool built to search your MD5 hashes against massive public indicator sets. It integrates [MalwareBazaar](https://bazaar.abuse.ch/export/#txt), [VirusShare](https://virusshare.com/hashes), and custom feeds, builds optimized binary structures, and answers queries within seconds even when working with tens of millions of entries.

HashHunter0x is **designed to correlate MD5 hashes of files**, including executables, obtained from any system (Windows, Linux, or even ESXi) and **quickly verify whether any of them correspond to malware**. It is especially useful in Incident Response, where the analyst looks for clues in the investigated systems and the tool allows for mass validation in seconds to determine whether there is malware in the system. If it detects a malicious binary, it provides an immediate clue to further the investigation and guide the necessary actions.


<p align="center">
<img src="https://i.imgur.com/CPqqAAU_d.webp?maxwidth=8000&fidelity=grand">
<br>
<img src="https://i.imgur.com/3XqGh0n.png">
</p>

---

## Quick Install

```bash
git clone https://github.com/corvus0x/HashHunter0x.git
cd HashHunter0x
# Ready to use: no external dependencies required

(Optional) If you already have a custom MD5 list, put it under IOC/Custom/ (one MD5 per line).
```

---

## Recommended Workflow

1. **Sync sources:** `python hashhunter0x.py update --all`
2. **Build artifacts:** `python hashhunter0x.py build --all`
3. **Scan your IOCs:** `python hashhunter0x.py scan hashes.txt`
4. **Ad-hoc lookups:** `python hashhunter0x.py check <md5>`
5. **Review dataset state:** `python hashhunter0x.py status`

All commands accept `--workdir <path>` to operate in a different directory (defaults to the current working directory).

---

## Key Features

- Downloads and normalizes MalwareBazaar and VirusShare dumps, with optional custom collections stored in `IOC/custom`.
- Produces deduplicated `.bin` datasets, prefix indexes `.idx`, and Bloom filters `.bf` for fast on-disk lookups.
- Uses only the Python standard library (urllib, mmap, ThreadPoolExecutor, gzip, zipfile); no external packages or databases.
- Provides five focused CLI commands: `update`, `build`, `scan`, `check`, `status`.
- Generates CSV, JSONL, and responsive HTML reports ready to share or archive.
- Streams and externally sorts data, enabling effortless handling of hundreds of millions of hashes without exhausting memory.

---

## Requirements

| Component | Details |
|-----------|---------|
| Python    | Version 3.10 or newer with read/write access to the working directory. |
| Platform  | Windows, Linux, or macOS (only portable stdlib APIs are used). |
| Storage   | Depends on the number of dumps: MalwareBazaar full dump ~700 MB, each VirusShare file ~150 MB; `.bin/.idx/.bf` artifacts require additional space. |
| Network   | HTTPS egress to `bazaar.abuse.ch` and `virusshare.com`; VirusShare may require authenticated cookies. |

---

## Command Reference

### update

Downloads and validates the input datasets.

```bash
python hashhunter0x.py update [--all|--mb|--vs|--custom] [--local-only] [--cookie-file cookies.txt] [--quiet]
```

| Option | Description |
|--------|-------------|
| `--all`        | Default selection. Processes MalwareBazaar, VirusShare, and `IOC/custom`. |
| `--mb`         | Only MalwareBazaar. |
| `--vs`         | Only VirusShare. |
| `--custom`     | Only files placed manually under `IOC/custom`. |
| `--local-only` | Skip downloads and reuse files already present in `IOC/`. |
| `--cookie-file`| Load Netscape/Mozilla cookies to access VirusShare when authentication is required. |
| `--quiet`      | Reduce console output. |

Results are recorded in `data/manifest.json`, including valid/invalid hash counts per source.

### build

Generates the artifacts needed for fast lookups (external sort, prefix index, Bloom filter).

```bash
python hashhunter0x.py build [--all|--mb|--vs|--custom] [--chunk-recs N] [--fp-rate F] [--threads N] [--quiet]
```

| Option | Description |
|--------|-------------|
| `--all`        | Builds artifacts for MalwareBazaar, VirusShare, and `IOC/custom`. |
| `--mb`         | Only MalwareBazaar. |
| `--vs`         | Only VirusShare. |
| `--custom`     | Only custom sources. |
| `--chunk-recs` | Number of records per chunk before flushing a `.part` file during external sort (default 8,000,000). |
| `--fp-rate`    | Target false-positive rate for the Bloom filter (default `1e-3`). |
| `--threads`    | Reserved for future build parallelism (currently informational). |
| `--quiet`      | Reduce console output. |

Artifacts are written to `data/` as `hashset.<source>.bin`, `.idx`, and `.bf`.

### scan

Compares your hashes against the selected sources and emits reports.

```bash
python hashhunter0x.py scan <file|-> [--all|--mb|--vs|--custom] [--csv path] [--json path] [--html path] [--quiet]
```

| Option | Description |
|--------|-------------|
| `infile`  | Input file containing one hash (and optional alias) per line. Use `-` to read from STDIN. |
| `--csv`   | CSV output path (defaults to `output/<stem>.csv`). |
| `--json`  | JSONL output path (optional; none generated unless provided). |
| `--html`  | HTML report path (defaults to `output/<stem>.html`). |
| `--quiet` | Reduce console output. |

Lines may include an alias after the hash (`md5 alias`). Bloom filters and binary searches over `.bin/.idx` structures deliver low-latency responses even with very large datasets.

### check

Looks up a single MD5 hash.

```bash
python hashhunter0x.py check <md5> [--all|--mb|--vs|--custom]
```

Shows whether the hash exists in the selected sources. Requires `build` to have been executed for those datasets.

### status

Summarizes available artifacts.

```bash
python hashhunter0x.py status [--workdir path]
```

Displays record counts plus file sizes for the `bin/idx/bloom` bundles using information from `data/manifest.json`.

---

## Directories and Artifacts

After running `update` and `build` you will find the following structure inside the working directory:

```
workdir/
  hashhunter0x.py
  IOC/
    MalwareBazaar/        # TXT/ZIP files downloaded from MalwareBazaar
    VirusShare/           # TXT/MD5/ZIP files downloaded from VirusShare
    custom/               # User-provided sources
  data/
    hashset.mb.bin
    hashset.mb.idx
    hashset.mb.bf
    hashset.vs.bin
    hashset.vs.idx
    hashset.vs.bf
    hashset.custom.*      # Present when custom sources are built
    manifest.json
  output/
    *.csv                 # Scan results
    *.html
    *.jsonl (optional)
  cache/
    hhx_*/                # Temporary parts produced during builds
```

The `cache/` directory is cleared automatically at the end of each build. You can delete it manually when no build is running.

---

## Reports and Output
- **HTML:** dark/light responsive dashboard with per-source positive counts, filterable table, and execution metadata.
- **CSV:** `md5,alias,in_mb,in_vs,in_custom,sources` columns suitable for SIEM ingestion or spreadsheets.
- **Console:** always prints total/positive counters per source and overall scan duration.
- **JSONL:** mirrors the CSV information in newline-delimited JSON (`{"md5": "...", "sources": [...]}`) when requested.

---

## Troubleshooting

| Symptom | Possible cause | Suggested action |
|---------|----------------|------------------|
| `Source vs is not built` | `scan` or `check` ran before `build` for that source. | Execute `python hashhunter0x.py build --vs` (or `--all`). |
| VirusShare downloads fail with 401/403 | Authentication required. | Export valid cookies and provide them via `--cookie-file`. |
| VirusShare `.zip` files are empty or corrupt | Incomplete download due to network interruption. | Run `update` again; `.part` files resume automatically. |

---

## FAQ

**Are malware samples downloaded?**  
No. Only public MD5 hash lists are retrieved and processed.

**Can I add other sources?**  
Yes. Drop your files under `IOC/custom`, run `update --custom`, then `build --custom`. They will appear in `scan` as the `Custom` source.

**How accurate are Bloom filter lookups?**  
The Bloom filter eliminates false negatives and keeps false positives below the configured rate (default `1e-3`). Every candidate match is confirmed by a binary search, so final results contain no false positives.

**Does it support SHA1 or SHA256?**  
Currently it focuses on MD5. Supporting other algorithms would require adjusting record sizes, validation, and file formats.

---

## License
> Author: corvus0x  
> License: MIT. See `LICENSE` for the full text.
