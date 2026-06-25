> Japanese version: [README.ja.md](README.ja.md)
> Part of the [neko-HQ](https://github.com/aliksir/neko-hq) ecosystem.

# pii-mask-yoshi

MCP server that automatically masks PII (personally identifiable information) in files before they reach external AI API servers. Works with **Claude Code**, **OpenAI Codex CLI**, and **Google Gemini CLI**. Masked content is sent for AI processing; original values are restored locally via a mapping file.

## Tools

| Tool | Description |
|------|-------------|
| `safe_read` | Read a file with automatic PII masking. Binary files (xlsx, docx, pptx, pdf, etc.) are auto-converted via markitdown. |
| `unmask_file` | Restore masked tokens in a file to original values. Output is written to a local file only (never returned to AI context). |
| `mask_stats` | Show masking statistics for the current session. |
| `block_report` | PII detection report by category, file, and line number. Supports text/json/jsonl/cef/ecs formats for SIEM integration. Actual PII values are never returned — detail report is local only. |
| `cleanup` | Delete expired token maps, block reports, and SIEM files. Deletes map+report+siem together per session to prevent orphaned files. |

### CLI Mode

```bash
# Delete files older than 30 days
pii-mask-yoshi --cleanup --days 30

# Preview what would be deleted
pii-mask-yoshi --cleanup --dry-run
```

### Startup Checks

On MCP server startup, pii-mask-yoshi automatically:
- Checks `~/.pii-mask-yoshi/` directory permissions (warns if world-readable on Unix)
- Warns about files exceeding the 30-day retention period

## Built-in Detection Patterns

These patterns work without any external dependencies:

- Email addresses
- Japanese phone numbers
- IPv4 addresses (private/global classification)
- IPv6 addresses
- Local file paths (home directories, etc.)
- API keys (OpenAI, GitHub, AWS, Anthropic)
- AWS Secret Keys, Azure Account Keys
- Passwords (key-value patterns, Japanese keywords, slash-separated)
- Credit card numbers (with Luhn validation)
- Japanese addresses (prefecture + city)
- Japanese My Number
- Bank account numbers
- Passport numbers (JP format)
- Corporate numbers
- Japanese person names (surname + space + given name)
- Comma-separated Japanese name lists

## Architecture

pii-mask-yoshi uses a Rust/WASM hybrid engine for pattern matching. All 66 built-in detection patterns run inside a WASM module compiled from Rust.

- **WASM engine**: All pattern matching runs in the compiled Rust module. This avoids shipping regex patterns as plain text in the JS source.
- **Pattern protection**: Pattern definitions are AES-256-GCM encrypted inside the WASM binary. Keys are derived at runtime via PBKDF2. No plaintext patterns appear in the published package.
- **PERSON overlap scan**: The 11 PERSON patterns run an additional overlap scan — after JS validators reject a candidate match, the engine re-checks the same position for a shorter or differently-bounded match. This reduces false negatives in name detection.
- **JS validators**: Applied on top of WASM match results. These handle false-positive suppression (e.g., common words that look like names) and Luhn validation for credit card numbers.
- **WASM fallback**: If the WASM module fails to load, pii-mask-yoshi falls back to JS regex automatically. Detection coverage is equivalent for most patterns; the overlap scan is not available in fallback mode.

## Optional Dependencies

pii-mask-yoshi works standalone with built-in patterns. Optional dependencies extend its capabilities:

### neko-not-yoshi (recommended)

Provides additional pattern definitions and customer-specific word lists.

- **What it adds**: Patterns from `ngwords.public.json` (override built-in) + customer-specific names/terms from `ngwords.private.json` + whitelist for false positive reduction (`ngwords-whitelist.json` + `ngwords-whitelist.local.json`)
- **Without it**: Built-in patterns still work. Customer-specific masking and whitelist-based false positive reduction are unavailable.
- **Config**: Set `NEKO_NOT_YOSHI_DIR` env var, or place at `./neko-not-yoshi/`
- **Repo**: [aliksir/neko-not-yoshi](https://github.com/aliksir/neko-not-yoshi)

### markitdown (Python)

Required for binary file support in `safe_read`.

- **What it adds**: xlsx, docx, pptx, pdf, odt, ods, odp, rtf conversion to text before masking
- **Without it**: Binary files return an error message. Text files work normally.
- **Install**: `pip install markitdown[all]`

### markitdown-yoshi (MCP server)

A standalone MCP server for document conversion. While pii-mask-yoshi calls `python -m markitdown` directly for its built-in binary support, markitdown-yoshi provides additional capabilities as a separate MCP tool:

- **What it adds**: `convert` tool for on-demand file conversion, `classify_pdf` for PDF structure analysis, `supported_formats` for format discovery
- **Use together**: pii-mask-yoshi handles PII masking on read; markitdown-yoshi handles standalone conversion tasks. Both can run as MCP servers simultaneously.
- **Allowed roots**: markitdown-yoshi enforces directory-scoped access for security (no filesystem root access)
- **Install**: `npm install -g markitdown-yoshi`
- **Repo**: [aliksir/markitdown-yoshi](https://github.com/aliksir/markitdown-yoshi)

### Conversion Flow: Who Does What

```
              Document files (xlsx, docx, pdf, ...)
                          |
          +---------------+---------------+
          |                               |
    pii-mask-yoshi                  markitdown-yoshi
    (safe_read tool)               (convert tool)
          |                               |
    python -m markitdown            python -m markitdown
    (internal call)                 (internal call)
          |                               |
    PII masking applied             Raw Markdown returned
          |                               |
    Masked text -> API              Markdown -> API
          |
    Token map saved locally
    (~/.pii-mask-yoshi/maps/)
```

| Aspect | pii-mask-yoshi | markitdown-yoshi |
|--------|---------------|-----------------|
| Purpose | Read files with PII masking | Convert documents to Markdown |
| PII handling | Auto-masked before API | No masking (raw content) |
| Binary conversion | Built-in via `python -m markitdown` | Built-in via `python -m markitdown` |
| Access control | No directory restriction | Allowed roots enforcement |
| Size limits | None (inherits file system) | 10MB input, 500KB output |
| Caching | Token map per session | No caching |
| When to use | Reading sensitive documents | Converting documents for general use |

## Encryption (At-Rest Protection)

Token mapping files (`~/.pii-mask-yoshi/maps/*.json`) contain the original PII values. For additional security, pii-mask-yoshi can encrypt these files at rest using AES-256-GCM.

### Enabling Encryption

Encryption is **automatic** when a key is available. No configuration flag needed.

**Option 1: Key file** (recommended)
```bash
# Generate a key (stored at ~/.pii-mask-yoshi/.key)
node -e "import('./src/crypto.mjs').then(c => c.generateKey())"
```

**Option 2: Environment variable**
```bash
# Set a base64-encoded 256-bit key
export PII_MASK_ENCRYPT_KEY="<base64-encoded-key>"
```

### How It Works

- **On save** (`safe_read` / session end): if a key is available, the token map is encrypted before writing to disk
- **On load** (`unmask_file`): encrypted maps are transparently decrypted in memory
- **No key available**: maps are stored as plain JSON (backward compatible)
- **Mixed mode**: `load()` auto-detects encrypted vs plain files, so old unencrypted maps remain readable after enabling encryption

### Key Resolution Order

| Priority | Source | Details |
|----------|--------|---------|
| 1 | `PII_MASK_ENCRYPT_KEY` env var | Base64-encoded 256-bit raw key |
| 2 | `~/.pii-mask-yoshi/.key` file | Generated by `generateKey()` |

### Security Notes

- The key file is created with restricted permissions (`0o600`)
- AES-256-GCM provides both confidentiality and integrity (tampered files are rejected)
- Each encryption uses a random IV, so the same data produces different ciphertext
- **The key itself must be protected** — anyone with the key can decrypt all maps
## How It Works

```
File ──→ safe_read ──→ [Binary?] ──→ markitdown convert ──→ WASM pattern matching ──→ JS validators ──→ Masked text ──→ API
                            │                                       ↑                        │
                            └──→ [Text] ──→ Read file ─────────────┘                        │
                                                          (WASM unavailable: JS regex ───────┘)
                                                                                   │
                                                                         Token mapping saved
                                                                         to ~/.pii-mask-yoshi/maps/
```

1. `safe_read` reads the file locally
2. Binary files are converted to Markdown via `python -m markitdown`
3. All patterns (built-in + neko-not-yoshi if available) are applied
4. Matched values are replaced with tokens like `[EMAIL-001]`, `[PRIV-IPv4-003]`, `[PERSON-002]`
5. Only masked text is returned to the AI (and sent to the external API)
6. Token-to-original mapping is saved locally at `~/.pii-mask-yoshi/maps/`
7. `unmask_file` restores tokens to original values in a local file

### block_report — PII Detection Report

Returns a summary of all PII detections in the current session (category, filename, line number). **Actual PII values are never included in the API response** — they are written only to a local report file.

Output to API:
- Category, filename, line number, mask token (e.g. \[EMAIL-001\])
- Path to the local detail report

Local report (contains actual values):
- `~/.pii-mask-yoshi/block-report-{session}.txt`

### Report Management

- **Location**: `~/.pii-mask-yoshi/block-report-{session}.txt`
- **Session ID format**: `session-{timestamp}` — a unique ID generated per MCP server instance (i.e., per AI CLI session). The timestamp is `Date.now()` at server startup.
- **Retention**: Reports are not auto-deleted. Periodically clean old reports:
  ```bash
  # Delete reports older than 30 days (Linux/macOS)
  find ~/.pii-mask-yoshi -name 'block-report-*' -mtime +30 -delete
  ```
  ```powershell
  # Delete reports older than 30 days (Windows PowerShell)
  Get-ChildItem "$env:USERPROFILE\.pii-mask-yoshi" -Filter "block-report-*" |
    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) } | Remove-Item
  ```
- **Security note**: Detail reports contain actual PII values. Ensure `~/.pii-mask-yoshi/` has appropriate permissions (e.g., `chmod 700` on Linux/macOS, or restrict ACL on Windows).
- **Token mapping files**: `~/.pii-mask-yoshi/maps/session-*.json` — same retention policy applies. Required for `unmask_file` to work.

### SIEM Integration

`block_report` supports multiple output formats for SIEM/log management systems:

| Format | Use case | Output |
|--------|----------|--------|
| `text` | Human-readable (default) | MCP response |
| `json` | Aggregated JSON | MCP response |
| `jsonl` | One event per line (Splunk, Datadog, generic) | File |
| `cef` | Common Event Format (ArcSight, QRadar) | File |
| `ecs` | Elastic Common Schema (Elasticsearch, Kibana) | File |

SIEM formats (`jsonl`, `cef`, `ecs`) write to `~/.pii-mask-yoshi/siem/{session}.{format}` by default. Override with `output_path`.

Custom metadata can be attached to every event via the `meta` parameter:
```json
{"format": "jsonl", "meta": {"org": "acme-corp", "environment": "prod"}}
```

Severity levels are assigned per PII category: `critical` (API keys, passwords), `high` (email, person names, credit cards), `medium` (phone, address), `low` (IP, file paths).

**PII values are never included in SIEM output** — only category, token, file path, and line number.

#### Output Examples

**JSONL** (one event per line):
```json
{"timestamp":"2026-06-07T10:00:00.000Z","event_type":"pii_detection","session_id":"session-1749290400000","host":"workstation-1","file":"/projects/report.txt","line":3,"category":"EMAIL","token":"[EMAIL-001]","severity":"high","org":"acme-corp"}
```

**CEF**:
```
CEF:0|aliksir|pii-mask-yoshi|0.6.0|pii_detection|PII Detected|7|src=/projects/report.txt spt=3 cs1=EMAIL cs1Label=Category cs2=[EMAIL-001] cs2Label=Token dvchost=workstation-1 externalId=session-1749290400000 org=acme-corp
```

**ECS** (Elastic Common Schema):
```json
{"@timestamp":"2026-06-07T10:00:00.000Z","event":{"kind":"alert","category":["intrusion_detection"],"type":["info"],"module":"pii-mask-yoshi","dataset":"pii.detection","severity":7},"file":{"path":"/projects/report.txt"},"source":{"line":3},"rule":{"category":"EMAIL"},"message":"[EMAIL-001]","agent":{"name":"pii-mask-yoshi","version":"0.6.0"},"host":{"name":"workstation-1"},"labels":{"session_id":"session-1749290400000","org":"acme-corp"}}
```

### neko-hq Integration

When pii-mask-yoshi runs as an MCP server, session summary (findings count, masked count) is automatically logged to `~/.neko-hq/stats.jsonl` on exit. This allows `neko-hq stats` to include PII detection metrics alongside other tool statistics.

## Protection Level by AI Client

| Client | MCP Support | Read Interception | Protection Level | Notes |
|--------|:-----------:|:------------------:|:----------------:|-------|
| Claude Code | Yes | Enforced | **Strong** | `pii-read-guard` hook blocks raw `Read` on sensitive files. `safe_read` is the only path. |
| OpenAI Codex CLI | Yes | Convention-based | Moderate | No hook system. Users must use `safe_read` instead of direct file reads. |
| Google Gemini CLI | Yes | Convention-based | Moderate | No hook system. Same convention-based approach as Codex. |

> Claude Code enforces PII masking via a PreToolUse hook that intercepts `Read` calls. Codex and Gemini rely on the user (or system prompt) to call `safe_read` instead of reading files directly. For maximum protection on Codex/Gemini, configure your system prompt to always use `safe_read` for file reading.

## Setup

```bash
# Install (Node.js 22+ required)
npm install -g pii-mask-yoshi

# Optional: binary file support
pip install markitdown[all]
```

### Claude Code

Add to your project's `.mcp.json`:

```json
{
  "mcpServers": {
    "pii-mask-yoshi": {
      "command": "pii-mask-yoshi"
    }
  }
}
```

See also: The `pii-read-guard` hook (included in `.claude-plugin/`) blocks unmasked `Read` calls on sensitive files.

### OpenAI Codex CLI

Add to your project's `.codex/.mcp.json`:

```json
{
  "mcpServers": {
    "pii-mask-yoshi": {
      "command": "pii-mask-yoshi"
    }
  }
}
```

Detailed guide: [docs/setup-codex.md](docs/setup-codex.md)

### Google Gemini CLI

Add to your Gemini MCP configuration:

```json
{
  "mcpServers": {
    "pii-mask-yoshi": {
      "command": "pii-mask-yoshi"
    }
  }
}
```

Detailed guide: [docs/setup-gemini.md](docs/setup-gemini.md)

> **Note**: The `pii-read-guard` PreToolUse hook is Claude Code-specific. For Codex and Gemini, use `safe_read` directly instead of `Read` for sensitive files.

## Disclaimer

This tool reduces the risk of PII exposure but does not guarantee complete detection. Pattern-based masking has inherent limitations:

- Novel or unusual PII formats may not be detected
- Context-dependent information (e.g., names that are also common words) may be missed or over-matched
- Binary file conversion depends on markitdown's extraction accuracy
- Custom word lists (neko-not-yoshi) require manual maintenance

**Do not rely on this tool as your sole PII protection measure.** Always review masked output before sharing sensitive documents and use it as one layer in a defense-in-depth strategy.

The authors assume no liability for any PII that passes through undetected.

## Repository & Build

This repository is a **clean-room public snapshot**. Internal development history has been sanitized to remove confidential information and reconstructed for public release. As a result:

- Git history does not contain the full development timeline
- Each public release is an orphan commit (no parent chain to prior releases)
- For change details between versions, refer to [CHANGELOG.md](CHANGELOG.md)

### Protected Build

The `dist/` directory contains an encrypted bundle built with `scripts/build-protected.mjs` (AES-256-GCM). This is an optional hardened distribution — the unencrypted source in `src/` is the primary codebase and works without the encrypted bundle.

Pattern definitions inside the WASM binary are AES-256-GCM encrypted with PBKDF2-derived keys. The npm package does not include `src/encoded-data.mjs` — pattern access is WASM-only in published builds. See [THREAT-MODEL.md](THREAT-MODEL.md) for details.

## License

Apache-2.0

