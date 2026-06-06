# pii-mask-yoshi

Claude Code (MCP) server that automatically masks PII (personally identifiable information) in files before they reach Anthropic's API servers. Masked content is sent for AI processing; original values are restored locally via a mapping file.

## Tools

| Tool | Description |
|------|-------------|
| `safe_read` | Read a file with automatic PII masking. Binary files (xlsx, docx, pptx, pdf, etc.) are auto-converted via markitdown. |
| `unmask_file` | Restore masked tokens in a file to original values. Output is written to a local file only (never returned to Claude). |
| `mask_stats` | Show masking statistics for the current session. |

## Built-in Detection Patterns

These patterns work without any external dependencies:

- Email addresses
- Japanese phone numbers
- IPv4 addresses (private/global classification)
- IPv6 addresses
- Local file paths (`C:\Users\...`)
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

## Optional Dependencies

pii-mask-yoshi works standalone with built-in patterns. Optional dependencies extend its capabilities:

### neko-not-yoshi (recommended)

Provides additional pattern definitions and customer-specific word lists.

- **What it adds**: Patterns from `ngwords.public.json` (override built-in) + customer-specific names/terms from `ngwords.private.json`
- **Without it**: Built-in patterns still work. Customer-specific masking is unavailable.
- **Config**: Set `NEKO_NOT_YOSHI_DIR` env var, or place at `C:/work/neko-not-yoshi/`
- **Repo**: [aliksir/neko-not-yoshi](https://github.com/aliksir/neko-not-yoshi)

### markitdown (Python)

Required for binary file support in `safe_read`.

- **What it adds**: xlsx, docx, pptx, pdf, odt, ods, odp, rtf conversion to text before masking
- **Without it**: Binary files return an error message. Text files work normally.
- **Install**: `pip install markitdown[all]`

### markitdown-yoshi (MCP server, separate)

An MCP server wrapper around markitdown. Not a direct dependency of pii-mask-yoshi (pii-mask-yoshi calls `python -m markitdown` directly), but part of the same ecosystem.

- **Repo**: [aliksir/markitdown-yoshi](https://github.com/aliksir/markitdown-yoshi)

## How It Works

```
File ──→ safe_read ──→ [Binary?] ──→ markitdown convert ──→ Pattern matching ──→ Masked text ──→ API
                            │                                       ↑
                            └──→ [Text] ──→ Read file ─────────────┘
                                                                    │
                                                          Token mapping saved
                                                          to ~/.pii-mask-yoshi/maps/
```

1. `safe_read` reads the file locally
2. Binary files are converted to Markdown via `python -m markitdown`
3. All patterns (built-in + neko-not-yoshi if available) are applied
4. Matched values are replaced with tokens like `[EMAIL-001]`, `[PRIV-IPv4-003]`, `[PERSON-002]`
5. Only masked text is returned to Claude (and sent to Anthropic's API)
6. Token-to-original mapping is saved locally at `~/.pii-mask-yoshi/maps/`
7. `unmask_file` restores tokens to original values in a local file

## Setup

```bash
# Install (Node.js 22+ required)
npm install -g pii-mask-yoshi

# Add to Claude Code MCP config (.mcp.json)
{
  "mcpServers": {
    "pii-mask-yoshi": {
      "command": "pii-mask-yoshi"
    }
  }
}

# Optional: binary file support
pip install markitdown[all]
```

## License

MIT
