# Setup: Google Gemini CLI

## Install

```bash
npm install -g pii-mask-yoshi
```

## Configure MCP Server

Add to your Gemini CLI MCP configuration (`~/.gemini/settings.json` or project-level config):

```json
{
  "mcpServers": {
    "pii-mask-yoshi": {
      "command": "pii-mask-yoshi"
    }
  }
}
```

Or, if installed locally (not globally):

```json
{
  "mcpServers": {
    "pii-mask-yoshi": {
      "command": "node",
      "args": ["/absolute/path/to/pii-mask-yoshi/index.mjs"]
    }
  }
}
```

> **Note**: Gemini CLI's MCP support status may vary by version. Verify that your Gemini CLI version supports MCP servers before configuring.

## Usage

Once configured, the following MCP tools are available in your Gemini session:

- **safe_read** — Read files with automatic PII masking
- **unmask_file** — Restore masked tokens to original values (local file only)
- **mask_stats** — Show session masking statistics
- **block_report** — PII detection report (text/json/jsonl/cef/ecs)
- **cleanup** — Delete expired token maps and reports

## Optional: Binary File Support

```bash
pip install markitdown[all]
```

Enables xlsx, docx, pptx, pdf conversion before masking.

## Optional: Enhanced Patterns

Install [neko-not-yoshi](https://github.com/aliksir/neko-not-yoshi) for additional detection patterns and customer-specific word lists.

```bash
npm install -g neko-not-yoshi
```

Set the path via environment variable in your MCP config:

```json
{
  "mcpServers": {
    "pii-mask-yoshi": {
      "command": "pii-mask-yoshi",
      "env": {
        "NEKO_NOT_YOSHI_DIR": "/path/to/neko-not-yoshi"
      }
    }
  }
}
```

## Note

The `pii-read-guard` hook (PreToolUse hook that blocks unmasked `Read` on sensitive files) is Claude Code-specific and does not apply to Gemini CLI. In Gemini, use `safe_read` directly instead of `Read` for sensitive files.
