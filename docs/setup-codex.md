# Setup: OpenAI Codex CLI

## Install

```bash
npm install -g pii-mask-yoshi
```

## Configure MCP Server

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

Or, if installed locally (not globally):

```json
{
  "mcpServers": {
    "pii-mask-yoshi": {
      "command": "node",
      "args": ["node_modules/pii-mask-yoshi/index.mjs"]
    }
  }
}
```

## Plugin Installation (alternative)

If Codex CLI supports plugin installation:

```bash
codex install pii-mask-yoshi
```

The `.codex-plugin/plugin.json` in this package provides the necessary metadata.

## Usage

Once configured, `safe_read` is available as an MCP tool in your Codex session:

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

Set the path via environment variable:

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

The `pii-read-guard` hook (PreToolUse hook that blocks unmasked `Read` on sensitive files) is Claude Code-specific and does not apply to Codex CLI. In Codex, use `safe_read` directly instead of `Read` for sensitive files.
