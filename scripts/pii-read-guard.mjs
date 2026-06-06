#!/usr/bin/env node
// pii-read-guard.mjs — PreToolUse(Read) hook for pii-mask-yoshi plugin
// PII検出時にReadをブロックし、safe_readの使用を促す。
// プラグイン内の patterns.mjs を import して自己完結。

import { readFileSync, existsSync } from 'node:fs';
import { extname, resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const PLUGIN_ROOT = resolve(SCRIPT_DIR, '..');

const BINARY_EXTS = new Set([
  '.xlsx', '.xls', '.docx', '.pptx', '.pdf',
  '.odt', '.ods', '.odp', '.rtf',
]);

const EXEMPT_PATTERNS = [
  /[\\/]\.claude[\\/]/i,
  /[\\/]CLAUDE\.md$/i,
];

async function loadPatterns() {
  try {
    const modPath = join(PLUGIN_ROOT, 'src', 'patterns.mjs').replaceAll('\\', '/');
    const mod = await import('file:///' + modPath);
    return mod.loadPatterns ? mod.loadPatterns() : [];
  } catch {
    // フォールバック: 最低限のパターン
    return [
      { regex: '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}' },
      { regex: "0\\d{1,4}-\\d{1,4}-\\d{4}" },
      { regex: "[A-Za-z]:[\\\\/]Users[\\\\/][^\\s\"'`,)\\]>]+" },
      { regex: 'sk-[a-zA-Z0-9]{20,}' },
      { regex: 'AKIA[A-Z0-9]{16}' },
    ];
  }
}

async function main() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  if (chunks.length === 0) process.exit(0);

  let data;
  try {
    data = JSON.parse(Buffer.concat(chunks).toString());
  } catch {
    process.exit(0);
  }

  if (data.tool_name !== 'Read') process.exit(0);

  const filePath = data.tool_input?.file_path;
  if (!filePath) process.exit(0);

  const resolved = resolve(filePath);

  if (EXEMPT_PATTERNS.some(p => p.test(resolved))) process.exit(0);

  const ext = extname(resolved).toLowerCase();
  if (BINARY_EXTS.has(ext)) {
    const reason = `[pii-guard] バイナリファイル（${ext}）は safe_read を使用してください: ${filePath}`;
    process.stderr.write(reason + '\n');
    console.log(JSON.stringify({ decision: 'block', reason }));
    process.exit(2);
  }

  if (!existsSync(resolved)) process.exit(0);

  let content;
  try {
    content = readFileSync(resolved, 'utf8');
  } catch {
    process.exit(0);
  }

  const patterns = await loadPatterns();
  for (const p of patterns) {
    try {
      const re = new RegExp(p.regex || p);
      if (re.test(content)) {
        const reason = `[pii-guard] PII検出 — safe_read を使用してください: ${filePath}`;
        process.stderr.write(reason + '\n');
        console.log(JSON.stringify({ decision: 'block', reason }));
        process.exit(2);
      }
    } catch {
      // invalid regex, skip
    }
  }

  process.exit(0);
}

main().catch(() => process.exit(0));
