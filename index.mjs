#!/usr/bin/env node

import { createInterface } from 'node:readline';
import { readFileSync, writeFileSync, mkdirSync, appendFileSync } from 'node:fs';
import { resolve, dirname, extname, basename, join } from 'node:path';
import { homedir } from 'node:os';
import { maskText, unmaskText, getStore } from './src/masker.mjs';
import { BINARY_EXTENSIONS, convertWithMarkitdown } from './src/converter.mjs';
import { formatSiemJsonl, formatSiemCef, formatSiemEcs } from './src/siem-formats.mjs';
import { checkPermissions, checkRetention, cleanup as runCleanup, getRetentionDays } from './src/cleanup.mjs';

// Schema v1.1 counters (module-scope)
let blockReportCount = 0;
let cleanupExpiredCount = 0;

const SEV_MAP = { critical: 'block', high: 'error', medium: 'warn', low: 'info', none: 'info' };

const TOOLS = [
  {
    name: 'safe_read',
    description: 'ファイルを読み取り、PII（個人情報・機密情報）を自動マスクして返す。マスクされた内容のみがAIに渡され、生データは外部AIサーバーに送信されない。',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'マスクして読み取るファイルの絶対パスまたは相対パス' },
      },
      required: ['path'],
    },
  },
  {
    name: 'unmask_file',
    description: 'マスクトークンを含むファイルを読み取り、元のPIIに復元してローカルファイルに保存する。復元データはAI会話コンテキストに返さず、ファイルにのみ書き出す。',
    inputSchema: {
      type: 'object',
      properties: {
        input_path: { type: 'string', description: 'マスクトークンを含むファイルのパス' },
        output_path: { type: 'string', description: '復元結果の出力先パス（省略時: 入力ファイル名.unmasked + 元の拡張子）' },
      },
      required: ['input_path'],
    },
  },
  {
    name: 'mask_stats',
    description: '現セッションのマスク統計を表示する（カテゴリ別件数、対応表ファイルパス）。',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'cleanup',
    description: '保持期限を超過した古いtoken map・block report・SIEMファイルを一括削除する。セッション単位で対応ファイルを同時削除し、孤立ファイルを防ぐ。',
    inputSchema: {
      type: 'object',
      properties: {
        days: { type: 'number', description: '保持日数（デフォルト: 30）。この日数より古いファイルを削除対象とする' },
        dry_run: { type: 'boolean', description: 'trueの場合、削除対象を表示するのみで実際には削除しない' },
      },
    },
  },
  {
    name: 'block_report',
    description: 'セッション中にマスクされたPIIの一覧をカテゴリ・ファイル名・行番号で表示する。実PII値はAPI応答に含めず、ローカルレポートファイルにのみ書き出す。SIEM連携用にjsonl/cef/ecs形式でのファイル出力にも対応。',
    inputSchema: {
      type: 'object',
      properties: {
        format: {
          type: 'string',
          enum: ['text', 'json', 'jsonl', 'cef', 'ecs'],
          description: '出力形式。text: 人間可読（デフォルト）、json: 集約JSON、jsonl: 1検出1行（Splunk/Datadog汎用）、cef: Common Event Format（ArcSight/QRadar）、ecs: Elastic Common Schema',
        },
        output_path: {
          type: 'string',
          description: 'SIEM形式（jsonl/cef/ecs）の出力先ファイルパス。省略時: ~/.pii-mask-yoshi/siem/{session}.{format}',
        },
        meta: {
          type: 'object',
          description: 'SIEMイベントに付与するカスタムメタデータ（例: {"org":"acme","environment":"prod"}）',
          properties: {
            org: { type: 'string', description: '組織名' },
            environment: { type: 'string', description: '環境名（prod/staging/dev）' },
          },
          additionalProperties: false,
        },
      },
    },
  },
];

function handleToolCall(name, args) {
  if (name === 'safe_read') {
    const filePath = resolve(args.path);
    const ext = extname(filePath).toLowerCase();
    let content;

    if (BINARY_EXTENSIONS.has(ext)) {
      content = convertWithMarkitdown(filePath);
      if (!content) {
        return { isError: true, content: [{ type: 'text', text: `バイナリファイル変換エラー: markitdown でファイルを変換できません（python -m markitdown が必要です）` }] };
      }
    } else {
      try {
        content = readFileSync(filePath, 'utf8');
      } catch (e) {
        return { isError: true, content: [{ type: 'text', text: `ファイル読み取りエラー: ${e.message}` }] };
      }
    }

    const masked = maskText(content, filePath);
    const stats = getStore().stats();
    const formatLabel = BINARY_EXTENSIONS.has(ext) ? ` [${ext} → markitdown変換]` : '';
    const header = `[pii-mask-yoshi] ${stats.totalMasked}箇所マスク済み${formatLabel} (対応表: ${stats.mapFile})\n---\n`;
    return { content: [{ type: 'text', text: header + masked }] };
  }

  if (name === 'unmask_file') {
    const inputPath = resolve(args.input_path);
    let content;
    try {
      content = readFileSync(inputPath, 'utf8');
    } catch (e) {
      return { isError: true, content: [{ type: 'text', text: `ファイル読み取りエラー: ${e.message}` }] };
    }

    const unmasked = unmaskText(content);
    const store = getStore();
    const allTokens = [...store.tokenToOriginal.keys()];
    const restoredCount = allTokens.filter((t) => content.includes(t)).length;

    let outputPath;
    if (args.output_path) {
      outputPath = resolve(args.output_path);
    } else {
      const ext = extname(inputPath);
      const base = basename(inputPath, ext);
      outputPath = join(dirname(inputPath), `${base}.unmasked${ext}`);
    }

    try {
      writeFileSync(outputPath, unmasked, 'utf8');
    } catch (e) {
      return { isError: true, content: [{ type: 'text', text: `ファイル書き込みエラー: ${e.message}` }] };
    }

    return { content: [{ type: 'text', text: `${outputPath} に復元済み出力を保存しました（${restoredCount}箇所復元）` }] };
  }

  if (name === 'mask_stats') {
    const stats = getStore().stats();
    const lines = [`セッション: ${stats.sessionId}`, `マスク総数: ${stats.totalMasked}`, ''];
    for (const [cat, count] of Object.entries(stats.byCategory)) {
      lines.push(`  ${cat}: ${count}件`);
    }
    lines.push('', `対応表: ${stats.mapFile}`);
    return { content: [{ type: 'text', text: lines.join('\n') }] };
  }

  if (name === 'cleanup') {
    const days = args.days || getRetentionDays();
    const dryRun = args.dry_run || false;

    if (dryRun) {
      const expired = checkRetention(days);
      if (expired.length === 0) {
        return { content: [{ type: 'text', text: `${days}日以上経過したファイルはありません` }] };
      }
      const lines = [`[dry-run] ${days}日超過: ${expired.length}件`, ''];
      for (const e of expired) lines.push(`  ${e.path} (${e.mtime.toISOString().slice(0, 10)})`);
      return { content: [{ type: 'text', text: lines.join('\n') }] };
    }

    const result = runCleanup(days);
    if (result.sessionIds === 0) {
      return { content: [{ type: 'text', text: `${days}日以上経過したファイルはありません` }] };
    }
    cleanupExpiredCount += result.filesDeleted;
    const lines = [`${result.sessionIds}セッション分のファイルを削除しました（${result.filesDeleted}ファイル）`, ''];
    for (const d of result.details) {
      lines.push(`  ${d.sessionId}: ${d.files.length}ファイル`);
    }
    return { content: [{ type: 'text', text: lines.join('\n') }] };
  }

  if (name === 'block_report') {
    blockReportCount++;
    const s = getStore();
    const findings = s.getFindings();
    const outputFormat = args.format || 'text';

    const siemFormats = ['jsonl', 'cef', 'ecs'];
    const isSiem = siemFormats.includes(outputFormat);

    if (findings.length === 0) {
      if (outputFormat === 'json') {
        return { content: [{ type: 'text', text: JSON.stringify({ session_id: s.sessionId, total: 0, by_file: {}, detail_report: null }) }] };
      }
      if (isSiem) {
        return { content: [{ type: 'text', text: `ブロック検出なし（0件）— ${outputFormat}出力スキップ` }] };
      }
      return { content: [{ type: 'text', text: 'ブロック検出なし（0件）' }] };
    }

    const byFile = {};
    for (const f of findings) {
      (byFile[f.file] = byFile[f.file] || []).push(f);
    }

    // ローカル詳細レポートファイル（両形式共通で書き出す）
    const detailLines = [`=== pii-mask-yoshi block report ===`, `Session: ${s.sessionId}`, `Date: ${new Date().toISOString()}`, ''];
    for (const [file, items] of Object.entries(byFile)) {
      detailLines.push(`File: ${file}`);
      for (const item of items.sort((a, b) => a.line - b.line)) {
        const original = s.tokenToOriginal.get(item.token) || '(unknown)';
        const conf = item.confidence != null ? item.confidence : 1.0;
        detailLines.push(`  Line ${item.line}: [${item.category}] ${original} -> ${item.token} (confidence: ${conf})`);
      }
      detailLines.push('');
    }
    const reportDir = join(homedir(), '.pii-mask-yoshi');
    mkdirSync(reportDir, { recursive: true });
    const reportPath = join(reportDir, `block-report-${s.sessionId}.txt`);
    writeFileSync(reportPath, detailLines.join('\n'), 'utf8');

    if (isSiem) {
      const meta = args.meta || {};
      const formatters = { jsonl: formatSiemJsonl, cef: formatSiemCef, ecs: formatSiemEcs };
      const content = formatters[outputFormat](findings, s.sessionId, meta);
      const siemDir = join(homedir(), '.pii-mask-yoshi', 'siem');
      mkdirSync(siemDir, { recursive: true });
      let siemPath = join(siemDir, `${s.sessionId}.${outputFormat}`);
      if (args.output_path) {
        const candidate = resolve(args.output_path);
        if (!candidate.startsWith(resolve(siemDir))) {
          return { isError: true, content: [{ type: 'text', text: `output_path は ${siemDir} 配下のみ許可されます` }] };
        }
        siemPath = candidate;
      }
      writeFileSync(siemPath, content, 'utf8');
      return { content: [{ type: 'text', text: `[pii-mask-yoshi] ${outputFormat.toUpperCase()}形式で${findings.length}件出力\nファイル: ${siemPath}\n詳細レポート（実PII値含む）: ${reportPath}` }] };
    }

    if (outputFormat === 'json') {
      const byFileJson = {};
      for (const [file, items] of Object.entries(byFile)) {
        byFileJson[file] = items
          .sort((a, b) => a.line - b.line)
          .map((item) => ({ line: item.line, category: item.category.toUpperCase(), token: item.token, confidence: item.confidence ?? 1.0 }));
      }
      const jsonResult = {
        session_id: s.sessionId,
        total: findings.length,
        by_file: byFileJson,
        detail_report: reportPath,
      };
      return { content: [{ type: 'text', text: JSON.stringify(jsonResult) }] };
    }

    // テキスト形式（既存動作維持）
    const safeLines = [`[pii-mask-yoshi] ブロックレポート`, `検出総数: ${findings.length}件`, ''];
    for (const [file, items] of Object.entries(byFile)) {
      safeLines.push(`${file}: ${items.length}件`);
      for (const item of items.sort((a, b) => a.line - b.line)) {
        const conf = item.confidence != null ? item.confidence : 1.0;
        safeLines.push(`  L${item.line}: [${item.category}] ${item.token} (confidence: ${conf})`);
      }
      safeLines.push('');
    }
    safeLines.push(`詳細レポート（実PII値含む）: ${reportPath}`);
    return { content: [{ type: 'text', text: safeLines.join('\n') }] };
  }

  return { isError: true, content: [{ type: 'text', text: `不明なツール: ${name}` }] };
}

function handleMessage(msg) {
  const { id, method, params } = msg;

  if (method === 'initialize') {
    return {
      jsonrpc: '2.0', id,
      result: {
        protocolVersion: '2024-11-05',
        capabilities: { tools: {} },
        serverInfo: { name: 'pii-mask-yoshi', version: '0.4.0' },
      },
    };
  }

  if (method === 'notifications/initialized') return null;

  if (method === 'tools/list') {
    return { jsonrpc: '2.0', id, result: { tools: TOOLS } };
  }

  if (method === 'tools/call') {
    const result = handleToolCall(params.name, params.arguments || {});
    return { jsonrpc: '2.0', id, result };
  }

  if (method === 'ping') {
    return { jsonrpc: '2.0', id, result: {} };
  }

  return {
    jsonrpc: '2.0', id,
    error: { code: -32601, message: `Method not found: ${method}` },
  };
}

const STARTUP_TIME = Date.now();
const STARTUP_ISO = new Date(STARTUP_TIME).toISOString();

process.on('exit', (code) => {
  try {
    const store = getStore();
    const nekoHqDir = join(homedir(), '.neko-hq');
    mkdirSync(nekoHqDir, { recursive: true });
    const statsPath = join(nekoHqDir, 'stats.jsonl');
    const findings = store.getFindings();
    const severities = findings.map(f => {
      const cat = f.category || '';
      if (/API_KEY|AWS_SECRET|AZURE_KEY|PASSWORD|JWT/.test(cat)) return 'critical';
      if (/EMAIL|PERSON|MYNUM|PASSPORT|CREDITCARD|BANK/.test(cat)) return 'high';
      if (/PHONE|ADDRESS|CORPORATE/.test(cat)) return 'medium';
      return 'low';
    });
    const maxSeverity = severities.includes('critical') ? 'critical'
      : severities.includes('high') ? 'high'
      : severities.includes('medium') ? 'medium'
      : severities.length > 0 ? 'low' : 'none';
    const entry = JSON.stringify({
      schema_version: '1.1',
      tool: 'pii-mask-yoshi',
      command: 'session',
      ts: STARTUP_ISO,
      duration_ms: Date.now() - STARTUP_TIME,
      exit_code: code,
      severity: SEV_MAP[maxSeverity] || 'info',
      session_id: store.sessionId,
      summary: {
        findings: findings.length,
        blocked: 0,
        masked: store.tokenToOriginal.size,
        reports: blockReportCount,
        cleanup_expired: cleanupExpiredCount,
      },
      meta: {},
    });
    appendFileSync(statsPath, entry + '\n', 'utf8');
  } catch {
    // exit handler must not throw
  }
});

// CLI mode: pii-mask-yoshi --cleanup [--days N] [--dry-run]
if (process.argv.includes('--cleanup')) {
  const daysIdx = process.argv.indexOf('--days');
  const days = daysIdx !== -1 ? parseInt(process.argv[daysIdx + 1], 10) || getRetentionDays() : getRetentionDays();
  const dryRun = process.argv.includes('--dry-run');

  if (dryRun) {
    const expired = checkRetention(days);
    if (expired.length === 0) { console.log(`${days}日以上経過したファイルはありません`); process.exit(0); }
    console.log(`[dry-run] ${days}日超過: ${expired.length}件`);
    for (const e of expired) console.log(`  ${e.path} (${e.mtime.toISOString().slice(0, 10)})`);
    process.exit(0);
  }

  const result = runCleanup(days);
  if (result.sessionIds === 0) { console.log(`${days}日以上経過したファイルはありません`); process.exit(0); }
  console.log(`${result.sessionIds}セッション分のファイルを削除しました（${result.filesDeleted}ファイル）`);
  for (const d of result.details) console.log(`  ${d.sessionId}: ${d.files.length}ファイル`);
  process.exit(0);
}

// Startup checks (#3B: permissions, #3E: retention)
for (const w of checkPermissions()) process.stderr.write(w + '\n');
const retDays = getRetentionDays();
const expiredFiles = checkRetention(retDays);
if (expiredFiles.length > 0) {
  process.stderr.write(`[pii-mask-yoshi] 警告: ${expiredFiles.length}件のファイルが保持期限を超過しています。cleanup ツールで削除を検討してください。\n`);
}

const rl = createInterface({ input: process.stdin, terminal: false });
rl.on('line', (line) => {
  if (!line.trim()) return;
  let msg;
  try { msg = JSON.parse(line); } catch { return; }
  const resp = handleMessage(msg);
  if (resp) process.stdout.write(JSON.stringify(resp) + '\n');
});
