#!/usr/bin/env node

import { createInterface } from 'node:readline';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve, dirname, extname, basename, join } from 'node:path';
import { maskText, unmaskText, getStore } from './src/masker.mjs';

const TOOLS = [
  {
    name: 'safe_read',
    description: 'ファイルを読み取り、PII（個人情報・機密情報）を自動マスクして返す。マスクされた内容のみがAIに渡され、生データはAnthropicサーバーに送信されない。',
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
    description: 'マスクトークンを含むファイルを読み取り、元のPIIに復元してローカルファイルに保存する。復元データはClaude会話に返さず、ファイルにのみ書き出す。',
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
];

function handleToolCall(name, args) {
  if (name === 'safe_read') {
    const filePath = resolve(args.path);
    let content;
    try {
      content = readFileSync(filePath, 'utf8');
    } catch (e) {
      return { isError: true, content: [{ type: 'text', text: `ファイル読み取りエラー: ${e.message}` }] };
    }
    const masked = maskText(content);
    const stats = getStore().stats();
    const header = `[pii-mask-yoshi] ${stats.totalMasked}箇所マスク済み (対応表: ${stats.mapFile})\n---\n`;
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
    const tokenPattern = /\[[A-Z]+-\d{3}\]/g;
    const maskedTokens = content.match(tokenPattern) || [];
    const restoredCount = maskedTokens.filter((t) => store.tokenToOriginal.has(t)).length;

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
        serverInfo: { name: 'pii-mask-yoshi', version: '0.1.0' },
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

const rl = createInterface({ input: process.stdin, terminal: false });
rl.on('line', (line) => {
  if (!line.trim()) return;
  let msg;
  try { msg = JSON.parse(line); } catch { return; }
  const resp = handleMessage(msg);
  if (resp) process.stdout.write(JSON.stringify(resp) + '\n');
});
