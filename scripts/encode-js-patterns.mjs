#!/usr/bin/env node
// encode-js-patterns.mjs — encoded-data.mjs の XOR 鍵ローテーション + パターン再エンコード
// 既存の encoded-data.mjs をデコードし、新しい XOR 鍵で再エンコードする
// 生成物: src/encoded-data.mjs
// 実行: node scripts/encode-js-patterns.mjs
//
// パターン追加手順:
//   1. src/encoded-data.mjs の BUILTIN or EXTRA 配列に新エントリを追加
//      regex フィールドには平文の正規表現を仮設定
//   2. 本スクリプトを実行（デコード→新キーで全体再エンコード）
//   3. テスト実行で動作確認

import { randomBytes } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');
const ENCODED_PATH = join(ROOT, 'src', 'encoded-data.mjs');

// 既存の encoded-data.mjs からデコードして読み込む
const encodedMod = await import(new URL(`file://${ENCODED_PATH.replace(/\\/g, '/')}`).href);
const currentK = Buffer.from(encodedMod.XOR_KEY, 'base64');
const decode = (b) => Buffer.from(Buffer.from(b, 'base64').map((v, i) => v ^ currentK[i % currentK.length])).toString('utf8');

// 現行パターンをデコード
const decodedBuiltin = encodedMod.BUILTIN.map(p => ({ ...p, regex: decode(p.regex) }));
const decodedExtra = encodedMod.EXTRA.map(p => ({ ...p, regex: decode(p.regex) }));
const decodedSurnames = decode(encodedMod.SURNAMES);
const decodedHonorifics = decode(encodedMod.HONORIFICS);

// 新しい XOR キー生成（32バイト）
const XOR_KEY = randomBytes(32);

// XOR エンコード関数
function xorEncode(str) {
  const bytes = Buffer.from(str, 'utf8');
  const encoded = Buffer.alloc(bytes.length);
  for (let i = 0; i < bytes.length; i++) {
    encoded[i] = bytes[i] ^ XOR_KEY[i % XOR_KEY.length];
  }
  return encoded.toString('base64');
}

// 新キーで再エンコード
const encodedBuiltin = decodedBuiltin.map(p => {
  const entry = { id: p.id, category: p.category, regex: xorEncode(p.regex), maskPrefix: p.maskPrefix };
  if (p.flags) entry.flags = p.flags;
  return entry;
});

const encodedExtra = decodedExtra.map(p => {
  const entry = { id: p.id, category: p.category, regex: xorEncode(p.regex), maskPrefix: p.maskPrefix };
  if (p.flags) entry.flags = p.flags;
  if (p.defaultConfidence != null) entry.defaultConfidence = p.defaultConfidence;
  return entry;
});

const encodedSurnames = xorEncode(decodedSurnames);
const encodedHonorifics = xorEncode(decodedHonorifics);

// encoded-data.mjs 出力（難読化目的のため鍵は同一ファイルに同梱）
const output = `// 自動生成ファイル — 手動編集禁止
// 生成コマンド: node scripts/encode-js-patterns.mjs
// XOR + base64 で難読化された PII 検出パターン定義
// 目的: grep/静的解析での平文パターン検出を防止（暗号学的保護ではない）

export const XOR_KEY = '${XOR_KEY.toString('base64')}';

export const BUILTIN = ${JSON.stringify(encodedBuiltin, null, 2)};

export const EXTRA = ${JSON.stringify(encodedExtra, null, 2)};

export const SURNAMES = '${encodedSurnames}';

export const HONORIFICS = '${encodedHonorifics}';
`;

writeFileSync(ENCODED_PATH, output, 'utf8');

console.log('Written: src/encoded-data.mjs');
console.log('Builtin patterns: %d', encodedBuiltin.length);
console.log('Extra patterns: %d', encodedExtra.length);
console.log('Surnames: %d chars', decodedSurnames.length);
console.log('Honorifics: %d chars', decodedHonorifics.length);
