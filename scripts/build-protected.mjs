#!/usr/bin/env node
// build-protected.mjs -- patterns.mjs + masker.mjs を単一 CJS factory に変換し AES-256-GCM 暗号化
// 生成物: dist/core.enc (暗号化バンドル) + dist/loader.mjs (復号ローダー)

import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes, createCipheriv } from 'node:crypto';

const __dir = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dir, '..');
const DIST = join(ROOT, 'dist');

// --- 1. ソース読み込み ---

function readSrc(rel) {
  return readFileSync(join(ROOT, rel), 'utf8');
}

const patternsSrc = readSrc('src/patterns.mjs');
const maskerSrc   = readSrc('src/masker.mjs');

// --- 2. ソース変換 ---

// import 文除去 (ESM import ... from '...' 形式)
function stripImports(src) {
  return src.replace(/^import\s+\{[^}]*\}\s+from\s+['"][^'"]+['"];?\s*$/gm, '');
}

// export キーワード除去
function stripExport(src) {
  return src.replace(/^export\s+(?=function\s|class\s)/gm, '');
}

// コメント先頭行除去 (1行目のモジュール説明)
function stripFirstComment(src) {
  return src.replace(/^\/\/[^\n]*\n/, '');
}

// patterns.mjs 固有: node:os import行 + NEKO_NOT_YOSHI_DIR 定義行を除去
function stripPatternsImports(src) {
  // import { homedir } from 'node:os'; を除去
  let result = src.replace(/^import\s+\{\s*homedir\s*\}\s+from\s+['"]node:os['"];?\s*$/gm, '');
  // const NEKO_NOT_YOSHI_DIR = ... 行を除去（require 経由に置換するため）
  result = result.replace(/^const\s+NEKO_NOT_YOSHI_DIR\s*=.*$/gm, '');
  return result;
}

// masker.mjs 固有: module-level store 変数を除去（factory 内で再定義）
function stripModuleLevelStore(src) {
  return src.replace(/^const\s+store\s*=\s*new\s+MaskStore\(\);?\s*$/gm, '');
}

// --- 3. 各ソースを変換 ---

let patternsCode = stripFirstComment(stripExport(stripPatternsImports(stripImports(patternsSrc))));

let maskerCode = stripFirstComment(stripModuleLevelStore(stripExport(stripImports(maskerSrc))));

// --- 4. factory function 組み立て ---

const factory = `"use strict";
const { readFileSync, existsSync } = require('node:fs');
const { join } = require('node:path');
const { homedir } = require('node:os');

const NEKO_NOT_YOSHI_DIR = process.env.NEKO_NOT_YOSHI_DIR || join(homedir(), 'neko-not-yoshi');

const store = new MaskStore();

// === patterns.mjs (inlined) ===
${patternsCode}

// === masker.mjs (inlined) ===
${maskerCode}

return { loadPatterns, maskText, unmaskText, getStore };
`;

// --- 5. 暗号化 ---

const key = randomBytes(32);
const iv = randomBytes(12);
const cipher = createCipheriv('aes-256-gcm', key, iv);
const enc = Buffer.concat([cipher.update(factory, 'utf8'), cipher.final()]);
const tag = cipher.getAuthTag();

const encPayload = JSON.stringify({
  v: 1,
  alg: 'aes-256-gcm',
  iv: iv.toString('base64'),
  tag: tag.toString('base64'),
  ct: enc.toString('base64'),
});

// --- 6. 出力 ---

if (!existsSync(DIST)) mkdirSync(DIST, { recursive: true });

writeFileSync(join(DIST, 'core.enc'), encPayload, 'utf8');

const mask = randomBytes(32);
const masked = Buffer.alloc(32);
for (let i = 0; i < 32; i++) masked[i] = key[i] ^ mask[i];
const toHex = buf => Array.from(buf).map(b => '0x' + b.toString(16).padStart(2, '0')).join(',');

const loaderSrc = `import { readFileSync } from 'node:fs';
import { createDecipheriv } from 'node:crypto';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { MaskStore } from '../src/store.mjs';

const _require = createRequire(import.meta.url);
const __dir = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dir, '..');

const _a = Buffer.from([${toHex(mask)}]);
const _b = Buffer.from([${toHex(masked)}]);
const _k = Buffer.alloc(32);
for (let _i = 0; _i < 32; _i++) _k[_i] = _a[_i] ^ _b[_i];

const _enc = JSON.parse(readFileSync(join(__dir, 'core.enc'), 'utf8'));
const _iv = Buffer.from(_enc.iv, 'base64');
const _tag = Buffer.from(_enc.tag, 'base64');
const _ct = Buffer.from(_enc.ct, 'base64');
const _d = createDecipheriv('aes-256-gcm', _k, _iv);
_d.setAuthTag(_tag);
const _src = Buffer.concat([_d.update(_ct), _d.final()]).toString('utf8');

const _fn = new Function('require', 'ROOT', 'MaskStore', _src);
const _core = _fn(_require, ROOT, MaskStore);

export const { maskText, unmaskText, getStore } = _core;
export const { loadPatterns } = _core;
`;

writeFileSync(join(DIST, 'loader.mjs'), loaderSrc, 'utf8');

console.log('[build-protected] core.enc: %d bytes', encPayload.length);
console.log('[build-protected] loader.mjs: generated');
console.log('[build-protected] key split into XOR-masked pair');
