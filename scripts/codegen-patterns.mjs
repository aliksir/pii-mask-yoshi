#!/usr/bin/env node
// AUTO-GENERATED-TOOL: codegen-patterns.mjs
// Reads src/patterns.mjs and emits rust/src/generated_patterns.rs + rust/pattern-validator-map.json

import { randomBytes } from 'node:crypto';
import { writeFileSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');

// Rust regex クレートで非対応の構文を検出する
function checkRustRegexCompat(regexStr) {
  const issues = [];

  // lookbehind: (?<=...) or (?<!...)
  if (/\(\?<[=!]/.test(regexStr)) {
    issues.push('lookbehind not supported (use fancy-regex crate)');
  }

  // lookahead は Rust regex で対応済み: (?=...) (?!...) は OK

  // \p{Script=Xxx} 形式 → \p{Xxx} に変換が必要
  // ここでは検出のみ（自動変換は危険なので手動マークする）
  if (/\\p\{Script=/.test(regexStr)) {
    issues.push('\\p{Script=Xxx} form not supported, use \\p{Xxx}');
  }

  // [\s\S] を含む場合、Rust では (?s:.) または s フラグで対応
  // regex クレートは DOT_MATCHES_NEW_LINE フラグで対応可能なため「変換必要」として記録
  if (/\[\\s\\S\]/.test(regexStr)) {
    issues.push('[\\s\\S] multiline dot — wrap with (?s:...) for Rust regex');
  }

  return issues;
}

// JS 正規表現文字列を Rust regex 向けに変換する
// 変換できない場合は null を返す
function convertToRustRegex(regexStr, flags) {
  const issues = checkRustRegexCompat(regexStr);

  // lookbehind は fancy-regex クレートで対応済み（変換不可の除外を解除）

  let converted = regexStr;

  // [\s\S] を (?s:.) に変換（Rust regex / fancy-regex の DOTALL 相当）
  converted = converted.replace(/\[\\s\\S\]\*\?/g, '(?s:.)*?');
  converted = converted.replace(/\[\\s\\S\]\*/g, '(?s:.)*');
  converted = converted.replace(/\[\\s\\S\]/g, '(?s:.)');

  // 大文字小文字無視フラグは regex 内の (?i) で表現
  let prefix = '';
  if (flags && flags.includes('i')) {
    prefix = '(?i)';
  }

  return { converted: prefix + converted, issues };
}

// XOR エンコード
function xorEncode(str, key) {
  const bytes = Buffer.from(str, 'utf8');
  const encoded = Buffer.alloc(bytes.length);
  for (let i = 0; i < bytes.length; i++) {
    encoded[i] = bytes[i] ^ key[i % key.length];
  }
  return encoded;
}

// バイト配列を Rust の配列リテラル文字列にする
function toRustByteArray(buf) {
  return Array.from(buf).join(', ');
}

// 文字列を Rust の文字列リテラルとしてエスケープ
function escapeRustStr(s) {
  return s.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

async function main() {
  // 1. src/patterns.mjs を dynamic import
  const patternsPath = join(ROOT, 'src', 'patterns.mjs');
  const patternsUrl = new URL(`file://${patternsPath.replace(/\\/g, '/')}`);

  let loadPatterns;
  try {
    const mod = await import(patternsUrl.href);
    loadPatterns = mod.loadPatterns;
  } catch (e) {
    console.error('Failed to import src/patterns.mjs:', e.message);
    process.exit(1);
  }

  // patterns.mjs は NEKO_NOT_YOSHI_DIR / ngwords.public.json がない環境でも動作するよう設計済み
  // loadPatterns() で BUILTIN + EXTRA がまとめて返る
  const compiled = loadPatterns();

  // 2. BUILTIN_PATTERNS + EXTRA_PATTERNS を分離せず全件使う（loadPatterns の結果）
  //    private word は wasm 非対応としてスキップ
  const patterns = compiled.filter(p => !p.isPrivateWord);

  // 3. 32バイトのランダム XOR キーを生成
  const XOR_KEY = randomBytes(32);

  // 4. 各パターンの互換性チェック + XOR エンコード
  const validatorMap = [];
  const rustPatterns = [];
  let id = 0;

  for (const p of patterns) {
    const regexSrc = p.regex.source;
    const flags = p.regex.flags.replace('g', ''); // g フラグは Rust では不要

    const { converted, issues } = convertToRustRegex(regexSrc, flags);
    const wasmSupported = converted !== null;
    const hasValidator = p.validator !== null;

    validatorMap.push({
      id,
      name: p.id,
      category: p.category,
      wasmSupported,
      hasValidator,
      ...(hasValidator && { validatorName: `validate_${p.id.replace(/-/g, '_')}` }),
      ...(!wasmSupported && { reason: issues.join('; ') }),
    });

    if (wasmSupported) {
      const encoded = xorEncode(converted, XOR_KEY);
      rustPatterns.push({
        id,
        name: p.id,
        category: p.category,
        maskPrefix: p.maskPrefix,
        encodedBytes: encoded,
      });
    } else {
      console.log(`[SKIP] ${p.id}: ${issues.join('; ')}`);
    }

    id++;
  }

  // 5. 非互換パターン一覧を出力
  const incompatible = validatorMap.filter(v => !v.wasmSupported);
  if (incompatible.length > 0) {
    console.log('\n=== WASM 非対応パターン一覧 ===');
    for (const v of incompatible) {
      console.log(`  ${v.name}: ${v.reason}`);
    }
    console.log('');
  }

  // 6. Rust ソースコード生成
  const keyBytes = toRustByteArray(XOR_KEY);

  const patternDefs = rustPatterns.map(p => {
    const nameEsc = escapeRustStr(p.name);
    const catEsc = escapeRustStr(p.category);
    const bytes = toRustByteArray(p.encodedBytes);
    // PERSON パターンは validator 棄却後の重複位置マッチを拾うため overlap scan が必要
    const overlap = p.maskPrefix === 'PERSON' ? 'true' : 'false';
    return `    PatternDef { id: ${p.id}, name: "${nameEsc}", category: "${catEsc}", mask_prefix: "${escapeRustStr(p.maskPrefix)}", encoded_regex: &[${bytes}], overlap_scan: ${overlap} },`;
  }).join('\n');

  const rustSrc = `// AUTO-GENERATED by codegen-patterns.mjs — DO NOT EDIT
// Regenerate: node scripts/codegen-patterns.mjs

use once_cell::sync::Lazy;
use fancy_regex::Regex;

const XOR_KEY: &[u8] = &[${keyBytes}];

struct PatternDef {
    id: u32,
    name: &'static str,
    category: &'static str,
    mask_prefix: &'static str,
    encoded_regex: &'static [u8],
    overlap_scan: bool,
}

const PATTERNS: &[PatternDef] = &[
${patternDefs}
];

fn xor_decode(encoded: &[u8]) -> String {
    String::from_utf8(
        encoded
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ XOR_KEY[i % XOR_KEY.len()])
            .collect(),
    )
    .expect("invalid UTF-8 after XOR decode")
}

pub static COMPILED_PATTERNS: Lazy<Vec<(u32, &'static str, &'static str, &'static str, Regex, bool)>> =
    Lazy::new(|| {
        PATTERNS
            .iter()
            .filter_map(|p| {
                let regex_str = xor_decode(p.encoded_regex);
                match Regex::new(&regex_str) {
                    Ok(re) => Some((p.id, p.name, p.category, p.mask_prefix, re, p.overlap_scan)),
                    Err(_) => None,
                }
            })
            .collect()
    });
`;

  // 7. ファイル書き出し
  const rustDir = join(ROOT, 'rust', 'src');
  mkdirSync(rustDir, { recursive: true });

  const rsPath = join(rustDir, 'generated_patterns.rs');
  writeFileSync(rsPath, rustSrc, 'utf8');
  console.log(`Written: ${rsPath}`);

  const mapPath = join(ROOT, 'rust', 'pattern-validator-map.json');
  writeFileSync(mapPath, JSON.stringify(validatorMap, null, 2) + '\n', 'utf8');
  console.log(`Written: ${mapPath}`);

  console.log(`\nTotal patterns: ${patterns.length}`);
  console.log(`WASM supported: ${rustPatterns.length}`);
  console.log(`WASM skipped:   ${incompatible.length}`);
}

main().catch(e => {
  console.error(e);
  process.exit(1);
});
