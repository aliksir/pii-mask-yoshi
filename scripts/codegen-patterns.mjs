#!/usr/bin/env node
// AUTO-GENERATED-TOOL: codegen-patterns.mjs
// Reads src/patterns.mjs and emits rust/src/generated_patterns.rs + rust/pattern-validator-map.json

import { randomBytes, createCipheriv, pbkdf2Sync } from 'node:crypto';
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

// AES-256-GCM 暗号化
// 出力フォーマット: [nonce(12B) | ciphertext | tag(16B)]
// nonce は呼び出しごとにランダム生成（パターンごとに異なる nonce を使う）
function aesGcmEncrypt(str, key) {
  const plaintext = Buffer.from(str, 'utf8');
  // 12バイトの nonce（GCM 推奨サイズ）をパターンごとにランダム生成
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  // ciphertext と認証タグ(16B)を結合して返す
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag(); // GCM 認証タグ（16バイト固定）
  return Buffer.concat([nonce, ciphertext, tag]);
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
  // loadPatterns() で BUILTIN + EXTRA がまとめて返る（戻り値はオブジェクト形式）
  const { patterns: compiled } = loadPatterns();

  // 2. BUILTIN_PATTERNS + EXTRA_PATTERNS を分離せず全件使う（loadPatterns の結果）
  //    private word は wasm 非対応としてスキップ
  const patterns = compiled.filter(p => !p.isPrivateWord);

  // 3. seed(32B) と salt(16B) をランダム生成し、PBKDF2 で AES-256 鍵を導出する
  // seed と salt を Rust 側の定数として埋め込む（鍵自体は埋め込まない）
  const SEED = randomBytes(32);
  const SALT = randomBytes(16);
  const ITERATIONS = 100000;
  // PBKDF2-SHA256: seed + salt → 32バイトの AES 鍵
  const aesKey = pbkdf2Sync(SEED, SALT, ITERATIONS, 32, 'sha256');

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
      // AES-256-GCM で各パターンを個別暗号化（nonce はパターンごとにランダム）
      const encrypted = aesGcmEncrypt(converted, aesKey);
      rustPatterns.push({
        id,
        name: p.id,
        category: p.category,
        maskPrefix: p.maskPrefix,
        encodedBytes: encrypted,
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
  // seed/salt をバイト配列リテラルとして埋め込む（鍵自体は埋め込まない）
  const seedBytes = toRustByteArray(SEED);
  const saltBytes = toRustByteArray(SALT);

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
use aes_gcm::{Aes256Gcm, KeyInit};
use aes_gcm::aead::{Aead, generic_array::{GenericArray, typenum::consts::U12}};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

// codegen 時にランダム生成した seed（32バイト）と salt（16バイト）
// 鍵自体はバイナリに埋め込まず、起動時に PBKDF2 で導出する
const SEED: &[u8; 32] = &[${seedBytes}];
const SALT: &[u8; 16] = &[${saltBytes}];
const ITERATIONS: u32 = ${ITERATIONS};

struct PatternDef {
    id: u32,
    name: &'static str,
    category: &'static str,
    mask_prefix: &'static str,
    // 暗号化フォーマット: [nonce(12B) | ciphertext | tag(16B)]
    encoded_regex: &'static [u8],
    overlap_scan: bool,
}

const PATTERNS: &[PatternDef] = &[
${patternDefs}
];

// PBKDF2-SHA256 で seed + salt → 32バイトの AES-256 鍵を導出する
fn derive_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(SEED, SALT, ITERATIONS, &mut key);
    key
}

// AES-256-GCM で暗号化済みパターンを復号する
// フォーマット: [nonce(12B) | ciphertext | tag(16B)]
// nonce(12) + tag(16) = 最小28バイト未満は不正データとして None を返す
fn decrypt_pattern(key: &[u8; 32], encrypted: &[u8]) -> Option<String> {
    if encrypted.len() < 28 {
        return None;
    }
    // 先頭12バイトを nonce として取り出す（U12 = 12バイト固定サイズ型）
    let nonce = GenericArray::<u8, U12>::from_slice(&encrypted[..12]);
    // 残りが ciphertext + tag（aes-gcm クレートは末尾16バイトを tag として扱う）
    let ciphertext_with_tag = &encrypted[12..];
    let cipher = Aes256Gcm::new_from_slice(key).ok()?;
    // 認証付き復号（tag 検証失敗時は None）
    let plaintext = cipher.decrypt(nonce, ciphertext_with_tag).ok()?;
    String::from_utf8(plaintext).ok()
}

pub static COMPILED_PATTERNS: Lazy<Vec<(u32, &'static str, &'static str, &'static str, Regex, bool)>> =
    Lazy::new(|| {
        // 起動時に一度だけ鍵導出（PBKDF2）を実行する
        let key = derive_key();
        PATTERNS
            .iter()
            .filter_map(|p| {
                // 各パターンを AES-256-GCM で復号してから正規表現をコンパイルする
                let regex_str = decrypt_pattern(&key, p.encoded_regex)?;
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
