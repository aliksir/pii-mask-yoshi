#!/usr/bin/env node
// AUTO-GENERATED-TOOL: codegen-patterns.mjs
// Reads src/patterns.mjs and emits rust/src/generated_patterns.rs + rust/pattern-validator-map.json
// パターン定義（src/encoded-data.mjs）はローカルにだけ存在する。公開物に入るのは暗号化済みの WASM だけ

import { randomBytes, createCipheriv, pbkdf2Sync } from 'node:crypto';
import { writeFileSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');

// ここから JS 正規表現 → Rust 正規表現の変換
// JS と Rust で意味が違う構文（\d \w \b . と文字クラス内の [ & ~）を、JS と同じマッチになる形に書き換える。
// 1つの JS パターンから4種類の文字列を作る:
//   meta:  regex-automata 用（線形時間）。\b は JS と同じ ASCII 単語境界 (?-u:\b)
//   fancy: fancy-regex 用（lookaround を含むパターン向け）。fancy は (?-u:) を解釈できないため \b はそのまま
//   skel:  lookaround を取り除いた版。一致の開始位置になりうる場所を線形時間で探すための上位集合
//   span:  lookaround の中身も文字を消費するとみなした版。1回の照合が触れる範囲の上限を求めるために使う
function translate(src) {
  const out = { meta: '', fancy: '', skel: '', span: '' };
  const stack = []; // 開き括弧の種類（'look' = lookaround / 'group' = それ以外）
  let inClass = false;
  // skel は lookaround の内側を出力しない
  const emit = (meta, fancy = meta, span = meta) => {
    out.meta += meta;
    out.fancy += fancy;
    out.span += span;
    if (!stack.includes('look')) out.skel += meta;
  };

  for (let i = 0; i < src.length; i++) {
    const c = src[i];

    // エスケープ: \d \w \b は JS（ASCII）の意味に合わせる。\uXXXX は Rust が確実に読める \x{XXXX} にする
    if (c === '\\') {
      const n = src[i + 1];
      i++;
      if (n === 'u' && /^[0-9A-Fa-f]{4}$/.test(src.slice(i + 1, i + 5))) {
        emit(`\\x{${src.slice(i + 1, i + 5)}}`);
        i += 4;
      } else if (inClass) {
        if (n === 'd') emit('0-9');
        else if (n === 'w') emit('0-9A-Za-z_');
        else emit('\\' + n);
      } else if (n === 'd') emit('[0-9]');
      else if (n === 'D') emit('[^0-9]');
      else if (n === 'w') emit('[0-9A-Za-z_]');
      else if (n === 'W') emit('[^0-9A-Za-z_]');
      else if (n === 'b' || n === 'B') emit(`(?-u:\\${n})`, `\\${n}`, `(?-u:\\${n})`);
      else emit('\\' + n);
      continue;
    }

    // 文字クラスの内側: JS ではリテラルだが Rust では入れ子クラス・集合演算になる [ & ~ をエスケープする
    if (inClass) {
      if (c === ']') { inClass = false; emit(']'); }
      else if (c === '[' || c === '&' || c === '~') emit('\\' + c);
      else emit(c);
      continue;
    }
    if (c === '[') { inClass = true; emit('['); continue; }

    // 括弧: lookaround は meta/fancy にはそのまま、span では非キャプチャグループとして出す
    if (c === '(') {
      const m = /^\(\?(?:=|!|<=|<!)/.exec(src.slice(i));
      if (m) {
        out.meta += m[0];
        out.fancy += m[0];
        out.span += '(?:';
        stack.push('look');
        i += m[0].length - 1;
      } else {
        emit('(');
        stack.push('group');
      }
      continue;
    }
    if (c === ')') {
      const kind = stack.pop();
      if (kind === 'look') {
        out.meta += ')';
        out.fancy += ')';
        out.span += ')';
      } else {
        emit(')');
      }
      continue;
    }

    // JS の . は改行類（\n \r U+2028 U+2029）にマッチしない。Rust の . は \n 以外にマッチするため明示する
    if (c === '.') { emit('[^\\n\\r\\x{2028}\\x{2029}]'); continue; }
    emit(c);
  }
  return out;
}

// 先頭の肯定 lookbehind（(?<=ラベル)値）の閉じ括弧位置を返す。先頭が肯定 lookbehind でなければ -1
function leadingLookbehindEnd(src) {
  if (!src.startsWith('(?<=')) return -1;
  let depth = 0;
  let inClass = false;
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (c === '\\') { i++; continue; }
    if (inClass) { if (c === ']') inClass = false; continue; }
    if (c === '[') inClass = true;
    else if (c === '(') depth++;
    else if (c === ')') { depth--; if (depth === 0) return i; }
  }
  return -1;
}

// JS パターン1件を Rust 向けの定義に変換する
// 先頭の肯定 lookbehind は fancy-regex が可変長を扱えないため、meta では「ラベル(?P<pmv>値)」の消費型に変え、
// Rust 側がキャプチャ pmv の範囲をマッチ位置として返す（group=true）
function convertPattern(regexSrc, flags) {
  const prefix = flags.includes('i') ? '(?i)' : '';
  const t = translate(regexSrc);
  const def = {
    meta: prefix + t.meta,
    fancy: prefix + t.fancy,
    skel: prefix + t.skel,
    span: prefix + t.span,
    group: false,
  };
  const lbEnd = leadingLookbehindEnd(regexSrc);
  if (lbEnd > 0) {
    const label = translate(regexSrc.slice(4, lbEnd)).meta;
    const value = translate(regexSrc.slice(lbEnd + 1)).meta;
    def.meta = `${prefix}(?:${label})(?P<pmv>${value})`;
    def.group = true;
  }
  return def;
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
  // 1. 生成対象を固定する: business パターンも収録し（実行時に有効/無効を切り替える）、
  //    利用者の ngwords.public.json で BUILTIN が置き換わらないよう存在しないディレクトリを指す
  process.env.PII_MASK_BUSINESS = '1';
  process.env.NEKO_NOT_YOSHI_DIR = join(ROOT, '.codegen-no-ngwords');

  // src/patterns.mjs を dynamic import（パターン定義 src/encoded-data.mjs が必要）
  const patternsPath = join(ROOT, 'src', 'patterns.mjs');
  const patternsUrl = new URL(`file://${patternsPath.replace(/\\/g, '/')}`);

  let mod;
  try {
    mod = await import(patternsUrl.href);
  } catch (e) {
    console.error('Failed to import src/patterns.mjs:', e.message);
    process.exit(1);
  }
  // パターン定義がない環境（公開リポ・npm パッケージ）では WASM を生成できない
  const aux = mod._codegenAux();
  if (!aux) {
    console.error('src/encoded-data.mjs が見つからないため WASM を生成できません（パターンソースは非公開）');
    process.exit(1);
  }

  // 2. BUILTIN + EXTRA（business 含む）を loadPatterns() の順序どおりに全件使う
  //    非公開NGワードはユーザ辞書由来なので WASM に入れない（JS 側で走査する）
  const { patterns: compiled } = mod.loadPatterns();
  const patterns = compiled.filter(p => !p.isPrivateWord);

  // 3. seed(32B) と salt(16B) をランダム生成し、PBKDF2 で AES-256 鍵を導出する
  // seed と salt を Rust 側の定数として埋め込む（鍵自体は埋め込まない）
  const SEED = randomBytes(32);
  const SALT = randomBytes(16);
  const ITERATIONS = 100000;
  // PBKDF2-SHA256: seed + salt → 32バイトの AES 鍵
  const aesKey = pbkdf2Sync(SEED, SALT, ITERATIONS, 32, 'sha256');
  const enc = (s) => toRustByteArray(aesGcmEncrypt(s, aesKey));

  // 4. 各パターンを変換して暗号化する
  const validatorMap = [];
  const patternDefs = [];
  patterns.forEach((p, id) => {
    const flags = p.regex.flags.replace('g', ''); // g フラグは Rust では不要
    const d = convertPattern(p.regex.source, flags);
    validatorMap.push({
      id,
      name: p.id,
      category: p.category,
      hasValidator: p.validator != null,
      group: d.group,
    });
    // PERSON パターンは validator 棄却後の重複位置マッチを拾うため overlap scan が必要
    const overlap = p.maskPrefix === 'PERSON' ? 'true' : 'false';
    const conf = p.defaultConfidence != null ? `Some(${Number(p.defaultConfidence).toFixed(3)})` : 'None';
    patternDefs.push(
      `    PatternDef { id: ${id}, name: "${escapeRustStr(p.id)}", category: "${escapeRustStr(p.category)}", ` +
      `mask_prefix: "${escapeRustStr(p.maskPrefix)}", default_confidence: ${conf}, overlap_scan: ${overlap}, group: ${d.group}, ` +
      `meta: &[${enc(d.meta)}], fancy: &[${enc(d.fancy)}], skel: &[${enc(d.skel)}], span: &[${enc(d.span)}] },`,
    );
  });

  // 5. validator 用の姓・敬称リストも暗号化して収録する（JS の JP_SURNAME_RE 等と同じ正規表現）
  const auxDefs = [
    ['AUX_SURNAME_PREFIX', `^(?:${aux.surnames})`],
    ['AUX_SURNAME_EXACT', `^(?:${aux.surnames})$`],
    ['AUX_HONORIFIC_SUFFIX', `(?:${aux.honorifics})$`],
  ].map(([name, src]) => `pub const ${name}: &[u8] = &[${enc(translate(src).meta)}];`).join('\n');

  // 6. Rust ソースコード生成
  const rustSrc = `// AUTO-GENERATED by codegen-patterns.mjs — DO NOT EDIT
// Regenerate: node scripts/codegen-patterns.mjs

use aes_gcm::{Aes256Gcm, KeyInit};
use aes_gcm::aead::{Aead, generic_array::{GenericArray, typenum::consts::U12}};
use once_cell::sync::Lazy;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

// codegen 時にランダム生成した seed（32バイト）と salt（16バイト）
// 鍵自体はバイナリに埋め込まず、起動時に PBKDF2 で導出する
const SEED: &[u8; 32] = &[${toRustByteArray(SEED)}];
const SALT: &[u8; 16] = &[${toRustByteArray(SALT)}];
const ITERATIONS: u32 = ${ITERATIONS};

// パターン1件の定義。正規表現は4種類とも暗号化済み（フォーマット: [nonce(12B) | ciphertext | tag(16B)]）
pub struct PatternDef {
    pub id: u32,
    pub name: &'static str,
    pub category: &'static str,
    pub mask_prefix: &'static str,
    pub default_confidence: Option<f64>,
    pub overlap_scan: bool,
    // true のとき meta はキャプチャ pmv の範囲をマッチ位置として返す（先頭 lookbehind の消費型変換）
    pub group: bool,
    pub meta: &'static [u8],
    pub fancy: &'static [u8],
    pub skel: &'static [u8],
    pub span: &'static [u8],
}

pub const PATTERNS: &[PatternDef] = &[
${patternDefs.join('\n')}
];

// validator 用の姓・敬称の正規表現（暗号化済み）
${auxDefs}

// PBKDF2-SHA256 で seed + salt → 32バイトの AES-256 鍵を起動時に一度だけ導出する
static KEY: Lazy<[u8; 32]> = Lazy::new(|| {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(SEED, SALT, ITERATIONS, &mut key);
    key
});

// AES-256-GCM で暗号化済みの文字列を復号する
// nonce(12) + tag(16) = 最小28バイト未満、または認証タグ不一致は None を返す
pub fn decrypt(encrypted: &[u8]) -> Option<String> {
    if encrypted.len() < 28 {
        return None;
    }
    // 先頭12バイトを nonce として取り出す（U12 = 12バイト固定サイズ型）
    let nonce = GenericArray::<u8, U12>::from_slice(&encrypted[..12]);
    // 残りが ciphertext + tag（aes-gcm クレートは末尾16バイトを tag として扱う）
    let cipher = Aes256Gcm::new_from_slice(&*KEY).ok()?;
    let plaintext = cipher.decrypt(nonce, &encrypted[12..]).ok()?;
    String::from_utf8(plaintext).ok()
}
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
}

main().catch(e => {
  console.error(e);
  process.exit(1);
});
