// masker.mjs — PIIマスキングの中核モジュール
// WASM版エンジン（高速・66パターン）とJS版フォールバックのハイブリッド構成
// WASM検出結果とJS検出結果をマージし、重複除去して最終マスク文字列を生成する

import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { loadPatterns } from './patterns.mjs';
import { MaskStore } from './store.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));

// WASMモジュールの遅延読み込み（初回呼び出し時に1回だけロード）
let _wasmFindMatches = null;
let _wasmLoadAttempted = false;

// WASM版find_matches関数を取得（ロード失敗時はnullを返す→JS版にフォールバック）
// wasm-pack 0.15+ は ESM を生成するため、.wasm を直接読んで initSync で同期初期化する
function getWasmFindMatches() {
  if (_wasmLoadAttempted) return _wasmFindMatches;
  _wasmLoadAttempted = true;
  try {
    // .wasm バイナリを同期読み込みし、WebAssembly.Module として直接インスタンス化
    const wasmPath = join(__dirname, '..', 'rust', 'pkg', 'pii_engine_bg.wasm');
    const wasmBytes = readFileSync(wasmPath);

    // wasm-pack 生成 ESM のインポート仕様に合わせた imports オブジェクト
    let instance;
    const imports = {
      './pii_engine_bg.js': {
        __wbindgen_init_externref_table() {
          const table = instance.exports.__wbindgen_externrefs;
          const offset = table.grow(4);
          table.set(0, undefined);
          table.set(offset + 0, undefined);
          table.set(offset + 1, null);
          table.set(offset + 2, true);
          table.set(offset + 3, false);
        },
      },
    };

    const wasmModule = new WebAssembly.Module(wasmBytes);
    instance = new WebAssembly.Instance(wasmModule, imports);
    const wasm = instance.exports;
    wasm.__wbindgen_start();

    // 文字列エンコーディングヘルパー（wasm-pack グルーコードから抽出した最小実装）
    const encoder = new TextEncoder();
    const decoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
    let cachedMem = null;
    const mem = () => cachedMem?.byteLength ? cachedMem : (cachedMem = new Uint8Array(wasm.memory.buffer));
    let vecLen = 0;

    // JS文字列を WASM メモリに書き込み、ポインタを返す
    function passString(arg) {
      const buf = encoder.encode(arg);
      const ptr = wasm.__wbindgen_malloc(buf.length, 1);
      mem().subarray(ptr, ptr + buf.length).set(buf);
      vecLen = buf.length;
      return ptr;
    }

    // WASMメモリから UTF-8 文字列を読み出す
    function getString(ptr, len) {
      return decoder.decode(mem().subarray(ptr, ptr + len));
    }

    _wasmFindMatches = (input) => {
      let d0, d1;
      try {
        const ptr0 = passString(input);
        const ret = wasm.find_matches(ptr0, vecLen);
        d0 = ret[0]; d1 = ret[1];
        return JSON.parse(getString(ret[0], ret[1]));
      } finally {
        if (d0 !== undefined) wasm.__wbindgen_free(d0, d1, 1);
      }
    };
  } catch (e) {
    process.stderr.write(`[pii-mask-yoshi] WASM init failed: ${e.message}\n`);
    _wasmFindMatches = null;
  }
  return _wasmFindMatches;
}

// パターンメタデータ（patterns配列とbuiltinCount/extraSkippedを含む）の遅延初期化キャッシュ
let patternsMeta = null;
const store = new MaskStore(); // [PERSON-001]等のマスクIDと原文の対応を保持

// 「テストデータ」「サンプル」等の文脈ではPII検出を抑制するためのパターン
const ANTI_CONTEXT = /(?:例[)）]|サンプルデータ|テストデータ|テスト用|ダミー|\bdummy\b|\bexample\b|\bsample\s+data\b)/i;
// メールのドメイン部分がexample.comならマスク対象外にするための正規表現
const emailDomainRe = /[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/g;
// 人名パターンのみANTI_CONTEXT抑制の対象にする（住所・電話等は抑制しない）
const ANTI_CONTEXT_IDS = new Set([
  'jp-person-name', 'jp-person-name-hira', 'jp-person-name-nospace', 'jp-person-name-list',
  'jp-person-name-honorific', 'jp-person-name-spaced-honorific', 'jp-label-name',
  'jp-furigana-name', 'jp-katakana-name', 'jp-name-nakaguro',
  'jp-person-name-fullspace',
]);

// パターンメタデータの遅延初期化（loadPatterns()を1回だけ呼び、結果をキャッシュする）
function ensurePatterns() {
  if (!patternsMeta) patternsMeta = loadPatterns();
  return patternsMeta;
}

// テスト用: パターンメタデータをリセット・差し替えする（本番コードからは呼ばない）
export function _resetPatternsForTest(meta) {
  patternsMeta = meta;
}

// テスト用: WASMの状態をリセット・差し替えする（本番コードからは呼ばない）
// fnにnullを渡すとWASMを無効化（_wasmLoadAttempted=trueでスキップ）
// fnにundefinedを渡すとWASM再ロードを許可（_wasmLoadAttempted=falseにリセット）
export function _resetWasmForTest(fn) {
  if (fn === undefined) {
    // WASM再ロードを許可するためにフラグをリセットする
    _wasmFindMatches = null;
    _wasmLoadAttempted = false;
  } else {
    // fnをモックとして設定し、再ロードを抑制する
    _wasmFindMatches = fn;
    _wasmLoadAttempted = true;
  }
}

// 文字位置から行番号を算出（レポート用）
function getLineNumber(text, charIndex) {
  let line = 1;
  for (let i = 0; i < charIndex && i < text.length; i++) {
    if (text[i] === '\n') line++;
  }
  return line;
}

// メインのマスキング関数
// テキストを受け取り、PII候補をマスク文字列（[PERSON-001]等）に置換して返す
export function maskText(text, filePath = null, options = {}) {
  // メタデータを展開してpats（パターン配列）とmeta（builtinCount等）を取得
  const { patterns: pats, ...meta } = ensurePatterns();
  let result = text;
  const replacements = []; // 検出したPII候補を一旦ここに集め、後でまとめて置換する

  // WASM側でPERSONパターンのoverlap scanを実装済み（lib.rs find_from_pos方式）
  // JS側のoverlap scanはWASM失敗時のフォールバックとしてのみ動作する

  // WASM版パターンマッチング（全66パターン対応、XOR保護済みバイナリ）
  const wasmFn = getWasmFindMatches();
  let wasmSuccess = false;
  if (wasmFn) {
    try {
      const wasmMatches = wasmFn(result);
      const patById = new Map(pats.map((p) => [p.id, p]));
      for (const wm of wasmMatches) {
        const matched = result.slice(wm.start, wm.end);
        const pat = patById.get(wm.name);
        let prefix = wm.maskPrefix ?? (pat ? pat.maskPrefix : wm.category.toUpperCase());
        let confidence = pat ? (pat.defaultConfidence ?? 1.0) : 1.0;
        // JS側のvalidatorをWASMマッチ結果に適用（人名FP抑制等）
        if (pat && pat.validator) {
          const v = pat.validator(matched, { text: result, start: wm.start, end: wm.end });
          if (v === null) continue;
          prefix = v.label;
          confidence = v.confidence;
        }
        replacements.push({
          start: wm.start,
          end: wm.end,
          original: matched,
          prefix,
          category: wm.category ?? (pat ? pat.category : 'pii'),
          patternId: wm.name,
          confidence,
        });
      }
      wasmSuccess = true;
    } catch (e) {
      process.stderr.write(`[pii-mask-yoshi] WASM find_matches failed: ${e.message}\n`);
    }
  }

  // Fail-Closed: WASM失敗時はBUILTINパターン全数チェックを行い、不足なら例外を投げる
  // npmパッケージでは encoded-data.mjs を除外するため、WASM失敗=検出エンジンなし
  const EXPECTED_BUILTIN_COUNT = 5;
  if (!wasmSuccess && pats.length === 0) {
    throw new Error('[pii-mask-yoshi] No detection engine available (WASM failed, JS patterns not bundled)');
  }
  // BUILTINパターン数が期待値を下回る場合は検出エンジン劣化として例外を投げる
  // pubPath使用時はBUILTINが代替されているためこのチェックをスキップする
  if (!wasmSuccess && !meta.usedPubPath && meta.builtinCount < EXPECTED_BUILTIN_COUNT) {
    throw new Error(`[pii-mask-yoshi] Detection engine degraded: BUILTIN patterns ${meta.builtinCount}/${EXPECTED_BUILTIN_COUNT} (expected all)`);
  }

  // JS版パターン走査（WASM失敗時のフォールバック）
  // WASM成功時: 全パターンをWASM側で処理済みのためスキップ
  // WASM失敗時: 全パターンをJS版で走査
  for (const p of pats) {
    if (wasmSuccess) continue;
    const overlapScan = p.maskPrefix === 'PERSON';
    p.regex.lastIndex = 0;
    let prevIndex = -1;
    let m;
    while ((m = p.regex.exec(result)) !== null) {
      if (m.index === prevIndex) break;
      prevIndex = m.index;
      const matched = m[0];

      let prefix = p.maskPrefix;
      let confidence = p.defaultConfidence ?? 1.0;
      if (p.validator) {
        const v = p.validator(matched, { text: result, start: m.index, end: m.index + matched.length });
        if (v === null) {
          if (overlapScan) {
            p.regex.lastIndex = m.index + 1;
          } else if (m.index === p.regex.lastIndex) {
            p.regex.lastIndex++;
          }
          continue;
        }
        prefix = v.label;
        confidence = v.confidence;
      }

      replacements.push({
        start: m.index,
        end: m.index + matched.length,
        original: matched,
        prefix,
        category: p.category,
        patternId: p.id,
        confidence,
      });

      if (overlapScan) {
        p.regex.lastIndex = m.index + 1;
      } else if (m.index === p.regex.lastIndex) {
        p.regex.lastIndex++;
      }
    }
  }

  // ここからマッチ結果の重複除去と最終マスク適用
  // WASM結果とJS結果がマージされているため、重複・オーバーラップを除去する
  replacements.sort((a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start));

  // 位置が完全一致するマッチと、範囲が重なるマッチを除去
  const seen = new Set();
  const deduped = [];
  for (const r of replacements) {
    const key = `${r.start}:${r.end}`;
    if (seen.has(key)) continue;
    let overlap = false;
    for (const d of deduped) {
      if (r.start < d.end && r.end > d.start) { overlap = true; break; }
    }
    if (overlap) continue;
    seen.add(key);
    deduped.push(r);
  }

  deduped.sort((a, b) => b.start - a.start);

  const EMAIL_DOMAIN_SAFE_RANGES = [];
  emailDomainRe.lastIndex = 0;
  let edm;
  while ((edm = emailDomainRe.exec(result)) !== null) {
    if (/example/i.test(edm[1])) {
      const domainStart = edm.index + edm[0].indexOf('@') + 1;
      EMAIL_DOMAIN_SAFE_RANGES.push([domainStart, edm.index + edm[0].length]);
    }
  }

  function isInEmailDomainSafeRange(pos) {
    return EMAIL_DOMAIN_SAFE_RANGES.some(([s, e]) => pos >= s && pos < e);
  }

  const filtered = deduped.filter(r => {
    if (!ANTI_CONTEXT_IDS.has(r.patternId)) return true;
    const ws = Math.max(0, r.start - 15);
    const we = Math.min(result.length, r.end + 15);
    const window = result.slice(ws, we);
    if (!ANTI_CONTEXT.test(window)) return true;
    // email ドメイン内の "example" が ANTI_CONTEXT を誤発動させている場合は除外しない（FN-34対応）
    // window 内の "example" が safe range に完全に含まれるか確認
    const exampleMatch = /\bexample\b/i.exec(window);
    if (exampleMatch) {
      const absolutePos = ws + exampleMatch.index;
      if (isInEmailDomainSafeRange(absolutePos)) return true;
    }
    return false;
  });

  const minConf = options.min_confidence ?? 0.0;
  const final = minConf > 0 ? filtered.filter(r => r.confidence >= minConf) : filtered;

  let masked = result;
  for (const r of final) {
    const token = store.getOrCreate(r.original, r.prefix);
    masked = masked.slice(0, r.start) + token + masked.slice(r.end);
    if (filePath) {
      store.addFinding(filePath, getLineNumber(text, r.start), r.category, token, r.confidence);
    }
  }

  store.save();
  return masked;
}

export function unmaskText(text) {
  return store.unmask(text);
}

export function getStore() {
  return store;
}
