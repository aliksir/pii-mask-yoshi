// masker.mjs — PIIマスキングの中核モジュール
// WASM版エンジン（高速・71パターン）とJS版フォールバックのハイブリッド構成
// WASM検出結果とJS検出結果をマージし、重複除去して最終マスク文字列を生成する

import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { loadPatterns, getValidator, _setWasmAux, HAS_JS_PATTERN_DATA } from './patterns.mjs';
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

    // flags: bit0 = business パターンを有効にする（PII_MASK_BUSINESS=1 相当）
    _wasmFindMatches = (input, flags = 0) => {
      let d0, d1;
      try {
        const ptr0 = passString(input);
        const ret = wasm.find_matches(ptr0, vecLen, flags);
        d0 = ret[0]; d1 = ret[1];
        const parsed = JSON.parse(getString(ret[0], ret[1]));
        // WASM 側の走査失敗（backtrack_limit 超過等）は {"error": ...} で返る。部分結果を使わず失敗として投げ、JS 経路へ落とす
        if (!Array.isArray(parsed)) throw new Error(parsed?.error ?? 'unexpected WASM result');
        return parsed;
      } finally {
        if (d0 !== undefined) wasm.__wbindgen_free(d0, d1, 1);
      }
    };

    // WASM に収録されている（コンパイルできた）パターン ID 一覧。maskText はここに無いパターンを JS で走査する
    // 取得に失敗した場合は空集合にし、全パターンを JS でも走査する側に倒す（検出漏れより二重走査を選ぶ）
    let ids = [];
    try {
      const ret = wasm.pattern_ids();
      try {
        ids = JSON.parse(getString(ret[0], ret[1]));
      } finally {
        wasm.__wbindgen_free(ret[0], ret[1], 1);
      }
    } catch (e) {
      process.stderr.write(`[pii-mask-yoshi] WASM pattern_ids failed: ${e.message}\n`);
    }
    _wasmFindMatches.patternIds = new Set(Array.isArray(ids) ? ids : []);

    // validator 用の姓・敬称判定を WASM 側で行えるようにする（JS パターンデータが無い npm 版で使われる）
    // kind: 0 = 先頭の姓 / 1 = 姓と完全一致か / 2 = 末尾の敬称。判定できない場合は例外（validator の素通し防止）
    const auxQuery = (kind, str) => {
      const ptr0 = passString(str);
      const ret = wasm.aux_query(kind, ptr0, vecLen);
      try {
        const parsed = JSON.parse(getString(ret[0], ret[1]));
        if (parsed.error) throw new Error(`[pii-mask-yoshi] WASM aux_query failed: ${parsed.error}`);
        return parsed.m;
      } finally {
        wasm.__wbindgen_free(ret[0], ret[1], 1);
      }
    };
    _setWasmAux({
      surnamePrefix: (str) => auxQuery(0, str),
      surnameExact: (str) => auxQuery(1, str),
      honorificSuffix: (str) => auxQuery(2, str),
    });
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

  // WASM版パターンマッチング（全71パターン対応、AES-256-GCM 暗号化済みバイナリ）
  const wasmFn = getWasmFindMatches();
  let wasmSuccess = false;
  if (wasmFn) {
    try {
      const wasmMatches = wasmFn(result, process.env.PII_MASK_BUSINESS === '1' ? 1 : 0);
      const patById = new Map(pats.map((p) => [p.id, p]));
      for (const wm of wasmMatches) {
        const matched = result.slice(wm.start, wm.end);
        // JS パターンデータが無い npm 版では pats に組込パターンが無いため、validator と既定の確信度を WASM の結果から補う
        const pat = patById.get(wm.name) ?? {
          id: wm.name,
          category: wm.category,
          maskPrefix: wm.maskPrefix,
          validator: getValidator(wm.name),
          defaultConfidence: wm.defaultConfidence,
        };
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
  // npmパッケージには JS パターンデータが無いため、WASM失敗=検出エンジンなし。
  // 非公開・公開NGワード辞書があると pats が空にならず usedPubPath で下のチェックも外れるため、辞書の有無より先に判定する
  if (!wasmSuccess && !HAS_JS_PATTERN_DATA) {
    throw new Error('[pii-mask-yoshi] No detection engine available (WASM failed, JS patterns not bundled)');
  }
  const EXPECTED_BUILTIN_COUNT = 5;
  if (!wasmSuccess && pats.length === 0) {
    throw new Error('[pii-mask-yoshi] No detection engine available (WASM failed, JS patterns not bundled)');
  }
  // BUILTINパターン数が期待値を下回る場合は検出エンジン劣化として例外を投げる
  // pubPath使用時はBUILTINが代替されているためこのチェックをスキップする
  if (!wasmSuccess && !meta.usedPubPath && meta.builtinCount < EXPECTED_BUILTIN_COUNT) {
    throw new Error(`[pii-mask-yoshi] Detection engine degraded: BUILTIN patterns ${meta.builtinCount}/${EXPECTED_BUILTIN_COUNT} (expected all)`);
  }

  // JS版パターン走査（WASM失敗時のフォールバック＋WASM未収録パターン）
  // WASM成功時: WASM に収録済みのパターンだけスキップする。未収録のもの（非公開NGワードは顧客語をバイナリに
  //   焼かないため codegen-patterns.mjs で除外、business はビルド時に無効なら未収録、復号失敗分も未収録）は JS で走査する
  // WASM失敗時: 全パターンをJS版で走査
  // この値は getWasmFindMatches() が WASM の pattern_ids() から取得（モック等で無い場合は空集合＝全走査）
  const wasmIds = wasmSuccess ? (wasmFn.patternIds ?? new Set()) : null;
  for (const p of pats) {
    if (wasmSuccess && wasmIds.has(p.id)) continue;
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
        isPrivateWord: !!p.isPrivateWord,
      });

      if (overlapScan) {
        p.regex.lastIndex = m.index + 1;
      } else if (m.index === p.regex.lastIndex) {
        p.regex.lastIndex++;
      }
    }
  }

  // ここから除外処理（ANTI_CONTEXT / min_confidence）→ 重複除去 → 非公開NGワードの強制マスクの順に処理する
  // 除外を重複除去より先に行うのは、後で捨てられるマッチが重なった有効なマッチを先に潰すのを防ぐため
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

  // ANTI_CONTEXT（「テスト用」等の文脈）による人名の抑制。非公開NGワードは登録語なので抑制しない
  const passesAntiContext = (r) => {
    if (r.isPrivateWord) return true;
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
  };

  // min_confidence 未満のマッチを除外する。非公開NGワードは登録語なので閾値に関わらず残す
  const minConf = options.min_confidence ?? 0.0;
  const candidates = replacements.filter(r =>
    passesAntiContext(r) && (r.isPrivateWord || minConf <= 0 || r.confidence >= minConf));

  // 非公開NGワード以外の重複除去（開始位置順・同位置は長い方を優先し、範囲が重なる後続は捨てる）
  const others = candidates.filter(r => !r.isPrivateWord);
  others.sort((a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start));
  const seen = new Set();
  const deduped = [];
  for (const r of others) {
    const key = `${r.start}:${r.end}`;
    if (seen.has(key)) continue;
    if (deduped.some(d => r.start < d.end && r.end > d.start)) continue;
    seen.add(key);
    deduped.push(r);
  }

  // 非公開NGワードは必ずマスクする。他のマッチと重なる場合は捨てずに範囲を和集合へ広げて1つの置換にまとめる
  // （NGワードを捨てると語が残り、他方を捨てると他方の PII の一部が残るため、どちらも残さない）
  const privates = candidates.filter(r => r.isPrivateWord);
  privates.sort((a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start));
  let final = deduped;
  for (const pw of privates) {
    let start = pw.start;
    let end = pw.end;
    const rest = [];
    for (const d of final) {
      if (d.start < end && d.end > start) {
        start = Math.min(start, d.start);
        end = Math.max(end, d.end);
      } else {
        rest.push(d);
      }
    }
    rest.push({ ...pw, start, end, original: result.slice(start, end), confidence: 1.0 });
    final = rest;
  }
  // 後ろから置換するため開始位置の降順に並べる
  final.sort((a, b) => b.start - a.start);

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
