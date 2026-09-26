// pii-engine — WASM版PIIパターンマッチングエンジン
// codegen-patterns.mjs が生成した generated_patterns.rs の暗号化済み正規表現を復号・コンパイルし、
// 入力テキストからPII（個人情報）候補を検出してJSON配列で返す

use once_cell::sync::Lazy;
use regex_automata::{meta, Input};
use serde::Serialize;
use wasm_bindgen::prelude::*;

// generated_patterns.rs は codegen-patterns.mjs が自動生成する（手動編集禁止）
mod generated_patterns;
use generated_patterns::{decrypt, PATTERNS};

// JS側に返すマッチ結果の構造体（JSON直列化用）
#[derive(Serialize)]
struct PiiMatch {
    #[serde(rename = "patternId")]
    pattern_id: u32,
    // start/end はUTF-16コードユニット位置（JSのString.sliceと互換にするため）
    start: usize,
    end: usize,
    category: String,
    matched: String,
    name: String,
    #[serde(rename = "maskPrefix")]
    mask_prefix: String,
    #[serde(rename = "defaultConfidence", skip_serializing_if = "Option::is_none")]
    default_confidence: Option<f64>,
}

// ここからパターンごとの照合エンジン
// Meta: regex-automata（線形時間。backtrack 上限なし）。lookaround を含まないパターンはすべてこちら
// Fancy: fancy-regex（lookaround を含むパターン）。lookaround を除いた骨格（Meta）で開始位置の候補を探し、
//        候補位置の前後の有界な窓だけを fancy で照合する。入力全体を fancy の VM で走査しないため、
//        入力長に比例して backtrack 回数が積み上がる失敗（約50KB超で発生していた）を起こさない
enum Engine {
    Meta { re: meta::Regex, group: Option<usize> },
    Fancy { re: fancy_regex::Regex, skel: Option<meta::Regex>, window: Option<usize> },
}

struct Compiled {
    id: u32,
    name: &'static str,
    category: &'static str,
    mask_prefix: &'static str,
    default_confidence: Option<f64>,
    overlap_scan: bool,
    engine: Engine,
}

// 先頭 lookbehind を消費型に変えたパターンで、ラベル部分が値の開始位置より手前に伸びうる最大バイト数
// （ラベル語＋区切り記号＋空白。これを超える空白の連続は想定しない）
const LOOKBACK: usize = 256;
// fancy の照合窓に足す余白（バイト）
const WINDOW_MARGIN: usize = 16;

// 暗号化済み定義からエンジンを組み立てる。meta でコンパイルできればそれを使い、できなければ fancy を使う
// どちらもコンパイルできないパターンは収録しない（pattern_ids に載らないため JS 側が走査する）
fn build(def: &generated_patterns::PatternDef) -> Option<Engine> {
    let meta_src = decrypt(def.meta)?;
    if let Ok(re) = meta::Regex::new(&meta_src) {
        let group = if def.group {
            Some(re.group_info().to_index(regex_automata::PatternID::ZERO, "pmv")?)
        } else {
            None
        };
        return Some(Engine::Meta { re, group });
    }
    // 先頭 lookbehind 変換の対象は meta で扱えることが前提（fancy は位置の読み替えをしない）
    if def.group {
        return None;
    }
    let re = fancy_regex::Regex::new(&decrypt(def.fancy)?).ok()?;
    let skel = decrypt(def.skel).and_then(|s| meta::Regex::new(&s).ok());
    // 1回の照合が触れる範囲の上限（lookaround の中身も含めた最大長）。上限が無いパターンは窓を使わない
    let window = decrypt(def.span)
        .and_then(|s| regex_syntax::parse(&s).ok())
        .and_then(|h| h.properties().maximum_len())
        .map(|n| n + WINDOW_MARGIN);
    Some(Engine::Fancy { re, skel, window })
}

// 起動時に一度だけ全パターンを復号・コンパイルする
static COMPILED: Lazy<Vec<Compiled>> = Lazy::new(|| {
    PATTERNS
        .iter()
        .filter_map(|p| {
            Some(Compiled {
                id: p.id,
                name: p.name,
                category: p.category,
                mask_prefix: p.mask_prefix,
                default_confidence: p.default_confidence,
                overlap_scan: p.overlap_scan,
                engine: build(p)?,
            })
        })
        .collect()
});

// UTF-8 の文字境界へ丸める（窓の切り出しに使う）
fn floor_boundary(s: &str, mut i: usize) -> usize {
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}
fn ceil_boundary(s: &str, mut i: usize) -> usize {
    while i < s.len() && !s.is_char_boundary(i) {
        i += 1;
    }
    i
}
// 位置 i の次の文字の開始位置（i が末尾なら末尾+1 を返し、呼び出し側の走査を終わらせる）
fn next_char(s: &str, i: usize) -> usize {
    i + s[i..].chars().next().map_or(1, |c| c.len_utf8())
}

impl Engine {
    // 位置 pos 以降で最も左のマッチ（開始, 終了）を返す。Err は照合エンジンの失敗（backtrack 上限超過等）
    fn find_at(&self, input: &str, pos: usize) -> Result<Option<(usize, usize)>, String> {
        match self {
            Engine::Meta { re, group: None } => {
                Ok(re.search(&Input::new(input).range(pos..)).map(|m| (m.start(), m.end())))
            }
            // 先頭 lookbehind の消費型: JS の lookbehind はラベルが pos より手前にあっても値が pos 以降なら一致するため、
            // ラベル分だけ手前から探し、値（pmv）の開始が pos 以降の最初のものを返す
            Engine::Meta { re, group: Some(gi) } => {
                let mut caps = re.create_captures();
                let mut start = floor_boundary(input, pos.saturating_sub(LOOKBACK));
                loop {
                    re.search_captures(&Input::new(input).range(start..), &mut caps);
                    let Some(m) = caps.get_match() else { return Ok(None) };
                    if let Some(g) = caps.get_group(*gi) {
                        if g.start >= pos {
                            return Ok(Some((g.start, g.end)));
                        }
                    }
                    if m.start() >= input.len() {
                        return Ok(None);
                    }
                    start = next_char(input, m.start());
                }
            }
            Engine::Fancy { re, skel: None, .. } => re
                .find_from_pos(input, pos)
                .map(|o| o.map(|m| (m.start(), m.end())))
                .map_err(|e| e.to_string()),
            Engine::Fancy { re, skel: Some(sk), window } => {
                let mut pos = pos;
                loop {
                    // 骨格（lookaround を除いた上位集合）で次の開始候補を探す
                    let Some(c) = sk.search(&Input::new(input).range(pos..)) else { return Ok(None) };
                    let s = c.start();
                    // 候補位置の前後だけを切り出して fancy で照合し、開始が候補位置と一致した場合だけ採用する
                    let (ws, we) = match window {
                        Some(w) => (
                            floor_boundary(input, s.saturating_sub(*w)),
                            ceil_boundary(input, (s + *w).min(input.len())),
                        ),
                        None => (0, input.len()),
                    };
                    if let Some(m) = re.find_from_pos(&input[ws..we], s - ws).map_err(|e| e.to_string())? {
                        if m.start() + ws == s {
                            return Ok(Some((s, m.end() + ws)));
                        }
                    }
                    if s >= input.len() {
                        return Ok(None);
                    }
                    pos = next_char(input, s);
                }
            }
        }
    }
}

// JS側から呼ばれるエントリポイント（wasm_bindgen経由）
// 入力テキストに対して全パターンを走査し、マッチ結果をJSON文字列で返す
// flags: bit0 = business パターン（金額・日付）を有効にする（PII_MASK_BUSINESS=1 相当）
// いずれかのパターンで照合エンジンが失敗した場合は {"error": ...} を返す（部分結果は返さない）
#[wasm_bindgen]
pub fn find_matches(input: &str, flags: u32) -> String {
    let business = flags & 1 == 1;
    let mut results: Vec<PiiMatch> = Vec::new();

    for p in COMPILED.iter() {
        // business は有効時だけ走査する（JS の loadPatterns と同じ扱い）
        if p.category == "business" && !business {
            continue;
        }
        let mut pos = 0;
        while pos <= input.len() {
            let (s, e) = match p.engine.find_at(input, pos) {
                Ok(Some(m)) => m,
                // 残りにマッチなし → このパターンの走査を終える
                Ok(None) => break,
                // 黙って打ち切ると検出漏れになるため全体を失敗として返す
                Err(e) => return error_json(p.name, &e),
            };
            let char_start = input[..s].encode_utf16().count();
            let char_end = char_start + input[s..e].encode_utf16().count();
            results.push(PiiMatch {
                pattern_id: p.id,
                start: char_start,
                end: char_end,
                category: p.category.to_string(),
                matched: input[s..e].to_string(),
                name: p.name.to_string(),
                mask_prefix: p.mask_prefix.to_string(),
                default_confidence: p.default_confidence,
            });
            // 次の走査位置: PERSON は validator 棄却後の重複位置マッチを拾うため開始の次の文字から、
            // それ以外は非重複でマッチ終端から（空マッチは1文字進める）
            pos = if p.overlap_scan || e == s {
                if s >= input.len() {
                    break;
                }
                next_char(input, s)
            } else {
                e
            };
        }
    }

    // JSON文字列にして返す（直列化失敗も空配列にせず失敗として返す。空配列だと検出0件と区別できないため）
    serde_json::to_string(&results).unwrap_or_else(|_| r#"{"error":"serialize failed"}"#.to_string())
}

// 走査失敗を JS 側へ伝える JSON を作る
// 成功時は配列、失敗時は {"error": ...} オブジェクトを返す約束で、JS 側は配列でなければ WASM 失敗として JS 経路へ落とす
fn error_json(pattern_name: &str, e: &str) -> String {
    serde_json::json!({ "error": format!("pattern {} failed: {}", pattern_name, e) }).to_string()
}

// WASM 側で実際にコンパイルできたパターンの ID 一覧を JSON 配列で返す
// JS 側はこの一覧に無いパターン（非公開NGワード・コンパイルできなかったもの）を WASM 成功時も JS で走査する
#[wasm_bindgen]
pub fn pattern_ids() -> String {
    let ids: Vec<&str> = COMPILED.iter().map(|p| p.name).collect();
    serde_json::to_string(&ids).unwrap_or_else(|_| "[]".to_string())
}

// ここから validator 用の姓・敬称判定（JS パターンデータが無い npm 版で patterns.mjs から呼ばれる）
static AUX: Lazy<Option<[meta::Regex; 3]>> = Lazy::new(|| {
    let c = |enc: &[u8]| decrypt(enc).and_then(|s| meta::Regex::new(&s).ok());
    Some([
        c(generated_patterns::AUX_SURNAME_PREFIX)?,
        c(generated_patterns::AUX_SURNAME_EXACT)?,
        c(generated_patterns::AUX_HONORIFIC_SUFFIX)?,
    ])
});

// kind: 0 = 先頭の姓（文字列）/ 1 = 姓と完全一致か（真偽）/ 2 = 末尾の敬称（文字列）
// 結果は {"m": ...}、判定できない場合は {"error": ...}
#[wasm_bindgen]
pub fn aux_query(kind: u32, s: &str) -> String {
    let Some(aux) = AUX.as_ref() else {
        return r#"{"error":"aux data unavailable"}"#.to_string();
    };
    let v = match kind {
        0 => serde_json::json!({ "m": aux[0].find(s).map_or("", |m| &s[m.range()]) }),
        1 => serde_json::json!({ "m": aux[1].is_match(s) }),
        2 => serde_json::json!({ "m": aux[2].find(s).map_or("", |m| &s[m.range()]) }),
        _ => serde_json::json!({ "error": "unknown kind" }),
    };
    v.to_string()
}
