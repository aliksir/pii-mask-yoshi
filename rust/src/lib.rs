// pii-engine — WASM版PIIパターンマッチングエンジン
// codegen-patterns.mjs が生成した generated_patterns.rs のコンパイル済み正規表現を使い、
// 入力テキストからPII（個人情報）候補を検出してJSON配列で返す

use wasm_bindgen::prelude::*;
use serde::Serialize;

// generated_patterns.rs は codegen-patterns.mjs が自動生成する（手動編集禁止）
mod generated_patterns;

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
}

// JS側から呼ばれるエントリポイント（wasm_bindgen経由）
// 入力テキストに対して全パターンを走査し、マッチ結果をJSON文字列で返す
#[wasm_bindgen]
pub fn find_matches(input: &str) -> String {
    // generated_patterns.rs で遅延初期化されたコンパイル済みパターン一覧を参照
    let patterns = &generated_patterns::COMPILED_PATTERNS;
    let mut results: Vec<PiiMatch> = Vec::new();

    // 各パターンで入力テキストを走査
    for (id, name, category, mask_prefix, re, overlap_scan) in patterns.iter() {
        if *overlap_scan {
            // PERSONパターン: validator棄却後の重複位置マッチを拾うため1文字ずつ進める
            let mut pos = 0;
            while pos < input.len() {
                match re.find_from_pos(input, pos) {
                    Ok(Some(mat)) => {
                        let char_start = input[..mat.start()].encode_utf16().count();
                        let char_end = char_start + mat.as_str().encode_utf16().count();
                        results.push(PiiMatch {
                            pattern_id: *id,
                            start: char_start,
                            end: char_end,
                            category: category.to_string(),
                            matched: mat.as_str().to_string(),
                            name: name.to_string(),
                            mask_prefix: mask_prefix.to_string(),
                        });
                        // 次の文字境界まで進める（UTF-8マルチバイト対応）
                        pos = mat.start();
                        pos += input[pos..].chars().next().map_or(1, |c| c.len_utf8());
                    }
                    _ => break,
                }
            }
        } else {
            // 通常パターン: 非重複マッチ（find_iter）
            for mat_result in re.find_iter(input) {
                if let Ok(mat) = mat_result {
                    let char_start = input[..mat.start()].encode_utf16().count();
                    let char_end = char_start + mat.as_str().encode_utf16().count();
                    results.push(PiiMatch {
                        pattern_id: *id,
                        start: char_start,
                        end: char_end,
                        category: category.to_string(),
                        matched: mat.as_str().to_string(),
                        name: name.to_string(),
                        mask_prefix: mask_prefix.to_string(),
                    });
                }
            }
        }
    }

    // JSON文字列にして返す（失敗時は空配列）
    serde_json::to_string(&results).unwrap_or_else(|_| "[]".to_string())
}
