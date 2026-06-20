# Threat Model — pii-mask-yoshi

更新日: 2026-06-20  
対象バージョン: 現行 src/masker.mjs + src/crypto.mjs + src/patterns.mjs

---

## 1. Assets（保護対象）

| Asset | 保存場所 | 説明 |
|-------|---------|------|
| **Mask Maps** | `~/.pii-mask-yoshi/maps/` | マスクトークン→原文の対応表。AES-256-GCM で暗号化 |
| **Pattern Definitions** | `src/encoded-data.mjs` / `ngwords.private.json` | PIIを検出する正規表現定義。XOR+base64 で難読化 |
| **Encryption Key** | `~/.pii-mask-yoshi/.key` or 環境変数 | Mask Mapsの暗号化鍵（32バイトランダム） |
| **生PII** | メモリ内のみ（一時）| マスク処理中の短命データ。ファイルに永続化しない |
| **ngwords.private.json** | `~/neko-not-yoshi/` | 顧客名・案件名等のプライベート検出ワード |

---

## 2. Threat Actors

| アクター | 動機 | 攻撃能力 |
|---------|------|---------|
| **悪意あるユーザー** | PII漏洩回避・検出迂回 | ローカルファイルアクセス可。入力テキスト制御可 |
| **中間者（ネットワーク）** | 送信データの盗聴 | MCP stdio通信の傍受。ただしstdioはローカルIPC |
| **コード読者（リバースエンジニア）** | パターン定義の抽出・複製 | ソースコード・バイナリの静的解析 |
| **外部AIサーバー** | 意図せぬPII受信 | Mask Maps にアクセス不可。マスク済みテキストのみ受信するはずだが、検出漏れがあれば生PIIを受信する |
| **プロセスインジェクション攻撃者** | ランタイムメモリ盗取 | 実行中 Node.js プロセスへのアタッチ |

---

## 3. Fail-Open vs Fail-Closed 判断

| 障害ケース | 現在の挙動 | 判断根拠 |
|-----------|----------|---------|
| **WASM ロード失敗** | Fail-Open（JS版にフォールバック） | 利便性優先。JS版も同等パターンをカバーするため機能的リスクは低い |
| **暗号化鍵なし** | Fail-Open（平文でMask Mapsを保存） | 鍵未生成の初回起動でも動作可能にするため。ただし Mask Maps が平文になるリスクあり |
| **patterns.mjs デコード失敗** | パターンなしで通過（スキップ） | 例外時に `compiled.push` が skip される。検出0件のまま平文が外部に流れる可能性がある |

> **注意**: WASM失敗はfail-openで許容されるが、パターンデコード失敗はPII検出ゼロになる深刻な状態。エラーログが出るのみで処理は続行される。

---

## 4. Regex 迂回経路

| 迂回手法 | 説明 | 影響 |
|---------|------|------|
| **全角/半角変換** | 「ａｌｉｃｅ＠ｅｘａｍｐｌｅ．ｃｏｍ」のような全角メールアドレス | patterns.mjs は NFKC 正規化を一部で実施（validateJpName）しているが、regex 自体はすべての文字変種に対応していない |
| **ゼロ幅文字挿入** | メール・電話番号の文字間にゼロ幅スペース（U+200B等）を挿入 | 正規表現ベースのパターンは連続文字列を期待するため検出不可 |
| **RTLマーク混入** | 右横書き制御文字（U+202E等）を挿入してパターンを分断 | 同上。正規表現はUnicodeの方向制御文字を無視しない |
| **エンコーディング変換** | URLエンコード（%40=%@）や HTMLエンティティで@を表現 | 正規表現マッチ前にデコードされない場合は迂回可能 |
| **分割改行** | 名前や電話番号の途中に改行を挿入 | `validateJpName` は `\n\r` を含む場合 null（除外）。ただし他パターンは改行非対応 |

---

## 5. Validator 棄却と Overlap Scan の False Negative リスク

### Validator 棄却による FN

`jp-person-name` の `validateJpPersonNameWithCtx` は多数の除外条件を持つ。以下の場合に人名を FN（見逃し）として棄却する：

- `COMMON_FIRST_WORDS`（「情報」「品質」等）に一致する場合
- `NON_NAME_ENDINGS`（「処理」「管理」等）で終わる場合
- 直前に金額パターン（`\d[万億兆百千円]`）がある場合

これらの除外条件は FP（誤検出）削減のために必要だが、**実在する人名が除外リストに一致すると FN になる**。例：「情報 太郎」のような名前は COMMON_FIRST_WORDS により棄却される。

### Overlap Scan の限界

WASM版は `find_from_pos` 方式でオーバーラップを処理するが、JS フォールバック時は `lastIndex = m.index + 1` によるスキャン。オーバーラップした長い名前リストが短いマッチに吸収される場合がある。

---

## 6. ANTI_CONTEXT 無効化による悪用

`ANTI_CONTEXT` パターン（`テストデータ`・`サンプル`・`example`等）が前後 15 文字の window 内に存在すると、PERSON 系パターンのマッチが**抑制**される。

### 悪用シナリオ

```
テストデータ: 山田 太郎（実際は本物の氏名）
```

攻撃者が「テストデータ」や「サンプル」の接頭語を実データの前に付加することで、本物の PII を意図的に検出回避できる。

### 適用範囲

`ANTI_CONTEXT_IDS` は PERSON 系パターン（10種）のみに限定。メールアドレス・電話番号・マイナンバー等は ANTI_CONTEXT の影響を**受けない**（こちらは安全）。

---

## 7. XOR 難読化の限界

`encoded-data.mjs` の XOR 難読化は**暗号学的保護ではなく obfuscation**。

| 項目 | 実態 |
|-----|------|
| 鍵の場所 | `XOR_KEY` 定数としてソースに直接埋め込み |
| デコード方法 | `Buffer.from(b, 'base64')` → XOR → UTF-8（7行で完結） |
| 保護の目的 | grep・静的解析での平文パターン直接参照を防止する |
| 保護の限界 | ソースコードまたはバイナリにアクセスできれば即座に全パターンが復元可能 |
| リバースエンジニアリング難易度 | 低い（鍵がソースに存在するため） |

XOR 難読化は「git grep で社内パターンが漏れる」リスクを下げるためのものであり、悪意ある解析者への耐性はほぼない。

---

## 8. Mitigations（既存の緩和策）

| 脅威 | 緩和策 | 実装箇所 |
|-----|--------|---------|
| Mask Maps 漏洩 | AES-256-GCM 暗号化（鍵あり時） | `crypto.mjs: encrypt/decrypt` |
| パターン直接参照 | XOR + base64 難読化 | `encoded-data.mjs` |
| 外部 AI への生 PII 送信 | safe_read がマスク後テキストのみ返す | `Purpose/pii-mask-yoshi.md` 不変条件 1 |
| FP（誤検出）による有用情報の過剰マスク | 多段 validator + ANTI_CONTEXT 抑制 | `patterns.mjs` |
| example.com アドレスによる ANTI_CONTEXT 誤発動 | emailDomainSafeRange チェック（FN-34対応） | `masker.mjs:197-204` |
| WASM 障害 | JS フォールバック | `masker.mjs:getWasmFindMatches` |
| Mask Map への不正アクセス | ファイルパーミッション 0o600 + ホームディレクトリ配置 | `crypto.mjs:generateKey` |
| クレジットカード FP | Luhn アルゴリズム検証 | `patterns.mjs:luhnCheck` |
| マイナンバー FP | チェックデジット検証 | `patterns.mjs:validateMyNumber` |

---

## 9. Residual Risks（残存リスク）

| リスク | 深刻度 | 現状 |
|--------|-------|------|
| **鍵なし時の Mask Maps 平文保存** | 高 | 鍵未生成環境では対応表が平文 JSON になる。`resolveKey()` が null を返しても警告のみ |
| **ANTI_CONTEXT による意図的 FN** | 中 | 攻撃者が「テストデータ:」を先頭に付加するだけで PERSON 系検出を回避可能 |
| **全角・ゼロ幅文字迂回** | 中 | Unicode 正規化の適用がパターンごとに不統一。grep レベルの回避が可能 |
| **XOR 鍵のソース埋め込み** | 中 | パターン定義の秘匿性がソースコードアクセスのみに依存 |
| **パターンデコード失敗時の無音通過** | 中 | `compiled.push` の try/catch が検出0件を無警告で通過させる |
| **プライベートワード（ngwords.private.json）の保護なし** | 中 | `ngwords.private.json` は平文 JSON。顧客名等がファイルシステム上に露出 |
| **ランタイムメモリ上の生 PII** | 低 | マスク処理中に `original` が `replacements` 配列に保持される。Node.js プロセスのメモリダンプで取得可能 |
| **js-person-name-list の FN（confidence=0.5）** | 低 | 人名リストパターンは自信度 0.5 のため、`min_confidence` が 0.5 超だとスキップされる |
