# Key Management Roadmap — pii-mask-yoshi

更新日: 2026-06-20

---

## Phase 1: Obfuscation（現状）

現在の鍵管理方式。暗号化と難読化を組み合わせた2層構成。

### パターン定義の保護

- **方式**: XOR + base64 難読化
- **実装**: `src/encoded-data.mjs`（`encode-js-patterns.mjs` で自動生成）
- **XOR鍵**: `XOR_KEY` 定数としてソースに埋め込み
- **目的**: grep・静的解析での平文パターン直接参照を防止する
- **限界**: 暗号学的保護ではない。ソースアクセスで即座に復元可能（THREAT-MODEL.md §7参照）

### Mask Maps の保護

- **方式**: AES-256-GCM 暗号化（鍵が存在する場合のみ）
- **実装**: `src/crypto.mjs`（`encrypt` / `decrypt`）
- **アルゴリズム**: AES-256-GCM、IV: 12バイトランダム、Auth Tag: 16バイト
- **鍵サイズ**: 32バイト（256ビット）
- **保存形式**: `{ v: 1, alg: "aes-256-gcm", iv: "...", tag: "...", ct: "..." }`

### 鍵の保存・取得

```
優先順位:
  1. 環境変数 PII_MASK_ENCRYPT_KEY（base64エンコード、32バイト）
  2. ~/.pii-mask-yoshi/.key（ファイル、パーミッション 0o600）
  3. null → 鍵なし（Mask Mapsは平文保存）
```

実装: `src/crypto.mjs: resolveKey()`

鍵の生成:
```bash
node -e "const c=require('node:crypto');const k=c.randomBytes(32);console.log(k.toString('base64'))"
# 出力を PII_MASK_ENCRYPT_KEY に設定、または generateKey() を呼び出す
```

### dist bundle の保護

- `build-protected.mjs` がビルド時に実施
- パターン定義: AES-256-GCM 暗号化 + XOR鍵導出（PBKDF2相当）
- 配布バイナリには鍵を含まず、起動時に環境変数から取得する設計

---

## Phase 2: Pattern Encryption（将来）

パターン定義自体を AES-GCM で暗号化し、XOR 難読化の限界を解消する。

### 目標

- `encoded-data.mjs` の XOR 難読化を廃止し、AES-256-GCM に移行
- パターン定義をビルド時に暗号化 → ランタイムに復号
- XOR 鍵のソース埋め込みを排除

### 実装イメージ

```
ビルド時:
  1. encode-js-patterns.mjs がパターンを JSON 化
  2. AES-256-GCM で暗号化（ビルド専用鍵で）
  3. 暗号化済みバイナリを encoded-data.mjs に出力

ランタイム時:
  1. PII_MASK_PATTERN_KEY 環境変数から鍵を取得
  2. AES-256-GCM で復号
  3. 正規表現としてコンパイル
```

### 鍵管理

- パターン暗号化鍵（`PII_MASK_PATTERN_KEY`）と Mask Maps 暗号化鍵（`PII_MASK_ENCRYPT_KEY`）を分離
- どちらも環境変数ベースで提供

### 移行時の影響

- 鍵なし起動時の挙動要検討（fail-closed にするか fail-open を維持するか）
- パターンデコード失敗時の警告強化（現在は無音通過、THREAT-MODEL.md §9参照）

---

## Phase 3: Enterprise（将来）

組織レベルの鍵管理基盤との統合。

### 対応予定の Key Management Service

| KMS | 用途 |
|-----|------|
| HashiCorp Vault | オンプレ・プライベートクラウド環境 |
| AWS KMS | AWS 環境での Mask Maps・パターン鍵管理 |
| Azure Key Vault | Azure 環境 |

### 実装方針

- `resolveKey()` を抽象化し、KMS バックエンドをプラグイン化
- `PII_MASK_KMS_BACKEND=vault|aws-kms|azure-kv` で切り替え

### 自動ローテーション

- 推奨ローテーション間隔: **90日**
- ローテーション手順:
  1. 新鍵で新規 Mask Maps を暗号化
  2. 旧鍵で既存 Mask Maps を復号 → 新鍵で再暗号化
  3. 旧鍵を無効化

### 鍵使用監査ログ

- `block_report` の CEF/ECS フォーマット出力を KMS 監査ログと連携
- どのセッションがいつ鍵を使用して何件マスクしたかを記録

### neko-hq 統合

- neko-hq の `enterprise` プリセットから KMS 設定を自動取得
- 設定例: `PII_MASK_KMS_BACKEND=vault PII_MASK_VAULT_ADDR=https://vault.example.com`

---

## Key Rotation 手順（現在の手動手順）

XOR 難読化パターンの再生成（Phase 1 の現状手順）。

### 前提条件

- `neko-not-yoshi` のパターン定義が更新済みであること
- `scripts/encode-js-patterns.mjs` が存在すること

### 手順

```bash
# 1. 既存の encoded-data.mjs を退避
cp src/encoded-data.mjs src/encoded-data.mjs.bak

# 2. neko-not-yoshi からパターンをデコード → 確認
node scripts/encode-js-patterns.mjs --dry-run

# 3. 再エンコード（encoded-data.mjs を上書き再生成）
node scripts/encode-js-patterns.mjs

# 4. 動作確認
node -e "import('./src/patterns.mjs').then(m => console.log('OK:', m.loadPatterns().length, 'patterns'))"

# 5. テスト実行
npm test

# 6. 確認後に退避ファイルを削除
rm src/encoded-data.mjs.bak
```

### Mask Maps の鍵ローテーション

鍵を変更した場合、既存の Mask Maps は旧鍵で復号してから新鍵で再暗号化が必要。

```bash
# 旧鍵で Mask Maps を復号（--old-key オプションは未実装、手動対応が必要）
# ~/.pii-mask-yoshi/maps/ 内の .json ファイルを対象に実施
# 現状: cleanup ツールで期限切れ Mask Maps を削除し、新鍵で再生成する方法が現実的
```

> **注意**: Phase 1 では鍵ローテーションの自動化ツールは未実装。Phase 3 での KMS 統合時に自動化を予定する。
