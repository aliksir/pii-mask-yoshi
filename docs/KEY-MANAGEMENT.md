# Key Management Roadmap — pii-mask-yoshi

更新日: 2026-09-26

---

## Phase 1: Obfuscation（現状）

現在の鍵管理方式。暗号化と難読化を組み合わせた2層構成。

### パターン定義の保護

- **方式**: WASM バイナリ内に AES-256-GCM で暗号化して格納（PBKDF2-HMAC-SHA256 で鍵導出）
- **配布物**: npm パッケージ・公開リポには WASM バイナリだけを含め、パターンのソースは含めない
- **目的**: パターン定義の気軽な複製・流出を防止する
- **限界**: 鍵導出用の seed/salt もバイナリ内にあるため、バイナリ解析で復元は可能（THREAT-MODEL.md §7参照）

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

---

## Phase 2: Pattern Key Externalization（将来）

パターン定義の AES-256-GCM 暗号化は WASM バイナリ内で実施済み（Phase 1 参照）。Phase 2 では鍵導出材料の置き場所を見直す。

### 目標

- 鍵導出材料（seed/salt）がバイナリ内にあるため、鍵をバイナリ外（`PII_MASK_PATTERN_KEY` 環境変数等）から与える方式へ移す

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

### パターン定義

パターンソースの保守手順（パターンの更新・WASM への再暗号化）は非公開。

### Mask Maps の鍵ローテーション

鍵を変更した場合、既存の Mask Maps は旧鍵で復号してから新鍵で再暗号化が必要。

```bash
# 旧鍵で Mask Maps を復号（--old-key オプションは未実装、手動対応が必要）
# ~/.pii-mask-yoshi/maps/ 内の .json ファイルを対象に実施
# 現状: cleanup ツールで期限切れ Mask Maps を削除し、新鍵で再生成する方法が現実的
```

> **注意**: Phase 1 では鍵ローテーションの自動化ツールは未実装。Phase 3 での KMS 統合時に自動化を予定する。
