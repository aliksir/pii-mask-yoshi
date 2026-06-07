> English version: [README.md](README.md)
> [neko-HQ](https://github.com/aliksir/neko-hq) エコシステムの一部です。

# pii-mask-yoshi（日本語ドキュメント）

Claude Code 用の MCP サーバー。ファイル内の PII（個人情報・機密情報）を自動マスクし、Anthropic の API サーバーに生データを送信せずに AI 処理を行う。マスクされた内容のみが送信され、元の値はローカルの対応表ファイルで復元できる。

## なぜ必要か

Claude Code は読み取ったファイル内容を Anthropic の API に送信する。顧客情報・社内機密を含むファイルをそのまま読ませると、API 経由で外部に流出するリスクがある。pii-mask-yoshi は通常の `Read` の代わりに `safe_read` を提供し、送信前に PII をトークンに置換することでこの問題を解決する。

## ツール一覧

| ツール | 説明 |
|--------|------|
| `safe_read` | ファイルを読み取り、PII を自動マスクして返す。バイナリ（xlsx, docx, pptx, pdf 等）は markitdown 経由で自動変換。 |
| `unmask_file` | マスクトークンを含むファイルを元の値に復元し、ローカルファイルに保存する。復元データは Claude に返さない。 |
| `mask_stats` | 現在セッションのマスキング統計を表示する。 |

## 検出パターン（内蔵）

外部依存なしで動作するパターン：

- メールアドレス
- 日本の電話番号（固定・携帯・フリーダイヤル）
- IPv4 アドレス（プライベート/グローバル分類）
- IPv6 アドレス
- ローカルファイルパス（`C:\Users\...`）
- API キー（OpenAI, GitHub, AWS, Anthropic）
- AWS シークレットキー、Azure アカウントキー
- パスワード（key=value 形式、日本語キーワード、スラッシュ区切り）
- クレジットカード番号（Luhn チェック付き）
- 日本の住所（都道府県 + 市区町村）
- マイナンバー
- 銀行口座番号
- パスポート番号（日本形式）
- 法人番号
- 日本人名（姓 + スペース + 名）
- 読点区切りの人名リスト

## 動作の流れ

```
ファイル → safe_read → [バイナリ?] → markitdown 変換 → パターンマッチ → マスク済みテキスト → API
                            │                                  ↑
                            └→ [テキスト] → ファイル読込 ──────┘
                                                               │
                                                     対応表を保存
                                                     ~/.pii-mask-yoshi/maps/
```

1. `safe_read` がローカルでファイルを読み取る
2. バイナリファイルは `python -m markitdown` で Markdown に変換
3. 全パターン（内蔵 + neko-not-yoshi）を適用
4. マッチした値をトークン（`[EMAIL-001]`, `[PRIV-IPv4-003]`, `[PERSON-002]` 等）に置換
5. マスク済みテキストのみが Claude に返される（= Anthropic API に送信される）
6. トークンと元の値の対応表はローカル（`~/.pii-mask-yoshi/maps/`）に保存
7. `unmask_file` でトークンを元の値に復元（結果はローカルファイルにのみ出力）

### block_report — PII検出レポート

現セッションで検出された全PIIのサマリを返す（カテゴリ・ファイル名・行番号）。**実PII値はAPI応答に含まれない**。実値はローカルレポートファイルにのみ書き出される。

API応答に含まれる情報:
- カテゴリ、ファイル名、行番号、マスクトークン（例: \[EMAIL-001\]）
- ローカル詳細レポートのパス

ローカルレポート（実値を含む）:
- `~/.pii-mask-yoshi/block-report-{session}.txt`

### レポート管理

- **保存場所**: `~/.pii-mask-yoshi/block-report-{session}.txt`
- **セッションID形式**: `session-{タイムスタンプ}` — MCPサーバーインスタンスごと（= Claude Codeセッションごと）に生成される一意のID。タイムスタンプはサーバー起動時の `Date.now()`。
- **保持期間**: レポートは自動削除されません。定期的に古いレポートを削除してください:
  ```bash
  # 30日以上前のレポートを削除（Linux/macOS）
  find ~/.pii-mask-yoshi -name 'block-report-*' -mtime +30 -delete
  ```
  ```powershell
  # 30日以上前のレポートを削除（Windows PowerShell）
  Get-ChildItem "$env:USERPROFILE\.pii-mask-yoshi" -Filter "block-report-*" |
    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) } | Remove-Item
  ```
- **セキュリティ注意**: 詳細レポートには実際のPII値が含まれます。`~/.pii-mask-yoshi/` に適切な権限を設定してください（例: Linux/macOS では `chmod 700`、Windows では ACL で制限）。
- **トークン対応表**: `~/.pii-mask-yoshi/maps/session-*.json` — 同じ保持ポリシーが適用されます。`unmask_file` の動作に必要です。

### SIEM 連携

`block_report` は複数の出力形式に対応しており、SIEM やログ管理システムに直接取り込めます:

| 形式 | 用途 | 出力先 |
|------|------|--------|
| `text` | 人間可読（デフォルト） | MCP応答 |
| `json` | 集約JSON | MCP応答 |
| `jsonl` | 1検出1行（Splunk, Datadog, 汎用） | ファイル |
| `cef` | Common Event Format（ArcSight, QRadar） | ファイル |
| `ecs` | Elastic Common Schema（Elasticsearch, Kibana） | ファイル |

SIEM形式（`jsonl`, `cef`, `ecs`）は `~/.pii-mask-yoshi/siem/{session}.{format}` に出力されます。`output_path` で変更可能。

カスタムメタデータを `meta` パラメータで各イベントに付与できます:
```json
{"format": "jsonl", "meta": {"org": "acme-corp", "environment": "prod"}}
```

重要度はPIIカテゴリ別に自動付与: `critical`（APIキー、パスワード）、`high`（メール、人名、クレジットカード）、`medium`（電話番号、住所）、`low`（IP、ファイルパス）。

**SIEM出力にPII実値は一切含まれません** — カテゴリ、トークン、ファイルパス、行番号のみ。

#### 出力例

**JSONL**（1検出1行）:
```json
{"timestamp":"2026-06-07T10:00:00.000Z","event_type":"pii_detection","session_id":"session-1749290400000","host":"workstation-1","file":"/projects/report.txt","line":3,"category":"EMAIL","token":"[EMAIL-001]","severity":"high","org":"acme-corp"}
```

**CEF**:
```
CEF:0|aliksir|pii-mask-yoshi|0.3.0|pii_detection|PII Detected|7|src=/projects/report.txt spt=3 cs1=EMAIL cs1Label=Category cs2=[EMAIL-001] cs2Label=Token dvchost=workstation-1 externalId=session-1749290400000 org=acme-corp
```

**ECS**（Elastic Common Schema）:
```json
{"@timestamp":"2026-06-07T10:00:00.000Z","event":{"kind":"alert","category":["intrusion_detection"],"type":["info"],"module":"pii-mask-yoshi","dataset":"pii.detection","severity":7},"file":{"path":"/projects/report.txt"},"source":{"line":3},"rule":{"category":"EMAIL"},"message":"[EMAIL-001]","agent":{"name":"pii-mask-yoshi","version":"0.3.0"},"host":{"name":"workstation-1"},"labels":{"session_id":"session-1749290400000","org":"acme-corp"}}
```

### neko-hq 連携

pii-mask-yoshi を MCP サーバーとして使用する場合、セッション終了時に検出サマリ（検出件数、マスク件数）が `~/.neko-hq/stats.jsonl` に自動記録されます。これにより `neko-hq stats` で PII 検出メトリクスを他のツール統計と合わせて確認できます。

## セットアップ

```bash
# インストール（Node.js 22 以上が必要）
npm install -g pii-mask-yoshi

# Claude Code の MCP 設定に追加（.mcp.json）
{
  "mcpServers": {
    "pii-mask-yoshi": {
      "command": "pii-mask-yoshi"
    }
  }
}

# オプション: バイナリファイル対応
pip install markitdown[all]
```

## オプション依存

pii-mask-yoshi は単体で動作する。以下のオプション依存で機能を拡張できる。

### neko-not-yoshi（推奨）

追加パターン定義と顧客固有のワードリストを提供する。

- **追加される機能**: `ngwords.public.json` のパターン（内蔵を上書き）+ `ngwords.private.json` の顧客固有名称
- **なくても動く**: 内蔵パターンは動作する。顧客固有のマスキングは使えない
- **設定**: 環境変数 `NEKO_NOT_YOSHI_DIR` を設定、または `C:/work/neko-not-yoshi/` に配置
- **リポジトリ**: [aliksir/neko-not-yoshi](https://github.com/aliksir/neko-not-yoshi)

### markitdown（Python）

`safe_read` でバイナリファイルを処理するために必要。

- **追加される機能**: xlsx, docx, pptx, pdf, odt, ods, odp, rtf をテキストに変換してからマスキング
- **なくても動く**: バイナリファイルはエラーになる。テキストファイルは正常動作
- **インストール**: `pip install markitdown[all]`

### markitdown-yoshi（MCP サーバー）

ドキュメント変換の単体 MCP サーバー。pii-mask-yoshi は内蔵バイナリ変換に `python -m markitdown` を直接呼ぶが、markitdown-yoshi は独立した MCP ツールとして追加機能を提供する:

- **追加される機能**: `convert`（オンデマンドファイル変換）、`classify_pdf`（PDF 構造分析）、`supported_formats`（対応形式一覧）
- **併用**: pii-mask-yoshi は読み取り時の PII マスク、markitdown-yoshi は単体変換。両方を MCP サーバーとして同時に動かせる
- **セキュリティ**: markitdown-yoshi はディレクトリスコープのアクセス制御を強制（ファイルシステムルートへのアクセス禁止）
- **インストール**: `npm install -g markitdown-yoshi`
- **リポジトリ**: [aliksir/markitdown-yoshi](https://github.com/aliksir/markitdown-yoshi)

## 免責事項

本ツールは PII 漏洩リスクを低減しますが、完全な検出を保証するものではありません。パターンベースのマスキングには以下の制約があります。

- 未知・特殊な形式の PII は検出できない場合がある
- 文脈依存の情報（一般語と同一の人名等）は見落とし・過検出の可能性がある
- バイナリファイルの変換精度は markitdown に依存する
- カスタムワードリスト（neko-not-yoshi）は手動メンテナンスが必要

**本ツールを唯一の PII 保護手段として使用しないでください。** 機密文書を扱う際はマスク結果を必ず確認し、多層防御の一環として利用してください。

検出漏れにより発生した損害について、作者は一切の責任を負いません。

## ライセンス

Apache-2.0
