# pii-mask-yoshi

Claude Code (MCP) server that automatically masks PII (personally identifiable information) in files before they reach Anthropic's API servers. Masked content is sent for AI processing; original values are restored locally via a mapping file.

**[日本語ドキュメントはこちら](#日本語)**

## Tools

| Tool | Description |
|------|-------------|
| `safe_read` | Read a file with automatic PII masking. Binary files (xlsx, docx, pptx, pdf, etc.) are auto-converted via markitdown. |
| `unmask_file` | Restore masked tokens in a file to original values. Output is written to a local file only (never returned to Claude). |
| `mask_stats` | Show masking statistics for the current session. |

## Built-in Detection Patterns

These patterns work without any external dependencies:

- Email addresses
- Japanese phone numbers
- IPv4 addresses (private/global classification)
- IPv6 addresses
- Local file paths (`C:\Users\...`)
- API keys (OpenAI, GitHub, AWS, Anthropic)
- AWS Secret Keys, Azure Account Keys
- Passwords (key-value patterns, Japanese keywords, slash-separated)
- Credit card numbers (with Luhn validation)
- Japanese addresses (prefecture + city)
- Japanese My Number
- Bank account numbers
- Passport numbers (JP format)
- Corporate numbers
- Japanese person names (surname + space + given name)
- Comma-separated Japanese name lists

## Optional Dependencies

pii-mask-yoshi works standalone with built-in patterns. Optional dependencies extend its capabilities:

### neko-not-yoshi (recommended)

Provides additional pattern definitions and customer-specific word lists.

- **What it adds**: Patterns from `ngwords.public.json` (override built-in) + customer-specific names/terms from `ngwords.private.json`
- **Without it**: Built-in patterns still work. Customer-specific masking is unavailable.
- **Config**: Set `NEKO_NOT_YOSHI_DIR` env var, or place at `C:/work/neko-not-yoshi/`
- **Repo**: [aliksir/neko-not-yoshi](https://github.com/aliksir/neko-not-yoshi)

### markitdown (Python)

Required for binary file support in `safe_read`.

- **What it adds**: xlsx, docx, pptx, pdf, odt, ods, odp, rtf conversion to text before masking
- **Without it**: Binary files return an error message. Text files work normally.
- **Install**: `pip install markitdown[all]`

### markitdown-yoshi (MCP server, separate)

An MCP server wrapper around markitdown. Not a direct dependency of pii-mask-yoshi (pii-mask-yoshi calls `python -m markitdown` directly), but part of the same ecosystem.

- **Repo**: [aliksir/markitdown-yoshi](https://github.com/aliksir/markitdown-yoshi)

## How It Works

```
File ──→ safe_read ──→ [Binary?] ──→ markitdown convert ──→ Pattern matching ──→ Masked text ──→ API
                            │                                       ↑
                            └──→ [Text] ──→ Read file ─────────────┘
                                                                    │
                                                          Token mapping saved
                                                          to ~/.pii-mask-yoshi/maps/
```

1. `safe_read` reads the file locally
2. Binary files are converted to Markdown via `python -m markitdown`
3. All patterns (built-in + neko-not-yoshi if available) are applied
4. Matched values are replaced with tokens like `[EMAIL-001]`, `[PRIV-IPv4-003]`, `[PERSON-002]`
5. Only masked text is returned to Claude (and sent to Anthropic's API)
6. Token-to-original mapping is saved locally at `~/.pii-mask-yoshi/maps/`
7. `unmask_file` restores tokens to original values in a local file

## Setup

```bash
# Install (Node.js 22+ required)
npm install -g pii-mask-yoshi

# Add to Claude Code MCP config (.mcp.json)
{
  "mcpServers": {
    "pii-mask-yoshi": {
      "command": "pii-mask-yoshi"
    }
  }
}

# Optional: binary file support
pip install markitdown[all]
```

## Disclaimer

This tool reduces the risk of PII exposure but does not guarantee complete detection. Pattern-based masking has inherent limitations:

- Novel or unusual PII formats may not be detected
- Context-dependent information (e.g., names that are also common words) may be missed or over-matched
- Binary file conversion depends on markitdown's extraction accuracy
- Custom word lists (neko-not-yoshi) require manual maintenance

**Do not rely on this tool as your sole PII protection measure.** Always review masked output before sharing sensitive documents and use it as one layer in a defense-in-depth strategy.

The authors assume no liability for any PII that passes through undetected.

## License

Apache-2.0

---

<a id="日本語"></a>

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
