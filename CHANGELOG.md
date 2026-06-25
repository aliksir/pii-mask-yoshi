# Changelog

All notable changes to pii-mask-yoshi are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versioning follows [Semantic Versioning](https://semver.org/).

## [0.6.0] - 2026-06-20

### Added
- **Rust/WASM pattern matching engine** — all 66 detection patterns now run inside a compiled WASM module
- **PERSON overlap scan** in WASM — `find_from_pos` loop catches validator-rejected overlapping matches natively in Rust
- **XOR obfuscation** for all regex patterns and surname/honorific lists in JS source (`encoded-data.mjs`)
- `min_confidence` threshold parameter for `maskText()`
- Confidence scoring for all validator-based patterns

### Changed
- JS regex scan now only runs as WASM failure fallback (previously ran for all PERSON patterns)
- Removed `WASM_NOT_SUPPORTED_IDS` dead code (all 66 patterns are WASM-supported)

### Security
- Pattern definitions no longer stored as plaintext in source code
- `encode-js-patterns.mjs` supports XOR key rotation via decode→re-encode

## [0.5.0] - 2026-06-14

### Added
- Initial Rust/WASM engine (`pii-engine`) with fancy-regex for lookbehind support
- `codegen-patterns.mjs` for auto-generating XOR-encoded Rust patterns from JS definitions
- `build-protected.mjs` for AES-256-GCM encrypted dist bundle
- Spaced-honorific person name detection
- Katakana/nakaguro/furigana/fullspace name patterns
- Company name detection (pre/post corporate entity patterns)

### Changed
- Validator return format: object `{label, confidence}` instead of plain string

## [0.4.0] - 2026-06-08

### Added
- `cleanup` tool — delete expired token maps, block reports, and SIEM files
- CLI mode (`pii-mask-yoshi --cleanup --days 30`)
- Startup permission and retention checks
- SIEM export formats: JSONL (Splunk/Datadog), CEF (ArcSight/QRadar), ECS (Elasticsearch)
- `block_report` JSON format option
- neko-hq stats schema v1.1 integration (severity, session_id, summary)
- At-rest encryption for mask maps (AES-256-GCM)
- Policy integration via neko-hq

### Security
- XOR-masked key derivation in dist loader (replaces raw key embedding)

## [0.3.0] - 2026-06-06

### Added
- `block_report` tool for PII detection summary
- EN/JA README split
- neko-HQ ecosystem integration
- markitdown binary file conversion support
- Multi-platform support (Claude Code, Codex CLI, Gemini CLI)
- Nospace person name detection
- Opt-in business category masking (`PII_MASK_BUSINESS=1`)

## [0.2.0] - 2026-05-28

### Added
- `unmask_file` tool for local token restoration
- `mask_stats` session statistics tool
- neko-not-yoshi integration (external pattern + private word lists)
- IPv4 private/global classification
- IPv6 detection

## [0.1.0] - 2026-05-20

### Added
- Initial release
- `safe_read` MCP tool
- Built-in patterns: email, phone-jp, IPv4, local-path
- Token mapping with session persistence
