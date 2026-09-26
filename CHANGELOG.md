# Changelog

All notable changes to pii-mask-yoshi are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versioning follows [Semantic Versioning](https://semver.org/).

## [0.6.2] - Unreleased

### Fixed
- **WASM engine hang on large inputs** — `maskText()` never returned for inputs of roughly 50KB or more. When a pattern exceeded fancy-regex's backtrack limit, the WASM engine discarded the error, and the iterator returned the same error at the same position forever. The engine now stops at the first regex error and reports it as a WASM failure (`{"error": ...}`), and `masker.mjs` treats it the same way as any other WASM failure. Partial WASM results are never used.
- The PERSON overlap scan no longer silently stops on a regex error (same failure handling as above).
- A JSON serialization failure in the WASM engine is now reported as a failure instead of an empty result.
- **Root cause of the large-input failure** — some patterns were counted against fancy-regex's backtrack limit in proportion to input length (the limit was exceeded without any catastrophic backtracking). Patterns without lookaround now run on regex-automata (linear time, no backtrack limit). Patterns with lookaround find candidate positions with a lookaround-free version of the pattern, then run fancy-regex only in a bounded window around each candidate. The WASM engine alone now completes a 333KB input (about 1 second), with the same detection count as the JS path.
- **Three label patterns were missing from WASM** — `jp-label-name`, `jp-label-address` and `jp-label-phone` use a variable-length lookbehind that fancy-regex cannot compile, so the WASM engine silently dropped them. They are now compiled as "label + captured value" on regex-automata, and only the value is reported, as with the lookbehind.
- WASM regexes now follow JavaScript semantics for `\d`, `\w`, `\b` (ASCII) and `.` (no line terminators). Previously they followed Unicode semantics in Rust.
- `src/patterns.mjs` loads the JS pattern source only if it exists. The npm package does not include it and runs on the WASM engine alone.

### Security
- **Pattern definitions are shipped only inside the WASM binary** (AES-256-GCM). The npm package and the public repository do not contain the pattern source or the generated Rust source that embeds the encrypted patterns. The surname and honorific lists used by validators are also served from the WASM binary. The WASM engine cannot be rebuilt from the public repository. The npm package contains only `src/` and the WASM binary; it has no `dist/` bundle. If the WASM engine fails to load or run, the npm package throws an error even when NG word dictionaries are present.
- **Patterns not compiled into WASM were not detected when WASM succeeded** — the JS scan loop skipped every pattern whenever WASM succeeded, so patterns missing from the WASM binary were never scanned on the normal path. This covered private NG words from `ngwords.private.json` (excluded from WASM by design in `codegen-patterns.mjs`) and `business` patterns enabled with `PII_MASK_BUSINESS=1` (previously not compiled into the WASM binary). Business patterns are now compiled into the WASM binary and switched on at runtime by the same variable. The WASM engine also exports `pattern_ids()`, the list of patterns it actually compiled. Private NG words are always scanned in JS, and in a local development checkout every other pattern not on that list is also scanned in JS. If the list cannot be read, all patterns are scanned in JS.
- **Private NG words could be dropped after detection** — a detected private NG word was removed when it overlapped another match that won de-duplication and was then filtered out by the test/sample-data context check (`ANTI_CONTEXT`) or by `min_confidence`. Filtering now runs before de-duplication, private NG words are exempt from both filters, and a private NG word that overlaps other matches is merged with them into one masked span. A registered word never remains in the output.

### Added
- `test/private-ngwords.test.mjs`: regression tests with a temporary dictionary of fictitious words. A private NG word is masked on both the WASM and JS paths, including when it overlaps a name or company match in a test-data context or under `min_confidence`. A `business` pattern is detected on the WASM path.
- `test/wasm-large-input.test.mjs`: regression test that a 50KB+ synthetic input returns within 10 seconds on the WASM engine without falling back, and yields the same detection count as the JS path.
- `test/npm-equivalence.test.mjs`: regression test that a copy of the package without the JS pattern source produces exactly the same masked output as the local JS path, covering the public fixtures, the fuzz data, label, name and business inputs, private NG words and a 50KB+ input, with business patterns off and on.

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
