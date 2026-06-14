import { loadPatterns } from './patterns.mjs';
import { MaskStore } from './store.mjs';

let patterns = null;
const store = new MaskStore();

function ensurePatterns() {
  if (!patterns) patterns = loadPatterns();
  return patterns;
}

function getLineNumber(text, charIndex) {
  let line = 1;
  for (let i = 0; i < charIndex && i < text.length; i++) {
    if (text[i] === '\n') line++;
  }
  return line;
}

export function maskText(text, filePath = null) {
  const pats = ensurePatterns();
  let result = text;
  const replacements = [];

  for (const p of pats) {
    p.regex.lastIndex = 0;
    let m;
    while ((m = p.regex.exec(result)) !== null) {
      const matched = m[0];

      let prefix = p.maskPrefix;
      if (p.validator) {
        const validResult = p.validator(matched, { text: result, start: m.index, end: m.index + matched.length });
        if (validResult === null) {
          if (m.index === p.regex.lastIndex) p.regex.lastIndex++;
          continue;
        }
        prefix = validResult;
      }

      replacements.push({
        start: m.index,
        end: m.index + matched.length,
        original: matched,
        prefix,
        category: p.category,
        patternId: p.id,
      });

      if (m.index === p.regex.lastIndex) p.regex.lastIndex++;
    }
  }

  replacements.sort((a, b) => b.start - a.start);

  const seen = new Set();
  const deduped = [];
  for (const r of replacements) {
    const key = `${r.start}:${r.end}`;
    if (seen.has(key)) continue;
    let overlap = false;
    for (const d of deduped) {
      if (r.start < d.end && r.end > d.start) { overlap = true; break; }
    }
    if (overlap) continue;
    seen.add(key);
    deduped.push(r);
  }

  deduped.sort((a, b) => b.start - a.start);

  // Anti-context: サンプルデータ等の文脈にあるPIIを除外
  const ANTI_CONTEXT = /(?:例[)）]|サンプルデータ|テストデータ|テスト用|ダミー|\bdummy\b|\bexample\b|\bsample\s+data\b)/i;
  const ANTI_CONTEXT_IDS = new Set([
    'jp-person-name', 'jp-person-name-nospace', 'jp-person-name-list',
    'jp-person-name-honorific', 'jp-label-name'
  ]);

  const filtered = deduped.filter(r => {
    if (!ANTI_CONTEXT_IDS.has(r.patternId)) return true;
    const ws = Math.max(0, r.start - 15);
    const we = Math.min(result.length, r.end + 15);
    return !ANTI_CONTEXT.test(result.slice(ws, we));
  });

  let masked = result;
  for (const r of filtered) {
    const token = store.getOrCreate(r.original, r.prefix);
    masked = masked.slice(0, r.start) + token + masked.slice(r.end);
    if (filePath) {
      store.addFinding(filePath, getLineNumber(text, r.start), r.category, token);
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
