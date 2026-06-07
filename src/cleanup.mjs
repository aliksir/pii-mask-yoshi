import { readdirSync, statSync, unlinkSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { homedir, platform } from 'node:os';

const BASE_DIR = join(homedir(), '.pii-mask-yoshi');
const MAPS_DIR = join(BASE_DIR, 'maps');
const SIEM_DIR = join(BASE_DIR, 'siem');
const DEFAULT_RETENTION_DAYS = 30;

export function checkPermissions() {
  const warnings = [];
  try {
    const stat = statSync(BASE_DIR);
    if (platform() !== 'win32' && (stat.mode & 0o077)) {
      warnings.push(`[pii-mask-yoshi] 警告: ${BASE_DIR} が他ユーザーからアクセス可能です (mode: ${(stat.mode & 0o777).toString(8)})。chmod 700 を推奨します。`);
    }
  } catch {
    // directory doesn't exist yet — no warning needed
  }
  return warnings;
}

export function checkRetention(days = DEFAULT_RETENTION_DAYS) {
  const cutoff = Date.now() - days * 86400_000;
  const expired = [];

  for (const dir of [MAPS_DIR, BASE_DIR]) {
    try {
      for (const f of readdirSync(dir)) {
        if (dir === BASE_DIR && !f.startsWith('block-report-')) continue;
        if (dir === MAPS_DIR && !f.endsWith('.json')) continue;
        const full = join(dir, f);
        try {
          const st = statSync(full);
          if (st.mtimeMs < cutoff) expired.push({ path: full, mtime: new Date(st.mtimeMs) });
        } catch { /* skip unreadable */ }
      }
    } catch { /* dir missing */ }
  }

  return expired;
}

function extractSessionId(filename) {
  const m = filename.match(/(?:block-report-|^)(session-\d+)\./);
  return m ? m[1] : null;
}

export function pairedDelete(sessionId) {
  const deleted = [];
  const targets = [
    join(MAPS_DIR, `${sessionId}.json`),
    join(BASE_DIR, `block-report-${sessionId}.txt`),
  ];

  try {
    for (const f of readdirSync(SIEM_DIR)) {
      if (f.startsWith(sessionId + '.')) targets.push(join(SIEM_DIR, f));
    }
  } catch { /* siem dir may not exist */ }

  for (const t of targets) {
    try {
      unlinkSync(t);
      deleted.push(t);
    } catch (e) {
      if (e.code !== 'ENOENT') throw e;
    }
  }
  return deleted;
}

export function cleanup(days = DEFAULT_RETENTION_DAYS) {
  const cutoff = Date.now() - days * 86400_000;
  const sessionIds = new Set();

  for (const [dir, prefix, ext] of [[MAPS_DIR, '', '.json'], [BASE_DIR, 'block-report-', '.txt']]) {
    try {
      for (const f of readdirSync(dir)) {
        if (!f.startsWith(prefix) || (ext && !f.endsWith(ext))) continue;
        if (dir === BASE_DIR && !f.startsWith('block-report-')) continue;
        const full = join(dir, f);
        try {
          if (statSync(full).mtimeMs < cutoff) {
            const sid = extractSessionId(f);
            if (sid) sessionIds.add(sid);
          }
        } catch { /* skip */ }
      }
    } catch { /* dir missing */ }
  }

  let totalDeleted = 0;
  const details = [];
  for (const sid of sessionIds) {
    const deleted = pairedDelete(sid);
    totalDeleted += deleted.length;
    if (deleted.length > 0) details.push({ sessionId: sid, files: deleted });
  }

  return { sessionIds: sessionIds.size, filesDeleted: totalDeleted, details };
}
