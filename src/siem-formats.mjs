import { hostname } from 'node:os';

const SEVERITY_MAP = {
  API_KEY: 'critical', AWS_SECRET: 'critical', AZURE_KEY: 'critical', PASSWORD: 'critical', JWT: 'critical',
  EMAIL: 'high', PERSON: 'high', MYNUM: 'high', PASSPORT: 'high', CREDITCARD: 'high', BANK: 'high',
  PHONE: 'medium', ADDRESS: 'medium', CORPORATE: 'medium',
  'PRIV-IPv4': 'low', 'GLOB-IPv4': 'low', IPv6: 'low', PATH: 'low',
};
const CEF_SEVERITY = { critical: 9, high: 7, medium: 5, low: 3 };
const PII_VERSION = '0.3.0';
const META_ALLOWLIST = new Set(['org', 'environment']);

export function getSeverity(category) {
  return SEVERITY_MAP[category] || 'medium';
}

function sanitizeMeta(meta) {
  if (!meta || typeof meta !== 'object') return {};
  const clean = {};
  for (const key of META_ALLOWLIST) {
    if (meta[key] != null) clean[key] = String(meta[key]).replace(/[\r\n]/g, '');
  }
  return clean;
}

function escapeCef(val) {
  return String(val || '').replace(/\\/g, '\\\\').replace(/=/g, '\\=').replace(/\r/g, '\\r').replace(/\n/g, '\\n');
}

export function formatSiemJsonl(findings, sessionId, meta) {
  const host = hostname();
  const safeMeta = sanitizeMeta(meta);
  return findings.map(f => JSON.stringify({
    timestamp: new Date().toISOString(),
    event_type: 'pii_detection',
    session_id: sessionId,
    host,
    file: f.file,
    line: f.line,
    category: f.category,
    token: f.token,
    severity: getSeverity(f.category),
    ...safeMeta,
  })).join('\n') + '\n';
}

export function formatSiemCef(findings, sessionId, meta) {
  const host = hostname();
  const safeMeta = sanitizeMeta(meta);
  const orgPart = safeMeta.org ? ` org=${escapeCef(safeMeta.org)}` : '';
  const envPart = safeMeta.environment ? ` env=${escapeCef(safeMeta.environment)}` : '';
  return findings.map(f => {
    const sev = CEF_SEVERITY[getSeverity(f.category)] || 5;
    return `CEF:0|aliksir|pii-mask-yoshi|${PII_VERSION}|pii_detection|PII Detected|${sev}|` +
      `src=${escapeCef(f.file)} spt=${f.line} cs1=${escapeCef(f.category)} cs1Label=Category cs2=${escapeCef(f.token)} cs2Label=Token ` +
      `dvchost=${escapeCef(host)} externalId=${escapeCef(sessionId)}${orgPart}${envPart}`;
  }).join('\n') + '\n';
}

export function formatSiemEcs(findings, sessionId, meta) {
  const host = hostname();
  const safeMeta = sanitizeMeta(meta);
  return findings.map(f => JSON.stringify({
    '@timestamp': new Date().toISOString(),
    event: {
      kind: 'alert',
      category: ['intrusion_detection'],
      type: ['info'],
      module: 'pii-mask-yoshi',
      dataset: 'pii.detection',
      severity: CEF_SEVERITY[getSeverity(f.category)] || 5,
    },
    file: { path: f.file },
    source: { line: f.line },
    rule: { category: f.category },
    message: f.token,
    agent: { name: 'pii-mask-yoshi', version: PII_VERSION },
    host: { name: host },
    labels: {
      session_id: sessionId,
      ...safeMeta,
    },
  })).join('\n') + '\n';
}
