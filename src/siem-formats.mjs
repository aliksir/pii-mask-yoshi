import { hostname } from 'node:os';

const SEVERITY_MAP = {
  API_KEY: 'critical', AWS_SECRET: 'critical', AZURE_KEY: 'critical', PASSWORD: 'critical', JWT: 'critical',
  EMAIL: 'high', PERSON: 'high', MYNUM: 'high', PASSPORT: 'high', CREDITCARD: 'high', BANK: 'high',
  PHONE: 'medium', ADDRESS: 'medium', CORPORATE: 'medium',
  'PRIV-IPv4': 'low', 'GLOB-IPv4': 'low', IPv6: 'low', PATH: 'low',
};
const CEF_SEVERITY = { critical: 9, high: 7, medium: 5, low: 3 };
const PII_VERSION = '0.3.0';

export function getSeverity(category) {
  return SEVERITY_MAP[category] || 'medium';
}

export function formatSiemJsonl(findings, sessionId, meta) {
  const host = hostname();
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
    ...meta,
  })).join('\n') + '\n';
}

export function formatSiemCef(findings, sessionId, meta) {
  const host = hostname();
  const orgPart = meta.org ? ` org=${meta.org}` : '';
  const envPart = meta.environment ? ` env=${meta.environment}` : '';
  return findings.map(f => {
    const sev = CEF_SEVERITY[getSeverity(f.category)] || 5;
    const escaped = (f.file || '').replace(/\\/g, '\\\\').replace(/=/g, '\\=');
    return `CEF:0|aliksir|pii-mask-yoshi|${PII_VERSION}|pii_detection|PII Detected|${sev}|` +
      `src=${escaped} spt=${f.line} cs1=${f.category} cs1Label=Category cs2=${f.token} cs2Label=Token ` +
      `dvchost=${host} externalId=${sessionId}${orgPart}${envPart}`;
  }).join('\n') + '\n';
}

export function formatSiemEcs(findings, sessionId, meta) {
  const host = hostname();
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
      ...(meta.org ? { org: meta.org } : {}),
      ...(meta.environment ? { environment: meta.environment } : {}),
    },
  })).join('\n') + '\n';
}
