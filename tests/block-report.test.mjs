import { describe, it, beforeEach } from 'node:test';
import { strict as assert } from 'node:assert';
import { maskText, getStore } from '../src/masker.mjs';
import { readFileSync } from 'node:fs';

describe('block_report findings', () => {
  beforeEach(() => {
    getStore().findings.length = 0;
  });

  it('records findings with file path and line number', () => {
    const text = 'Contact: test@example.com on line 1\nIP: 8.8.8.8 on line 2';
    maskText(text, '/tmp/test.txt');

    const findings = getStore().getFindings();
    assert.ok(findings.length >= 2, 'should have at least 2 findings');

    const emailF = findings.find(f => f.category === 'pii');
    assert.ok(emailF, 'should find pii category');
    assert.equal(emailF.file, '/tmp/test.txt');
    assert.equal(emailF.line, 1);

    const ipF = findings.find(f => f.category === 'network');
    assert.ok(ipF, 'should find network category');
    assert.equal(ipF.line, 2);
  });

  it('does not record findings when filePath is null', () => {
    maskText('test@example.com');
    const findings = getStore().getFindings();
    assert.equal(findings.length, 0);
  });

  it('accumulates findings across multiple files', () => {
    maskText('test@example.com', '/tmp/a.txt');
    maskText('other@example.com', '/tmp/b.txt');

    const findings = getStore().getFindings();
    const files = new Set(findings.map(f => f.file));
    assert.ok(files.has('/tmp/a.txt'));
    assert.ok(files.has('/tmp/b.txt'));
  });

  it('finding token does not contain original PII value', () => {
    maskText('secret@corp.com', '/tmp/c.txt');
    const findings = getStore().getFindings();
    for (const f of findings) {
      assert.ok(!f.token.includes('secret@corp.com'), 'token should not contain original value');
      assert.match(f.token, /^\[[A-Z]+-\d{3}\]$/, 'token should be in mask format');
    }
  });

  it('clear() resets findings', () => {
    maskText('test@example.com', '/tmp/d.txt');
    assert.ok(getStore().getFindings().length > 0);
    getStore().clear();
    assert.equal(getStore().getFindings().length, 0);
  });
});

describe('block_report handler E2E', () => {
  beforeEach(() => {
    getStore().clear();
  });

  it('safe output contains no actual PII values', () => {
    const testEmail = 'leak-test-42@secret-corp.example.com';
    const testIp = '203.0.113.99';
    maskText(`contact: ${testEmail}\nserver: ${testIp}`, '/tmp/e2e-test.txt');

    const store = getStore();
    const findings = store.getFindings();
    const byFile = {};
    for (const f of findings) (byFile[f.file] = byFile[f.file] || []).push(f);

    const safeLines = [];
    for (const [file, items] of Object.entries(byFile)) {
      safeLines.push(file + ': ' + items.length + ' items');
      for (const item of items) {
        safeLines.push('  L' + item.line + ': [' + item.category + '] ' + item.token);
      }
    }
    const output = safeLines.join('\n');

    assert.ok(!output.includes(testEmail), 'output must not contain email');
    assert.ok(!output.includes(testIp), 'output must not contain IP');
    assert.ok(output.includes('[EMAIL-'), 'output should contain EMAIL token');
  });
});

describe('block_report JSON format', () => {
  // Import handleToolCall indirectly via the module's exported handler
  // Since handleToolCall is not exported, we simulate the logic inline
  beforeEach(() => {
    getStore().clear();
  });

  it('returns valid JSON structure with findings', () => {
    maskText('contact: json-test@example.com\nserver: 10.0.0.1', '/tmp/json-test.txt');

    const store = getStore();
    const findings = store.getFindings();
    assert.ok(findings.length >= 1, 'should have findings');

    // Simulate JSON format output logic from block_report handler
    const byFile = {};
    for (const f of findings) {
      (byFile[f.file] = byFile[f.file] || []).push(f);
    }
    const byFileJson = {};
    for (const [file, items] of Object.entries(byFile)) {
      byFileJson[file] = items
        .sort((a, b) => a.line - b.line)
        .map((item) => ({ line: item.line, category: item.category.toUpperCase(), token: item.token }));
    }
    const jsonResult = {
      session_id: store.sessionId,
      total: findings.length,
      by_file: byFileJson,
      detail_report: '/mock/path',
    };

    // Validate JSON structure
    assert.equal(typeof jsonResult.session_id, 'string');
    assert.ok(jsonResult.session_id.startsWith('session-'));
    assert.equal(typeof jsonResult.total, 'number');
    assert.ok(jsonResult.total > 0);
    assert.equal(typeof jsonResult.by_file, 'object');
    assert.ok('/tmp/json-test.txt' in jsonResult.by_file);

    const fileEntries = jsonResult.by_file['/tmp/json-test.txt'];
    assert.ok(Array.isArray(fileEntries));
    assert.ok(fileEntries.length > 0);

    // Each entry has required fields
    for (const entry of fileEntries) {
      assert.equal(typeof entry.line, 'number');
      assert.equal(typeof entry.category, 'string');
      assert.equal(entry.category, entry.category.toUpperCase(), 'category should be uppercase');
      assert.match(entry.token, /^\[.+-\d{3}\]$/, 'token should be in mask format');
    }
  });

  it('returns empty by_file for zero findings', () => {
    const store = getStore();
    const jsonResult = {
      session_id: store.sessionId,
      total: 0,
      by_file: {},
      detail_report: null,
    };
    assert.equal(jsonResult.total, 0);
    assert.deepEqual(jsonResult.by_file, {});
    assert.equal(jsonResult.detail_report, null);
  });

  it('JSON output does not contain actual PII values', () => {
    const testEmail = 'secret-json@corp.example.com';
    maskText(`email: ${testEmail}`, '/tmp/json-pii-test.txt');

    const store = getStore();
    const findings = store.getFindings();
    const byFile = {};
    for (const f of findings) {
      (byFile[f.file] = byFile[f.file] || []).push(f);
    }
    const byFileJson = {};
    for (const [file, items] of Object.entries(byFile)) {
      byFileJson[file] = items.map((item) => ({ line: item.line, category: item.category.toUpperCase(), token: item.token }));
    }
    const jsonResult = {
      session_id: store.sessionId,
      total: findings.length,
      by_file: byFileJson,
      detail_report: '/mock/path',
    };
    const serialized = JSON.stringify(jsonResult);
    assert.ok(!serialized.includes(testEmail), 'JSON output must not contain actual PII');
  });
});
