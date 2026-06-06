import { describe, it, beforeEach } from 'node:test';
import { strict as assert } from 'node:assert';
import { maskText, unmaskText, getStore } from '../src/masker.mjs';

beforeEach(() => {
  getStore().clear();
});

describe('maskText', () => {
  it('should mask Japanese phone numbers', () => {
    const result = maskText('電話番号は090-1234-5678です');
    assert.ok(result.includes('[TEL-001]'), `got: ${result}`);
    assert.ok(!result.includes('090-1234-5678'));
  });

  it('should mask email addresses', () => {
    const result = maskText('連絡先: tanaka@company.co.jp');
    assert.ok(result.includes('[EMAIL-001]'), `got: ${result}`);
    assert.ok(!result.includes('tanaka@company.co.jp'));
  });

  it('should mask global IPv4 addresses', () => {
    const result = maskText('サーバー: 203.0.113.50');
    assert.ok(result.includes('[IPv4-001]'), `got: ${result}`);
    assert.ok(!result.includes('203.0.113.50'));
  });

  it('should mask private IPv4 with different prefix', () => {
    const result = maskText('LAN: 192.168.1.100');
    assert.ok(result.includes('[PRIV-IPv4-001]'), `got: ${result}`);
  });

  it('should skip invalid IPv4 (octet > 255)', () => {
    const result = maskText('version 1.2.300.4');
    assert.ok(!result.includes('[IPv4'), `should not mask: ${result}`);
  });

  it('should mask OpenAI API keys', () => {
    const result = maskText('OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwx');
    assert.ok(result.includes('[APIKEY-001]'), `got: ${result}`);
    assert.ok(!result.includes('sk-abcdefghijklmnopqrstuvwx'));
  });

  it('should mask password key-value pairs', () => {
    const result = maskText('password=my_secret_123');
    assert.ok(result.includes('[PASSWD-001]'), `got: ${result}`);
    assert.ok(!result.includes('my_secret_123'));
  });

  it('should mask Japanese password patterns', () => {
    const result = maskText('パスワード: secretpass');
    assert.ok(result.includes('[PASSWD-001]'), `got: ${result}`);
  });

  it('should mask credit card numbers with Luhn check', () => {
    const result = maskText('カード: 4111-1111-1111-1111');
    assert.ok(result.includes('[CARD-001]'), `got: ${result}`);
  });

  it('should not mask non-Luhn card-like numbers', () => {
    const result = maskText('ID: 1234-5678-9012-3456');
    assert.ok(!result.includes('[CARD'), `should not mask: ${result}`);
  });

  it('should mask Japanese addresses', () => {
    const result = maskText('住所: 東京都渋谷区神南1丁目');
    assert.ok(result.includes('[ADDR-001]'), `got: ${result}`);
  });

  it('should assign same token to same value', () => {
    const result = maskText('TEL: 090-1234-5678, FAX: 090-1234-5678');
    const matches = result.match(/\[TEL-001\]/g);
    assert.equal(matches?.length, 2, `same value should get same token: ${result}`);
  });

  it('should assign different tokens to different values', () => {
    const result = maskText('A: 090-1111-2222, B: 080-3333-4444');
    assert.ok(result.includes('[TEL-001]'), `got: ${result}`);
    assert.ok(result.includes('[TEL-002]'), `got: ${result}`);
  });

  it('should mask home paths', () => {
    const result = maskText('file at C:\\Users\\tanaka\\Documents\\secret.txt');
    assert.ok(result.includes('[PATH-001]'), `got: ${result}`);
  });

  it('should mask JWT tokens', () => {
    const result = maskText('Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature');
    assert.ok(result.includes('[JWT-001]'), `got: ${result}`);
    assert.ok(!result.includes('eyJhbGci'));
  });

  it('should mask AWS Secret Access Keys', () => {
    const result = maskText('Secret: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY');
    assert.ok(result.includes('[SECRET-001]'), `got: ${result}`);
    assert.ok(!result.includes('wJalrXUtnFEMI'));
  });

  it('should mask Azure AccountKey in connection strings', () => {
    const result = maskText('DefaultEndpointsProtocol=https;AccountKey=abc123def456ghi789jkl012mno345==;');
    assert.ok(result.includes('[SECRET-'), `got: ${result}`);
    assert.ok(!result.includes('abc123def456'));
  });

  it('should mask password with slash separator', () => {
    const result = maskText('管理者: admin / P@ssw0rd2026!');
    assert.ok(result.includes('[PASSWD-'), `got: ${result}`);
    assert.ok(!result.includes('P@ssw0rd2026!'));
  });

  it('should mask bank account with type prefix', () => {
    const result = maskText('三菱UFJ銀行 渋谷支店 普通 1234567');
    assert.ok(result.includes('[BANK-'), `got: ${result}`);
    assert.ok(!result.includes('1234567'));
  });

  it('should mask Japanese passport numbers', () => {
    const result = maskText('パスポート番号: TK1234567');
    assert.ok(result.includes('[PASSPORT-001]'), `got: ${result}`);
    assert.ok(!result.includes('TK1234567'));
  });

  it('should mask corporate numbers', () => {
    const result = maskText('法人番号: 1234567890123');
    assert.ok(result.includes('[CORPNUM-001]'), `got: ${result}`);
    assert.ok(!result.includes('1234567890123'));
  });

  it('should mask Japanese person names (surname + space + given name)', () => {
    const result = maskText('管理者: 山田 花子');
    assert.ok(result.includes('[PERSON-'), `got: ${result}`);
    assert.ok(!result.includes('山田 花子'));
  });

  it('should mask Japanese person names with full-width space', () => {
    const result = maskText('担当: 佐藤　健太');
    assert.ok(result.includes('[PERSON-'), `got: ${result}`);
    assert.ok(!result.includes('佐藤'));
  });

  it('should not mask geographic pairs as person names', () => {
    const result = maskText('東京都 渋谷区');
    assert.ok(!result.includes('[PERSON-'), `should not mask geo pair: ${result}`);
  });

  it('should mask comma-separated name lists', () => {
    const result = maskText('共同編集者: 鈴木、田中、高橋、渡辺');
    assert.ok(result.includes('[PERSON-'), `got: ${result}`);
    assert.ok(!result.includes('鈴木'));
  });

  it('should mask CJK Extension A characters in names', () => {
    const result = maskText('担当: 木村 次郎');
    assert.ok(result.includes('[PERSON-'), `got: ${result}`);
  });
});

describe('unmaskText', () => {
  it('should restore all masked tokens', () => {
    const original = '電話: 090-1234-5678, メール: test@example.com';
    const masked = maskText(original);
    const restored = unmaskText(masked);
    assert.equal(restored, original);
  });

  it('should handle text with no tokens', () => {
    maskText('090-1234-5678');
    const result = unmaskText('トークンなしのテキスト');
    assert.equal(result, 'トークンなしのテキスト');
  });
});

describe('store', () => {
  it('should report correct stats', () => {
    maskText('090-1234-5678 test@example.com 203.0.113.1');
    const stats = getStore().stats();
    assert.ok(stats.totalMasked >= 3, `totalMasked: ${stats.totalMasked}`);
    assert.ok(stats.byCategory.TEL >= 1);
    assert.ok(stats.byCategory.EMAIL >= 1);
    assert.ok(stats.byCategory.IPv4 >= 1);
  });

  it('should save and report map file path', () => {
    maskText('090-1234-5678');
    const stats = getStore().stats();
    assert.ok(stats.mapFile.includes('.pii-mask-yoshi'));
  });
});
