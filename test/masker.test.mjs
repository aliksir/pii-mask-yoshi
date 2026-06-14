import { describe, it, beforeEach } from 'node:test';
import { strict as assert } from 'node:assert';
import { maskText, unmaskText, getStore } from '../src/masker.mjs';

beforeEach(() => {
  getStore().clear();
});

describe('maskText', () => {
  it('should mask Japanese phone numbers', () => {
    const result = maskText('電話番号は090-1234-5678です');
    assert.ok(result.includes('[電話A]'), `got: ${result}`);
    assert.ok(!result.includes('090-1234-5678'));
  });

  it('should mask email addresses', () => {
    const result = maskText('連絡先: tanaka@company.co.jp');
    assert.ok(result.includes('[メールA]'), `got: ${result}`);
    assert.ok(!result.includes('tanaka@company.co.jp'));
  });

  it('should mask global IPv4 addresses', () => {
    const result = maskText('サーバー: 203.0.113.50');
    assert.ok(result.includes('[IPv4A]'), `got: ${result}`);
    assert.ok(!result.includes('203.0.113.50'));
  });

  it('should mask private IPv4 with different prefix', () => {
    const result = maskText('LAN: 192.168.1.100');
    assert.ok(result.includes('[内部IPv4A]'), `got: ${result}`);
  });

  it('should skip invalid IPv4 (octet > 255)', () => {
    const result = maskText('version 1.2.300.4');
    assert.ok(!result.includes('[IPv4'), `should not mask: ${result}`);
  });

  it('should mask OpenAI API keys', () => {
    const result = maskText('OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwx');
    assert.ok(result.includes('[APIキーA]'), `got: ${result}`);
    assert.ok(!result.includes('sk-abcdefghijklmnopqrstuvwx'));
  });

  it('should mask password key-value pairs', () => {
    const result = maskText('password=my_secret_123');
    assert.ok(result.includes('[PWA]'), `got: ${result}`);
    assert.ok(!result.includes('my_secret_123'));
  });

  it('should mask Japanese password patterns', () => {
    const result = maskText('パスワード: secretpass');
    assert.ok(result.includes('[PWA]'), `got: ${result}`);
  });

  it('should mask credit card numbers with Luhn check', () => {
    const result = maskText('カード: 4111-1111-1111-1111');
    assert.ok(result.includes('[カードA]'), `got: ${result}`);
  });

  it('should not mask non-Luhn card-like numbers', () => {
    const result = maskText('ID: 1234-5678-9012-3456');
    assert.ok(!result.includes('[カード'), `should not mask: ${result}`);
  });

  it('should mask Japanese addresses', () => {
    const result = maskText('住所: 東京都渋谷区神南1丁目');
    assert.ok(result.includes('[住所A]'), `got: ${result}`);
  });

  it('should assign same token to same value', () => {
    const result = maskText('TEL: 090-1234-5678, FAX: 090-1234-5678');
    const matches = result.match(/\[電話A\]/g);
    assert.equal(matches?.length, 2, `same value should get same token: ${result}`);
  });

  it('should assign different tokens to different values', () => {
    const result = maskText('A: 090-1111-2222, B: 080-3333-4444');
    assert.ok(result.includes('[電話A]'), `got: ${result}`);
    assert.ok(result.includes('[電話B]'), `got: ${result}`);
  });

  it('should mask home paths', () => {
    const result = maskText('file at C:\\Users\\tanaka\\Documents\\secret.txt');
    assert.ok(result.includes('[パスA]'), `got: ${result}`);
  });

  it('should mask JWT tokens', () => {
    const result = maskText('Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature');
    assert.ok(result.includes('[JWTA]'), `got: ${result}`);
    assert.ok(!result.includes('eyJhbGci'));
  });

  it('should mask AWS Secret Access Keys', () => {
    const result = maskText('Secret: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY');
    assert.ok(result.includes('[秘匿値A]'), `got: ${result}`);
    assert.ok(!result.includes('wJalrXUtnFEMI'));
  });

  it('should mask Azure AccountKey in connection strings', () => {
    const result = maskText('DefaultEndpointsProtocol=https;AccountKey=abc123def456ghi789jkl012mno345==;');
    assert.ok(result.includes('[秘匿値'), `got: ${result}`);
    assert.ok(!result.includes('abc123def456'));
  });

  it('should mask password with slash separator', () => {
    const result = maskText('管理者: admin / P@ssw0rd2026!');
    assert.ok(result.includes('[PW'), `got: ${result}`);
    assert.ok(!result.includes('P@ssw0rd2026!'));
  });

  it('should mask bank account with type prefix', () => {
    const result = maskText('三菱UFJ銀行 渋谷支店 普通 1234567');
    assert.ok(result.includes('[口座'), `got: ${result}`);
    assert.ok(!result.includes('1234567'));
  });

  it('should mask Japanese passport numbers', () => {
    const result = maskText('パスポート番号: TK1234567');
    assert.ok(result.includes('[パスポートA]'), `got: ${result}`);
    assert.ok(!result.includes('TK1234567'));
  });

  it('should mask corporate numbers', () => {
    const result = maskText('法人番号: 1234567890123');
    assert.ok(result.includes('[法人番号A]'), `got: ${result}`);
    assert.ok(!result.includes('1234567890123'));
  });

  it('should mask Japanese person names (surname + space + given name)', () => {
    const result = maskText('管理者: 山田 花子');
    assert.ok(result.includes('[人名'), `got: ${result}`);
    assert.ok(!result.includes('山田 花子'));
  });

  it('should mask Japanese person names with full-width space', () => {
    const result = maskText('担当: 佐藤　健太');
    assert.ok(result.includes('[人名'), `got: ${result}`);
    assert.ok(!result.includes('佐藤'));
  });

  it('should not mask geographic pairs as person names', () => {
    const result = maskText('東京都 渋谷区');
    assert.ok(!result.includes('[人名'), `should not mask geo pair: ${result}`);
  });

  it('should mask comma-separated name lists', () => {
    const result = maskText('共同編集者: 鈴木、田中、高橋、渡辺');
    assert.ok(result.includes('[人名'), `got: ${result}`);
    assert.ok(!result.includes('鈴木'));
  });

  it('should mask CJK Extension A characters in names', () => {
    const result = maskText('担当: 木村 次郎');
    assert.ok(result.includes('[人名'), `got: ${result}`);
  });

  // A1: 敬称トリガー
  it('should mask person name with honorific suffix (さん)', () => {
    getStore().clear();
    const result = maskText('渡辺さんに連絡してください');
    assert.ok(result.includes('[人名'), `got: ${result}`);
    assert.ok(!result.includes('渡辺さん'));
  });

  it('should mask person name with title suffix (部長)', () => {
    getStore().clear();
    const result = maskText('松本部長が承認しました');
    assert.ok(result.includes('[人名'), `got: ${result}`);
    assert.ok(!result.includes('松本'));
  });

  it('should not mask generic honorifics (お客様)', () => {
    const result = maskText('お客様のご要望にお応えします');
    assert.ok(!result.includes('[人名'), `should not mask: ${result}`);
  });

  // A2: 助詞ウィンドウ (indirect test via nospace names)
  it('should mask nospace name followed by particle', () => {
    getStore().clear();
    const result = maskText('佐藤太郎が発表した');
    assert.ok(result.includes('[人名'), `got: ${result}`);
  });

  // A3: Anti-context (人名系パターンのみ適用、電話等の構造的パターンは除外対象外)
  it('should not mask person name in test data context', () => {
    getStore().clear();
    const result = maskText('テストデータ: 田中 太郎');
    assert.ok(!result.includes('[人名'), `anti-context should skip person names: ${result}`);
  });

  it('should still mask phone number even in example context (structural pattern)', () => {
    getStore().clear();
    const result = maskText('例）03-1234-5678 のように入力');
    assert.ok(result.includes('[電話A]'), `structural patterns ignore anti-context: ${result}`);
  });

  it('should still mask credentials even near test context', () => {
    getStore().clear();
    const result = maskText('テストデータ password: secret123');
    assert.ok(result.includes('[PW'), `credentials should still mask: ${result}`);
  });

  // A4: ラベル共起 (SC-6)
  it('should mask name after label (Top50外の姓)', () => {
    getStore().clear();
    const result = maskText('氏名：木下美咲');
    assert.ok(result.includes('[人名'), `got: ${result}`);
    assert.ok(!result.includes('木下美咲'));
    assert.ok(result.includes('氏名'), `label should remain: ${result}`);
  });

  // A5: Top200姓
  it('should mask Top200 surname without space (藤井)', () => {
    getStore().clear();
    const result = maskText('藤井太郎が参加した');
    assert.ok(result.includes('[人名'), `got: ${result}`);
  });

  // B1: 在留カード番号
  it('should mask residence card number', () => {
    getStore().clear();
    const result = maskText('在留カード: AB12345678CD');
    assert.ok(result.includes('[在留カードA]'), `got: ${result}`);
    assert.ok(!result.includes('AB12345678CD'));
  });

  // B2: 基礎年金番号 (文脈必要)
  it('should mask pension number with context', () => {
    getStore().clear();
    const result = maskText('基礎年金番号: 1234-567890');
    assert.ok(result.includes('[年金番号A]'), `got: ${result}`);
  });

  // B3: 運転免許証番号 (文脈必須)
  it('should mask driver license number with context', () => {
    getStore().clear();
    const result = maskText('運転免許証番号: 123456789012');
    assert.ok(result.includes('[免許番号A]'), `got: ${result}`);
  });

  it('should not mask 12-digit number without license context', () => {
    getStore().clear();
    const result = maskText('注文番号 123456789012 を確認');
    assert.ok(!result.includes('[免許番号'), `should not mask without context: ${result}`);
  });

  // B4: URL
  it('should mask URLs', () => {
    getStore().clear();
    const result = maskText('詳細は https://example.com/path?q=1 を参照');
    assert.ok(result.includes('[URLA]'), `got: ${result}`);
    assert.ok(!result.includes('https://example.com'));
  });

  // B5: 暗号通貨アドレス
  it('should mask Ethereum address', () => {
    getStore().clear();
    const result = maskText('ETH: 0x742d35Cc6634C0532925a3b844Bc9e7595f2bD68');
    assert.ok(result.includes('[暗号通貨A]'), `got: ${result}`);
  });

  // B6: IBAN
  it('should mask valid IBAN', () => {
    getStore().clear();
    const result = maskText('IBAN: GB29NWBK60161331926819');
    assert.ok(result.includes('[IBANA]'), `got: ${result}`);
  });

  // B7: 住民票コード (文脈必須)
  it('should mask jumin code with context', () => {
    getStore().clear();
    const result = maskText('住民票コード: 12345678901');
    assert.ok(result.includes('[住民票コードA]'), `got: ${result}`);
  });

  it('should not mask 11-digit number without jumin context', () => {
    getStore().clear();
    const result = maskText('電話番号 12345678901 です');
    assert.ok(!result.includes('[住民票コード'), `should not mask without context: ${result}`);
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
    assert.ok(stats.byCategory['電話'] >= 1);
    assert.ok(stats.byCategory['メール'] >= 1);
    assert.ok(stats.byCategory['IPv4'] >= 1);
  });

  it('should save and report map file path', () => {
    maskText('090-1234-5678');
    const stats = getStore().stats();
    assert.ok(stats.mapFile.includes('.pii-mask-yoshi'));
  });
});
