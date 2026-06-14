import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

import { homedir } from 'node:os';
const NEKO_NOT_YOSHI_DIR = process.env.NEKO_NOT_YOSHI_DIR || join(homedir(), 'neko-not-yoshi');

const BUILTIN_PATTERNS = [
  { id: 'email', category: 'pii', regex: '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}', maskPrefix: 'EMAIL' },
  { id: 'phone-jp', category: 'pii', regex: '0\\d{1,4}-\\d{1,4}-\\d{4}', maskPrefix: 'TEL' },
  { id: 'ipv4', category: 'network', regex: '(?:\\d{1,3}\\.){3}\\d{1,3}', maskPrefix: 'IPv4' },
  { id: 'ipv6', category: 'network', regex: '(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}', maskPrefix: 'IPv6' },
  { id: 'local-path-home', category: 'pii', regex: "[A-Za-z]:[\\\\/]Users[\\\\/][^\\s\"'`,)]+", maskPrefix: 'PATH' },
];

const JP_SURNAMES_TOP200 = '長谷川|佐々木|佐藤|鈴木|高橋|田中|伊藤|渡辺|山本|中村|小林|加藤|吉田|山田|松本|井上|木村|斎藤|清水|山崎|阿部|池田|橋本|山口|石川|前田|小川|藤田|岡田|後藤|石井|村上|近藤|坂本|遠藤|青木|藤井|西村|福田|太田|三浦|藤原|岡本|松田|中川|中野|原田|小野|林|森|竹内|金子|和田|中島|原|中田|上田|高木|菅原|服部|杉山|北村|内田|松井|千葉|久保|水野|安藤|稲垣|奥村|市川|川口|本田|横山|増田|工藤|沢田|赤坂|黒田|大野|浜田|田村|植田|平野|中山|東|藤本|宮崎|内山|島田|吉川|野口|西田|白井|大西|熊谷|萩原|高田|宮田|鎌田|菊池|佐野|矢島|松尾|堀|古川|星野|渡部|村田|牧野|片山|上野|関口|大塚|山内|川村|寺田|三宅|長島|飯田|石田|新井|今井|堀口|河野|馬場|岩田|土屋|酒井|永井|田口|菅野|大久保|丸山|高山|宮本|山下|石原|武田|長田|池上|大島|小島|高野|伊東|久保田|永田|田辺|辻|今村|日野|木下|荒井|永野|宮川|小沢|桑原|北川|浜口|脇田|谷口|平田|田所|根本|沢|湯川|安田|野田|菊地|辻本|小山|前川|斉藤|桑田|矢野|岩崎';
const JP_SURNAME_RE = new RegExp(`^(?:${JP_SURNAMES_TOP200})`);

const EXTRA_PATTERNS = [
  { id: 'jwt-token', category: 'credential', regex: 'eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.?[A-Za-z0-9_-]*', maskPrefix: 'JWT' },
  { id: 'api-key-openai', category: 'credential', regex: 'sk-[a-zA-Z0-9]{20,}', maskPrefix: 'APIKEY' },
  { id: 'api-key-github', category: 'credential', regex: 'ghp_[a-zA-Z0-9]{36,}', maskPrefix: 'APIKEY' },
  { id: 'api-key-aws', category: 'credential', regex: 'AKIA[A-Z0-9]{16}', maskPrefix: 'APIKEY' },
  { id: 'api-key-anthropic', category: 'credential', regex: 'sk-ant-[a-zA-Z0-9-]{20,}', maskPrefix: 'APIKEY' },
  { id: 'aws-secret-key', category: 'credential', regex: '(?:(?:aws)?_?secret_?(?:access)?_?key|SecretAccessKey|Secret)\\s*[:=]\\s*[A-Za-z0-9/+=]{40}', maskPrefix: 'SECRET' },
  { id: 'azure-account-key', category: 'credential', regex: 'AccountKey=[A-Za-z0-9/+=]{20,}', maskPrefix: 'SECRET' },
  { id: 'password-kv-slash', category: 'credential', regex: "(?:管理者|\\badmin\\b|\\broot\\b|\\buser\\b)\\s*/\\s*[^\\s,;}\\\\'\"\\]]{1,128}", maskPrefix: 'PASSWD' },
  { id: 'password-kv-en', category: 'credential', regex: "\\b(?:password|passwd|secret|token)\\s*[:=]\\s*[^\\s,;}\\\\'\"\\]]{1,128}", maskPrefix: 'PASSWD' },
  { id: 'password-kv-ja', category: 'credential', regex: "(?:パスワード|パス|密码|秘密鍵)\\s*[:=：]\\s*[^\\s,;}\\\\'\"\\]]{1,128}", maskPrefix: 'PASSWD' },
  { id: 'credit-card', category: 'financial', regex: '\\b(?:\\d{4}[-\\s]?){3}\\d{4}\\b', maskPrefix: 'CARD' },
  { id: 'my-number', category: 'pii', regex: '\\b\\d{4}\\s?\\d{4}\\s?\\d{4}\\b', maskPrefix: 'MYNUM' },
  { id: 'bank-account', category: 'financial', regex: '(?:口座番号|口座)\\s*[:=：]?\\s*\\d{7,8}', maskPrefix: 'BANK' },
  { id: 'bank-account-type', category: 'financial', regex: '(?:普通|当座)\\s*\\d{7,8}', maskPrefix: 'BANK' },
  { id: 'passport-jp', category: 'pii', regex: '\\b[A-Z]{2}\\d{7}\\b', maskPrefix: 'PASSPORT' },
  { id: 'corporate-number', category: 'pii', regex: '(?:法人番号\\s*[:：]?\\s*|\\bT)\\d{13}', maskPrefix: 'CORPNUM' },
  { id: 'jp-address', category: 'pii', regex: '(?:東京都|北海道|(?:大阪|京都)府|[\\u4E00-\\u9FFF]{2,3}県)(?=[^はでをがもと])(?:[\\u4E00-\\u9FFF\\u3040-\\u309F\\u30A0-\\u30FF0-9０-９]{1,4}[\\u5E02\\u533A\\u753A\\u6751\\u90E1])[\\u4E00-\\u9FFF\\u30A0-\\u30FF0-9０-９\\-]{0,15}', maskPrefix: 'ADDR' },
  { id: 'jp-person-name', category: 'pii', regex: '[\\u3005\\u3400-\\u9FFF]{1,4}[ \\t\\u3000]+[\\u3005\\u3400-\\u9FFF\\u3041-\\u3096]{1,4}', maskPrefix: 'PERSON' },
  { id: 'jp-person-name-nospace', category: 'pii', regex: `(?:${JP_SURNAMES_TOP200})[\\u3005\\u3400-\\u9FFF]{1,3}`, maskPrefix: 'PERSON' },
  { id: 'jp-person-name-list', category: 'pii', regex: '[\\u3005\\u3400-\\u9FFF]{1,4}(?:[、,][\\u3005\\u3400-\\u9FFF]{1,4}){2,}', maskPrefix: 'PERSON' },
  { id: 'jp-person-name-honorific', category: 'pii', regex: '[\\u3005\\u3400-\\u9FFF]{2,6}(?:さん|様|氏|殿|先生|部長|課長|社長|所長|院長|局長|室長|係長|主任)', maskPrefix: 'PERSON' },
  { id: 'jp-label-name', category: 'pii', regex: '(?<=(?:氏名|名前|担当者?|代表者?|連絡先名?)\\s*[::\\uFF1A]\\s*)(?:[\\u3005\\u3400-\\u9FFF]{2,6}[\\s　]+)?[\\u3005\\u3400-\\u9FFF]{2,6}(?:[\\s　]+[\\u3005\\u3400-\\u9FFF]{1,4})?', maskPrefix: 'PERSON', defaultConfidence: 0.9 },
  { id: 'jp-label-address', category: 'pii', regex: '(?<=(?:住所|所在地|居住地|現住所)\\s*[::\\uFF1A]\\s*)(?:[\\u3005\\u3400-\\u9FFF\\u3040-\\u309F\\u30A0-\\u30FF0-9０-９]{2,30})', maskPrefix: 'ADDR' },
  { id: 'jp-label-phone', category: 'pii', regex: '(?<=(?:電話番号?|TEL|tel|携帯番号?|連絡先)\\s*[::\\uFF1A]\\s*)\\d[\\d-]{7,14}', maskPrefix: 'TEL' },
  { id: 'zairyu-card', category: 'pii', regex: '[A-Z]{2}\\d{8}[A-Z]{2}', maskPrefix: 'ZAIRYU' },
  { id: 'basic-pension', category: 'pii', regex: '\\d{4}[-ー－]\\d{6}', maskPrefix: 'PENSION' },
  { id: 'driver-license', category: 'pii', regex: '\\d{12}', maskPrefix: 'LICENSE' },
  { id: 'url', category: 'network', regex: 'https?://[^\\s<>\'"\\)\\]]+', maskPrefix: 'URL' },
  { id: 'crypto-eth', category: 'credential', regex: '0x[a-fA-F0-9]{40}', maskPrefix: 'CRYPTO' },
  { id: 'crypto-btc', category: 'credential', regex: '[13][a-km-zA-HJ-NP-Z1-9]{25,34}', maskPrefix: 'CRYPTO' },
  { id: 'iban', category: 'financial', regex: '[A-Z]{2}\\d{2}[A-Z0-9]{4}\\d{7}[A-Z0-9]{0,16}', maskPrefix: 'IBAN' },
  { id: 'jumin-code', category: 'pii', regex: '\\d{11}', maskPrefix: 'JUMINCODE' },
  { id: 'amount-yen', category: 'business', regex: '[0-9０-９,，]{1,15}[万億兆]?円', maskPrefix: 'AMOUNT' },
  { id: 'amount-yen-kanji', category: 'business', regex: '[一二三四五六七八九十百千万億兆]{2,8}円', maskPrefix: 'AMOUNT' },
  { id: 'date-jp-era', category: 'business', regex: '(?:令和|平成|昭和|大正|明治)[元0-9０-９]{1,3}年(?:[0-9０-９]{1,2}月)?(?:[0-9０-９]{1,2}日)?', maskPrefix: 'DATE' },
  { id: 'date-iso', category: 'business', regex: '20[0-9]{2}[-/][01]?[0-9][-/][0-3]?[0-9]', maskPrefix: 'DATE' },
  // 郵便番号（〒マーク付き）
  { id: 'postal-code-jp', category: 'pii', regex: '〒[0-9]{3}-[0-9]{4}', maskPrefix: 'POSTAL' },
  // 全角ハイフン電話番号
  { id: 'phone-jp-fullwidth', category: 'pii', regex: '0[0-9]{1,4}[－ー][0-9]{1,4}[－ー][0-9]{4}', maskPrefix: 'TEL' },
  // ひらがなふりがな姓名（括弧内）
  { id: 'jp-furigana-name', category: 'pii', regex: '[（(][ぁ-ん]{2,6}[ \\t　][ぁ-ん]{2,6}[）)]', maskPrefix: 'PERSON' },
  // 片仮名人名（スペース区切り2語以上）
  { id: 'jp-katakana-name', category: 'pii', regex: '[ァ-ヴー]{2,8}[ \\t　][ァ-ヴー]{2,8}', maskPrefix: 'PERSON' },
  // 中黒区切り複数人名（姓・姓 形式）
  { id: 'jp-name-nakaguro', category: 'pii', regex: '[\\u3005\\u3400-\\u9FFF]{1,4}・[\\u3005\\u3400-\\u9FFF]{1,4}', maskPrefix: 'PERSON' },
  // 全角スペース区切り姓名（小林　宝 型、Top200姓に限定）
  { id: 'jp-person-name-fullspace', category: 'pii', regex: `(?:${JP_SURNAMES_TOP200})\\u3000[\\u3005\\u3400-\\u9FFF\\u3041-\\u3096]{1,4}`, maskPrefix: 'PERSON' },
  // 会社名（株式会社〜 または 〜株式会社 形式）
  { id: 'jp-company-name', category: 'pii', regex: '(?:株式会社|有限会社|合同会社|合資会社)[ぁ-ん\\u3005\\u3400-\\u9FFF\\uFF66-\\uFF9F\\u30A0-\\u30FF\\uFF21-\\uFF3AA-Za-z0-9・]{2,20}|[ぁ-ん\\u3005\\u3400-\\u9FFF\\uFF66-\\uFF9F\\u30A0-\\u30FF\\uFF21-\\uFF3AA-Za-z0-9・]{2,20}(?:株式会社|有限会社|合同会社|合資会社|（株）|\\(株\\))', maskPrefix: 'COMPANY' },
  // 生年パターン
  { id: 'birth-year-jp', category: 'pii', regex: '(?:19|20)[0-9]{2}年生まれ', maskPrefix: 'BIRTHYEAR' },
  // 西暦年月日（全体の日付: YYYY年M月D日）
  { id: 'date-jp-full', category: 'business', regex: '[0-9]{4}年[0-9]{1,2}月[0-9]{1,2}日', maskPrefix: 'DATE' },
];

const CATEGORY_TO_PREFIX = {
  email: 'EMAIL',
  'phone-jp': 'TEL',
  ipv4: 'IPv4',
  ipv6: 'IPv6',
  'local-path-home': 'PATH',
  'local-path-work': 'PATH',
};

function classifyIPv4(ip) {
  const o = ip.split('.').map((n) => Number(n));
  if (o.length !== 4 || o.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return 'invalid';
  if (o[0] === 10) return 'private';
  if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return 'private';
  if (o[0] === 192 && o[1] === 168) return 'private';
  if (o[0] === 127) return 'private';
  if (o[0] === 0 || o[0] === 255) return 'private';
  if (o[0] === 169 && o[1] === 254) return 'private';
  return 'global';
}

function looksLikeIPv6(s) {
  if (s.includes('::')) return true;
  const g = s.split(':');
  if (g.length < 6) return false;
  return g.some((x) => x.length >= 3 || /[a-fA-F]/.test(x));
}

const GEO_SUFFIXES = /[都道府県市区町村郡]$/;
const NOSPACE_EXCLUDE = /(?:様|氏|殿|社|部|課|係|長|官|局|室|員|棟|号|館|駅|港|橋|寺|院|神|塚|山|川|池|田|畑|工業|電気|商店|物産|建設|製作|通信|銀行|保険|証券|不動産|新聞|食品|薬品|産業|科学|商事|運送|倉庫|鉄道|放送|出版|印刷|繊維|化学|金属|機械|電子|光学|医療|福祉|教育|大学|学院|中学|小学|幼稚|高校|学園|病院|薬局|農園|牧場|酒造|醸造|水産|漁業|林業|鉱業|興業|観光|旅館|飯店|食堂|書店|薬店|花店|教授|先生|委員|議員|知事|市長|大臣|弁護士|医師|博士|商会|組合|漁協|農協|学校|幼園)$/;

// 第2パートが一般動詞・操作名で終わる場合は人名ではない
const NON_NAME_ENDINGS = /(?:処理|管理|対応|追加|変更|削除|設定|確認|報告|実装|作成|修正|更新|登録|解除|承認|完了|開始|終了|検討|導入|移行|構築|改善|改修|分析|統計|集計|検証|試験|測定|調査|連絡|相談|方法|情報|一覧|研究|発表|委員|議員|学会|研究科|職員|業務|工事|工務|建設|開発|運用|担当|責任|担当者|制度|規程|規則|通達|規約|基準)$/;

// 第1パートが一般的な概念語の場合は人名ではない
const COMMON_FIRST_WORDS = new Set([
  '情報', '品質', '機能', '技術', '基本', '詳細', '概要', '要件', '仕様',
  '画面', '帳票', '一覧', '明細', '予算', '実績', '計画', '目標', '成果',
  '評価', '審査', '監査', '環境', '設備', '資材', '資産', '在庫', '受注',
  '発注', '請求', '支払', '売上', '原価', '利益', '費用', '経費', '給与',
  '処理', '学会', '発表', '分類', '研究', '参加', '申込', '講演', '登壇',
  '基調', '登壇者', '会場', '幕張', '配信', '管理', '戦略', '未来', '号館',
  '行委', '者連', '執行', '株式', '合同', '工務', '専務', '総務', '省庁',
  '政策', '局長', '究部', '部門', '大学', '学研', '東京',
]);

// 人名として出現しにくい第2パートの語（組織・役職・概念語）
const NON_NAME_SECOND_WORDS = new Set([
  '部長', '課長', '係長', '室長', '主任', '工事', '事業', '代表', '関係',
  '支援', '一式', '以降', '以前', '以外', '以上', '以下',
  '申請', '通知', '開催', '開幕', '実行', '研報',
  '研究科', '学部', '事務局',
]);

// 法人格・組織形態語（第1パートとして人名ではない）
const LEGAL_ENTITY_WORDS = /^(?:株式会社|有限会社|合同会社|合資会社|一般社団|公益社団|特定非営利|独立行政|国立研究|都立|県立|市立|区立)/;

function validateJpName(matched) {
  // 改行を含む場合は人名ではない（FP抑制: 「会場\n幕張」等）
  if (/[\n\r]/.test(matched)) return null;
  const parts = matched.trim().split(/[ \t　]+/);
  if (parts.length !== 2) return null;
  if (GEO_SUFFIXES.test(parts[0]) && GEO_SUFFIXES.test(parts[1])) return null;
  if (COMMON_FIRST_WORDS.has(parts[0])) return null;
  if (COMMON_FIRST_WORDS.has(parts[1])) return null;
  if (NON_NAME_ENDINGS.test(parts[1])) return null;
  if (NON_NAME_SECOND_WORDS.has(parts[1])) return null;
  if (/[部課室係局所省庁院]$/.test(parts[0])) return null;
  if (/[部課室係局所省庁院]$/.test(parts[1])) return null;
  // 法人格語が第1パートの場合は除外（「株式会社 の役員」等）
  if (LEGAL_ENTITY_WORDS.test(parts[0])) return null;
  // 金額コンテキスト除外: 第1パートが金額単位の場合（「万円 相当」等）
  if (/^[万億兆百千円]/.test(parts[0]) || /^[万億兆百千]/.test(parts[1].slice(0, 1))) return null;
  // 第2パートが「相当」「以上」「未満」等の比較語の場合は除外
  if (/^(?:相当|以上|以下|未満|超過|程度|前後|水準|規模)/.test(parts[1])) return null;
  return 'PERSON';
}

const NOSPACE_CONTAINS = /(?:工業|電気|商店|物産|建設|製作|通信|銀行|保険|証券|不動産|新聞|食品|薬品|産業|商事|運送|倉庫|鉄道|放送|出版|印刷|医療|福祉|教育|病院|観光|酒造|水産|漁業|部長|課長|社長|会長|取締|委員|教授|先生|議員|大臣|知事|市長|弁護|医師|博士|主任|係長|局長|室長)/;

function validateJpNameNospace(matched, ctx) {
  if (matched.length < 3 || matched.length > 6) return null;
  if (GEO_SUFFIXES.test(matched)) return null;
  if (NOSPACE_EXCLUDE.test(matched)) return null;
  const afterSurname = matched.replace(JP_SURNAME_RE, '');
  if (NOSPACE_CONTAINS.test(afterSurname)) return null;
  if (ctx) {
    const after = ctx.text.slice(ctx.end, ctx.end + 4);
    if (/^(?:は|が|を|に|で|の|へ|から|まで|として|という)/.test(after)) return 'PERSON';
  }
  const surname = matched.match(JP_SURNAME_RE)?.[0];
  if (surname && surname.length === 1) return null;
  return 'PERSON';
}

function luhnCheck(num) {
  const digits = num.replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = parseInt(digits[i], 10);
    if (alt) { n *= 2; if (n > 9) n -= 9; }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

function validateMyNumber(matched) {
  const digits = matched.replace(/\s/g, '');
  if (digits.length !== 12) return null;
  // マイナンバーチェックデジット: Q[n] * P[n] の合計 mod 11
  const q = digits.split('').map(Number);
  const p = [6, 5, 4, 3, 2, 7, 6, 5, 4, 3, 2];
  let sum = 0;
  for (let i = 0; i < 11; i++) sum += q[i] * p[i];
  const remainder = sum % 11;
  const checkDigit = remainder <= 1 ? 0 : 11 - remainder;
  if (q[11] !== checkDigit) return null;
  return 'MYNUM';
}

const NON_NAME_WORDS = new Set([
  '東京', '大阪', '名古屋', '福岡', '札幌', '横浜', '神戸', '京都', '広島', '仙台',
  '横浜市', '川崎市', '千葉市', '浜松市', '堺市', '新潟市', '静岡市', '岡山市',
  '営業', '技術', '管理', '総務', '経理', '人事', '企画', '開発', '設計', '製造',
  '生産', '物流', '販売', '購買', '調達', '検査', '保守', '運用', '広報', '法務',
  '会計', '財務', '監査', '品質', '安全', '環境', '情報', '研究', '教育', '福利',
  '売上高', '売上', '利益', '時価', '従業', '工業', '商業', '観光', '農業', '漁業',
  '鹿児島', '営業利益', '時価総額', '従業員数', '純利益', '経常利益',
  // 組織・機関（FP追加分）
  '吉田本町', '東京基礎', '処理学会', '情報学', '学会', '研究報告', '発表一覧',
  '業務一式', '保守業務', '会計課長', '室契約班', '参加申込',
]);

function validateJpNameList(matched) {
  const items = matched.split(/[、,]/);
  if (items.some(item => item.length < 2)) return null;
  const longItems = items.filter(item => item.length > 4);
  if (longItems.length > items.length / 2) return null;
  const nonNameCount = items.filter(item => NON_NAME_WORDS.has(item)).length;
  if (nonNameCount >= items.length / 2) return null;
  const instSuffix = /[藩城寺宮院塔閣橋川山湖池港駅線路号丁市区町村郡県府都道社軍職制令地]/;
  const instCount = items.filter(item => instSuffix.test(item.slice(-1))).length;
  if (instCount >= items.length / 2) return null;
  return 'PERSON';
}

// D2: 敬称トリガー validator
const GENERIC_HONORIFIC = /^(?:お客様|皆様|各位|関係者各位|担当者様|ご担当者様|受講者様|利用者様|保護者様)/;

function validateHonorific(matched) {
  if (GENERIC_HONORIFIC.test(matched)) return null;
  // 敬称部分を除去して漢字部分のみ取得
  const name = matched.replace(/(?:さん|様|氏|殿|先生|部長|課長|社長|所長|院長|局長|室長|係長|主任)$/, '');
  if (name.length < 2) return null;
  // 敬称付きは人名確度が高いため、組織名・役職名のみ除外（NOSPACE_EXCLUDEは使わない）
  if (NOSPACE_CONTAINS.test(name)) return null;
  if (GEO_SUFFIXES.test(name)) return null;
  return 'PERSON';
}

// D8: contextContains ヘルパー
function contextContains(ctx, keywords) {
  if (!ctx) return false;
  const s = Math.max(0, ctx.start - 30);
  const e = Math.min(ctx.text.length, ctx.end + 30);
  const range = ctx.text.slice(s, e);
  return keywords.some(k => range.includes(k));
}

// D8: IBAN mod97 バリデーション
function validateIBAN(iban) {
  const rearranged = iban.slice(4) + iban.slice(0, 4);
  const numeric = rearranged.replace(/[A-Z]/g, ch => (ch.charCodeAt(0) - 55).toString());
  let remainder = '';
  for (const ch of numeric) {
    remainder = String(Number(remainder + ch) % 97);
  }
  return Number(remainder) === 1;
}

function compileBasePattern(p) {
  return {
    id: p.id,
    category: p.category,
    regex: new RegExp(p.regex, 'g'),
    maskPrefix: CATEGORY_TO_PREFIX[p.id] || p.maskPrefix || p.category.toUpperCase(),
    validator: p.id === 'ipv4' ? (m) => {
      const cls = classifyIPv4(m);
      if (cls === 'invalid') return null;
      return { label: cls === 'private' ? 'PRIV-IPv4' : 'IPv4', confidence: 1.0 };
    } : p.id === 'ipv6' ? (m) => looksLikeIPv6(m) ? { label: 'IPv6', confidence: 1.0 } : null : null,
  };
}

// 組織・役職語を含むマッチを除外する jp-company-name バリデーター
const COMPANY_EXCLUDE_PATTERNS = /(?:部長|課長|室長|係長|主任|担当|局長|事務|役員|委員|取締役|議員|教授|先生|弁護士|医師|博士|知事|市長|大臣)/;

function validateCompanyName(matched) {
  // 組織内役職語を含む場合は除外
  if (COMPANY_EXCLUDE_PATTERNS.test(matched)) return null;
  return 'COMPANY';
}

// jp-person-name の金額コンテキスト validator（FP-44対応）
function validateJpPersonNameWithCtx(matched, ctx) {
  const r = validateJpName(matched);
  if (!r) return null;
  // 直前に数字・金額単位がある場合は除外（「万円 相当」パターン）
  if (ctx) {
    const before = ctx.text.slice(Math.max(0, ctx.start - 10), ctx.start);
    if (/\d[,，]?\d*[万億兆百千円]\s*$/.test(before)) return null;
  }
  return { label: r, confidence: 0.9 };
}

const KATAKANA_COMMON = /^(?:アプリ|システム|サービス|ネットワーク|データ|プラン|コース|センター|タワー|ビル|ホール|スタジオ|チーム|グループ|ブランド|イベント|メッセ|プロジェクト|エンジン|モデル|フレーム|ドライバ|ドライブ|テスト|サンプル|ダミー|クラウド|ポータル)$/;

function validateKatakanaName(matched) {
  const parts = matched.trim().split(/[ \t　]+/);
  if (parts.some(p => KATAKANA_COMMON.test(p))) return null;
  return 'PERSON';
}

// 中黒区切りで人名ではない語の末尾パターン
const NAKAGURO_NON_NAME_ENDS = /(?:事項|関係|情報|業務|管理|制度|処理|対応|設定|確認|報告|学会|研究|委員|工事|一式|担当|方針|規程|手順|基準|種別|番号|分類|内訳|附則|通達|その他|等|他)$/;

function validateNakaguro(matched) {
  // 一般語や機関名の可能性があるパターンを除外
  const parts = matched.split('・');
  // 地名接尾辞を含む場合は除外
  if (parts.some(p => GEO_SUFFIXES.test(p))) return null;
  // NON_NAME_WORDS に含まれる場合は除外
  if (parts.some(p => NON_NAME_WORDS.has(p))) return null;
  // 業務・事項・関係等の概念語で終わる場合は除外
  if (parts.some(p => NAKAGURO_NON_NAME_ENDS.test(p))) return null;
  // 3文字以上の各パートが概念語的な場合は除外（人名は通常1-2文字の固有パート）
  const longConceptParts = parts.filter(p => p.length >= 3 && NON_NAME_ENDINGS.test(p));
  if (longConceptParts.length > 0) return null;
  return 'PERSON';
}

// jp-label-name: 部門名・役職名を除外
function validateLabelName(matched) {
  // 「広報部」「営業課」等の部門名は除外
  if (/[部課室係局庁院]$/.test(matched)) return null;
  // 「株式会社」等の法人格語は除外
  if (LEGAL_ENTITY_WORDS.test(matched)) return null;
  if (NON_NAME_WORDS.has(matched)) return null;
  if (matched.length < 2) return null;
  return 'PERSON';
}

const VALIDATORS = {
  'credit-card': (m) => luhnCheck(m) ? { label: 'CARD', confidence: 1.0 } : null,
  'my-number': (m) => { const r = validateMyNumber(m); return r ? { label: r, confidence: 1.0 } : null; },
  'jp-person-name': (m, ctx) => validateJpPersonNameWithCtx(m, ctx),
  'jp-person-name-nospace': (m, ctx) => { const r = validateJpNameNospace(m, ctx); return r ? { label: r, confidence: 0.7 } : null; },
  'jp-person-name-list': (m) => { const r = validateJpNameList(m); return r ? { label: r, confidence: 0.5 } : null; },
  'jp-person-name-honorific': (m) => { const r = validateHonorific(m); return r ? { label: r, confidence: 0.8 } : null; },
  'basic-pension': (m, ctx) => contextContains(ctx, ['年金', '基礎年金番号']) ? { label: 'PENSION', confidence: 0.7 } : null,
  'driver-license': (m, ctx) => contextContains(ctx, ['免許', '免許証番号', '運転免許']) ? { label: 'LICENSE', confidence: 0.5 } : null,
  'iban': (m) => validateIBAN(m) ? { label: 'IBAN', confidence: 1.0 } : null,
  'jumin-code': (m, ctx) => contextContains(ctx, ['住民票コード', '住民票']) ? { label: 'JUMINCODE', confidence: 0.5 } : null,
  'jp-company-name': (m) => { const r = validateCompanyName(m); return r ? { label: r, confidence: 0.8 } : null; },
  'jp-katakana-name': (m) => { const r = validateKatakanaName(m); return r ? { label: r, confidence: 0.7 } : null; },
  'jp-name-nakaguro': (m) => { const r = validateNakaguro(m); return r ? { label: r, confidence: 0.7 } : null; },
  'jp-label-name': (m) => { const r = validateLabelName(m); return r ? { label: r, confidence: 0.9 } : null; },
};

export function loadPatterns() {
  const compiled = [];

  const pubPath = join(NEKO_NOT_YOSHI_DIR, 'ngwords.public.json');
  if (existsSync(pubPath)) {
    const pub = JSON.parse(readFileSync(pubPath, 'utf8'));
    for (const p of pub.patterns || []) {
      try { compiled.push(compileBasePattern(p)); } catch { /* skip */ }
    }
  } else {
    for (const p of BUILTIN_PATTERNS) {
      try { compiled.push(compileBasePattern(p)); } catch { /* skip */ }
    }
  }

  const privPath = join(NEKO_NOT_YOSHI_DIR, 'ngwords.private.json');
  if (existsSync(privPath)) {
    const priv = JSON.parse(readFileSync(privPath, 'utf8'));
    for (const w of priv.words || []) {
      if (!w.value || w.value.startsWith('<')) continue;
      const escaped = w.value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const isAscii = /^[\x00-\x7F]+$/.test(w.value);
      const pattern = isAscii ? `\\b${escaped}\\b` : escaped;
      compiled.push({
        id: `private:${w.value.slice(0, 8)}`,
        category: w.category || 'customer',
        regex: new RegExp(pattern, 'g'),
        maskPrefix: w.category === 'customer' ? 'CUSTOMER' : 'NAME',
        isPrivateWord: true,
      });
    }
  }

  const businessEnabled = process.env.PII_MASK_BUSINESS === '1';

  for (const p of EXTRA_PATTERNS) {
    if (p.category === 'business' && !businessEnabled) continue;
    try {
      compiled.push({
        id: p.id,
        category: p.category,
        regex: new RegExp(p.regex, 'g'),
        maskPrefix: p.maskPrefix,
        validator: VALIDATORS[p.id] || null,
        ...(p.defaultConfidence != null && { defaultConfidence: p.defaultConfidence }),
      });
    } catch { /* skip */ }
  }

  return compiled;
}
