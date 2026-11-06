/* Test samples for every rule.
 *
 * IMPORTANT: no sample is written out as a literal secret. Each is built at run time from a fixed prefix
 * plus a seeded random body. Two reasons: GitHub's push protection refuses commits that contain strings
 * shaped like real keys, and this keeps the repository free of anything a scanner would flag.
 *
 * A rule is "covered" when it has at least one positive (must be found) and one negative (must not be
 * found by that rule). test/rules.test.js fails for any rule without both.
 */
const { luhnCheckDigit, verhoeffCheckDigit } = require('../src/engine/validators.js');

function prng(seed) {
  let a = seed >>> 0;
  return () => {
    a += 0x6d2b79f5;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const ALPHABET = {
  alnum: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
  b64url: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_',
  b64: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
  hex: '0123456789abcdef',
  b32: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
  digits: '0123456789',
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
};

/** A deterministic random string. The same (length, alphabet, seed) always gives the same text. */
function rand(length, alphabet, seed) {
  const next = prng(seed);
  const chars = ALPHABET[alphabet] || alphabet;
  let out = '';
  for (let i = 0; i < length; i++) out += chars[Math.floor(next() * chars.length)];
  return out;
}

const b64url = (value) => Buffer.from(value).toString('base64url');
const b64 = (value) => Buffer.from(value).toString('base64');

function jwt(seed) {
  return `${b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))}.${b64url(JSON.stringify({ sub: rand(8, 'digits', seed), name: 'A User' }))}.${rand(43, 'b64url', seed + 1)}`;
}

function card(prefix, length, seed) {
  let body = prefix;
  const next = prng(seed);
  while (body.length < length - 1) body += Math.floor(next() * 10);
  return body + luhnCheckDigit(body);
}

function aadhaar(seed) {
  const next = prng(seed);
  let body = String(2 + Math.floor(next() * 8));
  while (body.length < 11) body += Math.floor(next() * 10);
  return body + verhoeffCheckDigit(body);
}

const group4 = (digits) => digits.replace(/(\d{4})(?=\d)/g, '$1 ');

function pem(label, seed, withEnd = true) {
  const lines = [];
  for (let i = 0; i < 5; i++) lines.push(rand(64, 'b64', seed + i));
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n` + (withEnd ? `-----END ${label}-----` : '');
}

/** ruleId -> { positive: [() => text], negative: [text] } */
const fixtures = {
  'private-key': {
    positive: [
      () => pem('RSA ' + 'PRIVATE KEY', 1),
      () => pem('OPENSSH ' + 'PRIVATE KEY', 2),
      () => pem('PRIVATE KEY', 3),
      () => pem('EC ' + 'PRIVATE KEY', 4, false), // cut off before the end marker
      () => 'here is my key:\n' + pem('ENCRYPTED ' + 'PRIVATE KEY', 5) + '\nthanks',
    ],
    negative: ['-----BEGIN ' + 'PRIVATE KEY-----\nXXXX\nXXXX\n-----END ' + 'PRIVATE KEY-----', '-----BEGIN ' + 'RSA PRIVATE KEY-----','-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----', 'Never share your private key with anyone.', '-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----'],
  },
  'anthropic-api-key': {
    positive: [() => 'sk-' + 'ant-api03-' + rand(93, 'b64url', 10), () => 'ANTHROPIC_API_KEY=' + 'sk-' + 'ant-admin01-' + rand(90, 'b64url', 11)],
    negative: ['sk-ant-api03-xxxxxxxx', 'export ANTHROPIC_API_KEY=sk-ant-...'],
  },
  'openrouter-api-key': {
    positive: [() => 'sk-' + 'or-v1-' + rand(64, 'hex', 12)],
    negative: ['sk-or-v1-abc', 'sk-or-v1-' + 'a'.repeat(64)],
  },
  'openai-api-key': {
    positive: [() => 'sk-' + rand(48, 'alnum', 13), () => 'sk-' + 'proj-' + rand(100, 'b64url', 14), () => 'my key is ' + 'sk-' + rand(32, 'hex', 15) + ' ok?', () => 'sk-' + 'svcacct-' + rand(80, 'b64url', 16)],
    negative: ['sk-' + 'x'.repeat(40), 'sk-short', 'sk-learn-is-a-python-library-for-machine-learning-2024', '.sk-cube-grid-animation-delay-1 { color: red }', 'sk-' + '0'.repeat(48)],
  },
  'google-api-key': {
    positive: [() => 'AIza' + rand(35, 'b64url', 20), () => 'key=' + 'AIza' + rand(35, 'b64url', 21) + '&alt=json'],
    negative: ['AIza-short', 'AIzaSy' + 'x'.repeat(10)],
  },
  'google-oauth-token': {
    positive: [() => 'ya29.' + rand(80, 'b64url', 22)],
    negative: ['ya29.short', 'ya29'],
  },
  'aws-access-key-id': {
    positive: [() => 'AKIA' + rand(16, 'b32', 23), () => 'ASIA' + rand(16, 'b32', 24)],
    negative: ['AKIA' + 'X'.repeat(16), 'AKIAIOSFODNN7EXAMPLE', 'AKIA-too-short'],
  },
  'aws-secret-key': {
    positive: [() => 'aws_secret_access_key = ' + rand(40, 'b64', 25), () => 'AWS_SECRET_ACCESS_KEY="' + rand(40, 'b64', 26) + '"'],
    negative: ['aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', 'aws_secret_access_key = <your secret>', 'aws_secret_access_key = ' + 'x'.repeat(40)],
  },
  'github-token': {
    positive: [() => 'ghp_' + rand(36, 'alnum', 27), () => 'gho_' + rand(36, 'alnum', 28), () => 'token ' + 'ghs_' + rand(40, 'alnum', 29)],
    negative: ['ghp_' + 'x'.repeat(36), 'ghp_short', 'github.com/user/repo'],
  },
  'github-fine-grained-token': {
    positive: [() => 'github_pat_' + rand(82, 'alnum', 30)],
    negative: ['github_pat_short', 'github_pat_' + 'A'.repeat(40)],
  },
  'gitlab-token': {
    positive: [() => 'glpat-' + rand(20, 'b64url', 31)],
    negative: ['glpat-short', 'glpat-' + 'x'.repeat(20)],
  },
  'slack-token': {
    positive: [() => 'xox' + 'b-' + rand(12, 'digits', 32) + '-' + rand(24, 'alnum', 33), () => 'xox' + 'p-' + rand(40, 'alnum', 34)],
    negative: ['xoxb-short', 'xoxb-' + 'x'.repeat(24)],
  },
  'slack-webhook': {
    positive: [() => 'https://hooks.slack.com/services/T' + rand(8, 'upper', 35) + '/B' + rand(8, 'upper', 36) + '/' + rand(24, 'alnum', 37)],
    negative: ['https://hooks.slack.com/services/', 'https://slack.com/help'],
  },
  'stripe-live-key': {
    positive: [() => 'sk_' + 'live_' + rand(24, 'alnum', 38), () => 'rk_' + 'live_' + rand(30, 'alnum', 39)],
    negative: ['sk_live_xxxxxxxxxxxxxxxxxxxxxxxx', 'sk_live_short'],
  },
  'stripe-test-key': {
    positive: [() => 'sk_' + 'test_' + rand(24, 'alnum', 40)],
    negative: ['sk_test_xxxxxxxxxxxxxxxxxxxxxxxx', 'sk_test_short'],
  },
  'sendgrid-api-key': {
    positive: [() => 'SG.' + rand(22, 'b64url', 41) + '.' + rand(43, 'b64url', 42)],
    negative: ['SG.short.short', 'SG.' + 'x'.repeat(22) + '.' + 'x'.repeat(43)],
  },
  'npm-token': {
    positive: [() => 'npm_' + rand(36, 'alnum', 43)],
    negative: ['npm_short', 'npm_' + 'x'.repeat(36)],
  },
  'pypi-token': {
    positive: [() => 'pypi-AgEIcHlwaS5vcmc' + rand(60, 'b64url', 44)],
    negative: ['pypi-short', 'pypi-AgEIcHlwaS5vcmc' + 'x'.repeat(60)],
  },
  'huggingface-token': {
    positive: [() => 'hf_' + rand(34, 'alnum', 45)],
    negative: ['hf_short', 'hf_' + 'x'.repeat(34)],
  },
  'groq-api-key': {
    positive: [() => 'gsk_' + rand(52, 'alnum', 46)],
    negative: ['gsk_short', 'gsk_' + 'x'.repeat(52)],
  },
  'replicate-token': {
    positive: [() => 'r8_' + rand(37, 'alnum', 47)],
    negative: ['r8_short', 'r8_' + 'x'.repeat(37)],
  },
  'perplexity-api-key': {
    positive: [() => 'pplx-' + rand(48, 'alnum', 48)],
    negative: ['pplx-short', 'pplx-' + 'x'.repeat(48)],
  },
  'xai-api-key': {
    positive: [() => 'xai-' + rand(80, 'alnum', 49)],
    negative: ['xai-short', 'xai-' + 'x'.repeat(80)],
  },
  'telegram-bot-token': {
    positive: [() => rand(10, 'digits', 50) + ':' + rand(35, 'b64url', 51)],
    negative: ['12345678:short', '1730000000:' + 'a'.repeat(35), 'time 12:34:56'],
  },
  'discord-bot-token': {
    positive: [() => 'M' + rand(24, 'b64url', 52) + '.' + rand(6, 'b64url', 53) + '.' + rand(30, 'b64url', 54)],
    negative: ['MyApplicationConfigurationManager.getDefault.SomethingVeryLongInThirdSegmentHere', 'M.short.short'],
  },
  'shopify-token': {
    positive: [() => 'shp' + 'at_' + rand(32, 'hex', 55)],
    negative: ['shpat_short', 'shpat_' + '0'.repeat(32)],
  },
  'digitalocean-token': {
    positive: [() => 'dop_' + 'v1_' + rand(64, 'hex', 56)],
    negative: ['dop_v1_short', 'dop_v1_' + '0'.repeat(64)],
  },
  'databricks-token': {
    positive: [() => 'dapi' + rand(32, 'hex', 57)],
    negative: ['dapi-short', 'dapi' + '0'.repeat(32)],
  },
  'square-token': {
    positive: [() => 'sq0atp-' + rand(22, 'b64url', 58)],
    negative: ['sq0atp-short', 'sq0atp-' + 'x'.repeat(22)],
  },
  'mailgun-key': {
    positive: [() => 'key-' + rand(32, 'hex', 59)],
    negative: ['key-short', 'key-' + '0'.repeat(32)],
  },
  'twilio-api-key': {
    positive: [() => 'SK' + rand(32, 'hex', 60)],
    negative: ['SKshort', 'SK' + '0'.repeat(32)],
  },
  'azure-storage-key': {
    positive: [() => 'DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=' + rand(86, 'b64', 61) + '=='],
    negative: ['AccountKey=short', 'AccountKey=<your key>'],
  },
  jwt: {
    positive: [() => jwt(70), () => 'token: ' + jwt(71) + ' (expired)'],
    negative: ['eyJub3Rqc29u.eyJub3Rqc29u.notajwtnotajwt', 'plain.dotted.string.here', 'eyJ'],
  },
  'bearer-token': {
    positive: [() => 'Authorization: Bearer ' + rand(40, 'b64url', 72), () => `curl -H "Authorization: Bearer ${rand(36, 'alnum', 73)}" https://api.test/v1`, () => "headers = {'Authorization': 'token " + rand(30, 'alnum', 74) + "'}"],
    negative: ['Authorization: Bearer <token>', 'Authorization: Bearer ${TOKEN}', 'Authorization: Bearer YOUR_API_KEY_HERE', 'Authorization: Bearer token', 'Authorization: Bearer ' + 'x'.repeat(30)],
  },
  'basic-auth-header': {
    positive: [() => 'Authorization: Basic ' + b64('deploy:' + rand(14, 'alnum', 75))],
    negative: ['Authorization: Basic ' + b64('user:pass'), 'Authorization: Basic <credentials>', 'Authorization: Basic ' + b64('justonepart')],
  },
  'url-credentials': {
    positive: [() => 'postgres://app_user:' + rand(18, 'alnum', 76) + '@db.internal:5432/app', () => 'mongodb+srv://admin:' + rand(16, 'alnum', 77) + '@cluster0.abcde.mongodb.net/test', () => 'DATABASE_URL=mysql://root:' + rand(12, 'b64url', 78) + '@10.0.0.5/shop'],
    negative: ['https://user:password@example.com/', 'postgres://user:${DB_PASS}@host/db', 'https://github.com/user/repo', 'redis://:@localhost:6379', 'postgres://user:<password>@host/db', 'ftp://anonymous:xxxxxxxx@host/', 'http://evil:thing@example.com/', 'https://alice:s3cretvalue1@docs.example.org/path'],
  },
  'password-assignment': {
    positive: [() => 'DB_PASSWORD=' + rand(12, 'alnum', 80) + '#9', () => 'password: "' + rand(10, 'alnum', 81) + '!7"', () => '"password": "' + rand(14, 'alnum', 82) + '$"', () => 'admin_passwd = ' + rand(12, 'alnum', 83) + '&1'],
    negative: ['password = input("Password: ")', 'password: string', 'password=os.environ["DB_PASS"]', "password = request.form['password']", 'new_password = confirm_password', 'password: ********', 'password: <your-password>', 'PASSWORD=${DB_PASSWORD}', 'password = process.env.PASSWORD', 'password: changeme', '"password": "string"', 'password=password', "'pwd': 'library/pwd.html#module-pwd'", 'password_field = "passwd"', 'Given a username and password.\n\n    :param x: the thing',"const passwordPrompt = 'npm password: ';", 'passwd = "test123"', 'password = "demo"', 'password_file: creds.json', 'password_reset_url = "account/reset"'],
  },
  'secret-assignment': {
    positive: [() => 'SECRET_KEY=django-insecure-' + rand(40, 'b64url', 84), () => 'export API_TOKEN="' + rand(32, 'alnum', 85) + '"', () => 'client_secret: ' + rand(36, 'b64url', 86), () => '{"access_key": "' + rand(28, 'alnum', 87) + '"}'],
    negative: ['token: process.env.GITHUB_TOKEN', 'api_key = os.getenv("KEY")', 'TOKEN=<your-token>', 'secret: ${{ secrets.NPM_TOKEN }}', 'api_key: Optional[str] = None', 'token_type: "bearer"', 'secret_name: my-app-secret', 'max_tokens: 100000', 'API_KEY=your-api-key-here', 'api_key = config.api_key', 'secret = "x"', "token = (tokenize.NAME, 'Hello')", "expected_tokens = [tokenize.TokenInfo(3, 'x')]", 'token: https://example.com/oauth/token', "token_type = 'quoted-string'", "token_type = 'bare-quoted-string'", 'secret_name: production_database_credentials', 'key_path = "keys/service-account-prod.json"', 'description: "the secret token used for signing requests"'],
  },
  'cli-secret-flag': {
    positive: [() => 'mytool --password=' + rand(14, 'alnum', 88) + '#1', () => 'mytool login --token ' + rand(30, 'alnum', 89), () => "mytool --api-key '" + rand(24, 'b64url', 90) + "'"],
    negative: ['mytool --password $PASS', 'mytool --token=<token>', 'mytool --password-file ./pw.txt', 'mytool --secret ${SECRET}'],
  },
  'credit-card': {
    positive: [() => 'card ' + card('4539', 16, 100), () => 'card ' + group4(card('5425', 16, 101)), () => 'card ' + group4(card('4539', 16, 102)).replace(/ /g, '-'), () => 'amex ' + card('3714', 15, 103), () => 'pay with ' + card('6011', 16, 104) + ' today'],
    negative: ['4111 1111 1111 1111', '4242 4242 4242 4242', '5555555555554444', '4539 1488 0343 6468', 'order 1234 5678 9012 3456', 'id 0000000000000000', 'acos 0.99999999999999989 0.0 -> 1.5707963267948966 -0.0', 'x = 3.1415926535897932384626', 'id4539148803436468', '4539148803436468x', '+91 98765 43210', 'timestamp 1730000000000'],
  },
  iban: {
    positive: [() => 'IBAN: GB82 WEST 1234 5698 7654 32', () => 'send to DE89370400440532013000 please'],
    negative: ['GB82 WEST 1234 5698 7654 33', 'GB00 NOPE', 'AB12 CDEF'],
  },
  'us-ssn': {
    positive: [() => 'ssn 412-34-5678', () => 'SSN: 538-21-9034 on file'],
    negative: ['000-12-3456', '666-12-3456', '912-12-3456', '123-00-4567', '123-45-0000', '2024-11-05', '111-11-1111', '1234-56-7890'],
  },
  aadhaar: {
    positive: [() => 'aadhaar ' + group4(aadhaar(110)), () => 'Aadhaar: ' + aadhaar(111), () => 'UID ' + group4(aadhaar(112)).replace(/ /g, '-'), () => 'my aadhar number is ' + aadhaar(113) + ' thanks'],
    negative: ['2345 6789 0123', 'order id ' + aadhaar(114), '1111 1111 1111', 'phone 9876543210', '0123 4567 8901'],
  },
  'india-pan': {
    positive: [() => 'PAN: ABCPD1234E', () => 'my PAN is BNZPM2501F please', () => 'Permanent Account Number AFZPK7190K'],
    negative: ['ABCPD1234E', 'part number XYZPQ9876R', 'PAN: abcde1234f'],
  },
  email: {
    positive: [() => 'contact jane.doe@gmail.com for details', () => 'From: Ravi Kumar <ravi.k+work@company.co.in>'],
    negative: ['user@example.com', 'a@b', 'name@test', 'noatsign.example', '@mention'],
  },
  phone: {
    positive: [() => 'call +91 98765 43210', () => 'tel: +1 (415) 555-0132', () => 'whatsapp +44 7700 900123'],
    negative: ['9876543210', '+1 2', 'version +1.2.3', '+0000000000000'],
  },
  'high-entropy-string': {
    positive: [() => 'blob ' + rand(48, 'b64url', 120), () => rand(40, 'alnum', 121)],
    negative: ['0123456789abcdef0123456789abcdef', 'da39a3ee5e6b4b0d3255bfef95601890afd80709', '550e8400-e29b-41d4-a716-446655440000', 'a'.repeat(40), 'thisisaverylongwordwithoutanydigitsatallinit'],
  },
};

/** Realistic text that must NOT trigger anything at the default settings. The false-positive guard. */
const cleanCorpus = {
  'python reading env vars': 'import os\nAPI_KEY = os.environ["OPENAI_API_KEY"]\npassword = os.getenv("DB_PASSWORD")\ntoken = config.get("token")\nsecret_key = settings.SECRET_KEY\n',
  'js with bearer from variable': 'const token = process.env.TOKEN;\nheaders["Authorization"] = `Bearer ${token}`;\nconst res = await fetch(url, { headers: { Authorization: "Bearer " + accessToken } });\n',
  dockerfile: 'FROM node:20\nARG NPM_TOKEN\nENV PASSWORD=${DB_PASSWORD}\nRUN echo "//registry.npmjs.org/:_authToken=${NPM_TOKEN}" > .npmrc\n',
  'docs with placeholders': 'Set `OPENAI_API_KEY` to your key:\n\nexport OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\nexport ANTHROPIC_API_KEY="sk-ant-..."\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n',
  'dotenv template': 'DATABASE_URL=postgres://user:password@localhost:5432/mydb\nSECRET_KEY=changeme\nAPI_TOKEN=<your-token-here>\nSTRIPE_KEY=sk_test_your_key_here\n',
  'github actions': 'env:\n  NPM_TOKEN: ${{ secrets.NPM_TOKEN }}\n  GH_TOKEN: ${{ github.token }}\n  PASSWORD: ${{ secrets.DB_PASSWORD }}\n',
  'package-lock integrity': '"integrity": "sha512-' + rand(86, 'b64', 200) + '==",\n"resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"\n',
  'git log': 'commit da39a3ee5e6b4b0d3255bfef95601890afd80709\nAuthor: A Dev\nDate: Mon Nov 3 2026\n    fix: tokens expire after 3600 seconds\n',
  'uuids and ids': 'request_id: 550e8400-e29b-41d4-a716-446655440000\ntrace=4bf92f3577b34da6a3ce929d0e0e4736\nsession 123e4567-e89b-12d3-a456-426614174000\n',
  'css classes': '.sk-cube-grid-animation-delay-1 { animation: sk-cubeGridScaleDelay 1.3s infinite; }\n.token-comment { color: slategray; }\n',
  'openapi schema': '{"password": {"type": "string", "format": "password"}, "token": {"type": "string"}, "api_key": {"type": "string"}}\n',
  'typed code': 'password: str\ntoken: Optional[str] = None\napi_key: string;\nconst secret: string = "";\ndef login(password: str, token: str) -> bool: ...\n',
  'prose about secrets': 'Never commit a password or API key. Rotate your token every 90 days. The secret is stored in a vault, not in code. Max tokens: 4096.\n',
  'test card numbers': 'Use 4242 4242 4242 4242 or 4111 1111 1111 1111 with any future date. Amex: 3782 822463 10005.\n',
  'numbers and dates': 'Total 1,234,567.89 on 2024-11-05, ref 20241105-0042, order #482915, timestamp 1730000000000, phone 9876543210.\n',
  'data uri': 'src="data:image/png;base64,' + rand(300, 'b64', 201) + '"\n',
  'urls': 'See https://docs.example.com/guide?page=2&token_type=bearer and https://github.com/owner/repo/blob/main/src/auth.py\n',
  'markdown install': '```sh\npip install openai\nexport OPENAI_API_KEY="your-api-key"\ncurl -H "Authorization: Bearer $OPENAI_API_KEY" https://api.openai.com/v1/models\n```\n',
  'yaml config': 'database:\n  host: localhost\n  password: ${DB_PASSWORD}\n  username: admin\nauth:\n  secret: !vault |\n    $ANSIBLE_VAULT;1.1;AES256\n',
  'error log': 'ERROR 2026-11-05 12:00:01 auth failed for user bob (invalid token) request=abc-123\nWARN retrying in 5s, attempt 3/10\n',
  'sql': "SELECT * FROM users WHERE password_hash = crypt($1, password_hash) AND token IS NOT NULL;\nINSERT INTO sessions (token, user_id) VALUES ($1, $2);\n",
};

/** Realistic text that must trigger, with the rule ids expected. */
function dirtyCorpus() {
  return {
    dotenv: {
      text: `OPENAI_API_KEY=${'sk-' + 'proj-' + rand(100, 'b64url', 300)}\nDATABASE_URL=postgres://app:${rand(16, 'alnum', 301)}@db.internal/app\nSTRIPE_SECRET=${'sk_' + 'live_' + rand(24, 'alnum', 302)}\nDEBUG=true\nPORT=8080\n`,
      expect: ['openai-api-key', 'url-credentials', 'stripe-live-key'],
    },
    curl: {
      text: `curl https://api.test/v1/items -H "Authorization: Bearer ${rand(40, 'b64url', 303)}" -H "X-Api-Key: ok"`,
      expect: ['bearer-token'],
    },
    'github actions with a real token': {
      text: `env:\n  GITHUB_TOKEN: ${'gh' + 'p_' + rand(36, 'alnum', 304)}\n  NAME: build\n`,
      expect: ['github-token'],
    },
    'pasted stack trace with a key': {
      text: `Traceback (most recent call last):\n  File "app.py", line 3, in <module>\n    client = Client(api_key="${'sk-' + 'ant-api03-' + rand(93, 'b64url', 305)}")\nValueError: bad request`,
      expect: ['anthropic-api-key'],
    },
    'private key in a message': {
      text: `Can you help me convert this?\n${pem('RSA ' + 'PRIVATE KEY', 306)}\nIt is for the staging server.`,
      expect: ['private-key'],
    },
    'person with documents': {
      text: `Name: A Kumar\nAadhaar: ${group4(aadhaar(307))}\nPAN: ABCPD1234E\nCard: ${group4(card('4539', 16, 308))}`,
      expect: ['aadhaar', 'india-pan', 'credit-card'],
    },
  };
}

module.exports = { fixtures, cleanCorpus, dirtyCorpus, rand, jwt, card, aadhaar, group4, pem, b64, b64url, ALPHABET };
