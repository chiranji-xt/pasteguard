/* Paste Guard: small checks that turn "looks like a secret" into "is probably a secret".
 *
 * Plain script (no imports) so it can be a browser content script and also `require`d by the tests.
 */
(function (global) {
  'use strict';

  const PG = (global.PasteGuard = global.PasteGuard || {});

  // --- checksums -----------------------------------------------------------------------------

  /** Luhn check used by payment cards. `digits` is a string of digits only. */
  function luhn(digits) {
    if (!/^\d+$/.test(digits)) return false;
    let sum = 0;
    let double = false;
    for (let i = digits.length - 1; i >= 0; i--) {
      let n = digits.charCodeAt(i) - 48;
      if (double) {
        n *= 2;
        if (n > 9) n -= 9;
      }
      sum += n;
      double = !double;
    }
    return sum % 10 === 0;
  }

  const VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
  ];
  const VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
  ];
  const VERHOEFF_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9];

  /** Verhoeff check used by Aadhaar numbers. `digits` includes the check digit. */
  function verhoeff(digits) {
    if (!/^\d+$/.test(digits)) return false;
    let c = 0;
    const reversed = digits.split('').reverse();
    for (let i = 0; i < reversed.length; i++) {
      c = VERHOEFF_D[c][VERHOEFF_P[i % 8][reversed[i].charCodeAt(0) - 48]];
    }
    return c === 0;
  }

  /** The check digit to append to `digits` so the whole string passes `verhoeff`. For tests. */
  function verhoeffCheckDigit(digits) {
    let c = 0;
    const reversed = digits.split('').reverse();
    for (let i = 0; i < reversed.length; i++) {
      c = VERHOEFF_D[c][VERHOEFF_P[(i + 1) % 8][reversed[i].charCodeAt(0) - 48]];
    }
    return String(VERHOEFF_INV[c]);
  }

  /** ISO 13616 mod-97 check. `iban` may contain spaces. */
  function ibanValid(iban) {
    const s = iban.replace(/\s+/g, '').toUpperCase();
    if (!/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(s)) return false;
    const rearranged = s.slice(4) + s.slice(0, 4);
    let remainder = 0;
    for (let i = 0; i < rearranged.length; i++) {
      const ch = rearranged.charCodeAt(i);
      const value = ch >= 65 ? String(ch - 55) : String(ch - 48);
      for (let j = 0; j < value.length; j++) {
        remainder = (remainder * 10 + (value.charCodeAt(j) - 48)) % 97;
      }
    }
    return remainder === 1;
  }

  // --- how random-looking a string is ---------------------------------------------------------

  /** Shannon entropy in bits per character. */
  function shannonEntropy(str) {
    if (!str) return 0;
    const counts = Object.create(null);
    for (let i = 0; i < str.length; i++) counts[str[i]] = (counts[str[i]] || 0) + 1;
    let entropy = 0;
    const length = str.length;
    for (const ch in counts) {
      const p = counts[ch] / length;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  }

  /** True for strings with too little variety to be a real key: "xxxxxxxx", "aaaa1111", "0000000000". */
  function isRepetitive(str) {
    if (str.length < 8) return false;
    if (/(.)\1{7,}/.test(str)) return true;
    const unique = new Set(str).size;
    return unique < Math.max(5, Math.floor(str.length / 8));
  }

  // --- placeholders and code references (the main source of false positives) --------------------

  const PLACEHOLDER_WORDS = new RegExp(
    '^(?:' +
      [
        'example', 'sample', 'dummy', 'placeholder', 'changeme', 'change[-_ ]?me', 'replace[-_ ]?me',
        'insert[-_ ]?here', 'todo', 'tbd', 'fixme', 'redacted', 'null', 'none', 'nil', 'undefined',
        'true', 'false', 'string', 'text', 'password', 'passwd', 'passw0rd', 'secret', 'token',
        'apikey', 'api[-_ ]?key', 'test', 'testing', 'foo', 'bar', 'baz', 'admin', 'user', 'username',
        'email', 'hunter2', 'letmein', 'qwerty\\w*', 'abc123\\w*', '12345\\d*', 'secretkey',
        'my[-_ ]?secret', 'my[-_ ]?password', 'mypassword\\d*', 'mysecret\\d*', 'not[-_ ]?set',
        'unset', 'empty', 'default', 'xxx+', 'x{3,}', 'n/a', 'pass', 'pwd', 'pw', 'key', 'bearer',
        '(?:test|demo|temp|tmp|sample|dummy|foo|bar|guest|root|pass|passwd|password)\\d{0,4}',
      ].join('|') +
      ')$',
    'i'
  );

  /** True if a value is obviously a stand-in ("<token>", "${API_KEY}", "your-api-key", "********"). */
  function isPlaceholder(value) {
    const v = value.trim();
    if (!v) return true;
    if (/^[*xX•·.#_\-~=]+$/.test(v)) return true; // masking characters
    if (/^<[^>]*>$/.test(v) || /^\[[^\]]*\]$/.test(v)) return true; // <token>, [token]
    // Variable references. Prefix tests, because a value pattern may stop before the closing brace: "${DB_PASS".
    if (/^\$\{/.test(v) || /^\{\{/.test(v) || /^\$\(/.test(v)) return true;
    if (/^%[sd]$/.test(v) || /^%[A-Za-z_]+%$/.test(v) || /^\$[A-Za-z_][A-Za-z0-9_]*$/.test(v)) return true;
    if (/^(?:your|my|the|an?)[-_. ]?(?:[a-z]+[-_. ]?){0,3}(?:key|token|secret|password|pass|pwd|id)\b/i.test(v)) return true;
    if (/(?:^|[-_])(?:here|goes[-_]here|placeholder|example|redacted)(?:$|[-_])/i.test(v)) return true;
    if (/\[REDACTED[^\]]*\]/i.test(v)) return true;
    if (/example/i.test(v)) return true; // AKIAIOSFODNN7EXAMPLE and friends; a real random key never spells it out
    return PLACEHOLDER_WORDS.test(v);
  }

  /**
   * True for values that are a reference to a secret rather than the secret:
   * process.env.KEY, os.environ["KEY"], config.get(...), getPassword(), self.token, a plain variable name.
   */
  function looksLikeCodeReference(value) {
    const v = value.trim();
    if (/^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+/.test(v)) return true; // a.b.c...
    if (/^[A-Za-z_$][\w$]*\s*[([]/.test(v)) return true; // fn( or arr[
    if (/^[@$&*][A-Za-z_]/.test(v) || /^(?:new|await|async|return|lambda|this|self)\b/.test(v)) return true;
    if (/^[A-Za-z_]+$/.test(v) && v.length < 40) return true; // a bare word or variable: user_password
    if (/^[a-z]+(?:_[a-z]+)+$/.test(v)) return true; // snake_case identifier
    if (/^[a-z]+(?:[A-Z][a-z]*)+$/.test(v) && !/\d/.test(v)) return true; // camelCase identifier
    if (/^(?:Optional|List|Dict|Set|Tuple|Union|Array|Promise|Record|Partial)\b/.test(v)) return true;
    return false;
  }

  /** True if a candidate JWT has a JSON header with an "alg" claim (filters out random dotted strings). */
  function jwtLooksValid(token) {
    const parts = token.split('.');
    if (parts.length < 2) return false;
    try {
      const b64 = parts[0].replace(/-/g, '+').replace(/_/g, '/');
      const padded = b64 + '==='.slice((b64.length + 3) % 4);
      const json = typeof atob === 'function' ? atob(padded) : Buffer.from(padded, 'base64').toString('binary');
      const header = JSON.parse(json);
      return !!header && typeof header === 'object' && ('alg' in header || 'typ' in header);
    } catch (e) {
      return false;
    }
  }

  const KNOWN_CARD_PREFIXES = [
    /^4\d{12}(?:\d{3}(?:\d{3})?)?$/, // Visa 13, 16, 19
    /^(?:5[1-5]\d{2}|2(?:2[2-9]\d|[3-6]\d{2}|7[01]\d|720))\d{12}$/, // Mastercard
    /^3[47]\d{13}$/, // American Express
    /^(?:6011|65\d{2}|64[4-9]\d)\d{12}(?:\d{3})?$/, // Discover
    /^35(?:2[89]|[3-8]\d)\d{12}(?:\d{3})?$/, // JCB
    /^3(?:0[0-5]|[68]\d)\d{11}$/, // Diners Club
    /^(?:60|65|81|82|508)\d{13,17}$/, // RuPay
    /^62\d{14,17}$/, // UnionPay
  ];

  /** Public test numbers from payment providers' documentation. Pasting these is harmless, so they are not flagged. */
  const KNOWN_TEST_CARDS = new Set([
    '4111111111111111', '4242424242424242', '4012888888881881', '4000056655665556', '4000000000000002',
    '5555555555554444', '5105105105105100', '5200828282828210', '2223003122003222', '378282246310005',
    '371449635398431', '378734493671000', '6011111111111117', '6011000990139424', '3530111333300000',
    '3566002020360505', '30569309025904', '38520000023237', '6200000000000005', '4000000000000069',
  ]);

  /** The Luhn check digit to append to `body` so the whole number passes `luhn`. For tests. */
  function luhnCheckDigit(body) {
    for (let d = 0; d < 10; d++) if (luhn(body + d)) return String(d);
    return '0';
  }

  /** True if `digits` is a plausible, real payment card number: right issuer, right length, passes Luhn. */
  function cardNumberValid(digits) {
    if (digits.length < 13 || digits.length > 19) return false;
    if (KNOWN_TEST_CARDS.has(digits)) return false;
    if (isRepetitive(digits) || /^(\d)\1+$/.test(digits)) return false;
    if (!KNOWN_CARD_PREFIXES.some((re) => re.test(digits))) return false;
    return luhn(digits);
  }

  /** Domains reserved for documentation (RFC 2606): addresses at these are never real people. */
  function isExampleDomain(domain) {
    return /(?:^|\.)(?:example\.(?:com|org|net|edu)|test|invalid|localhost|example)$/i.test(domain);
  }

  PG.validators = {
    luhn,
    verhoeff,
    verhoeffCheckDigit,
    ibanValid,
    shannonEntropy,
    isRepetitive,
    isPlaceholder,
    looksLikeCodeReference,
    jwtLooksValid,
    cardNumberValid,
    luhnCheckDigit,
    isExampleDomain,
  };

  if (typeof module !== 'undefined' && module.exports) module.exports = PG.validators;
})(typeof globalThis !== 'undefined' ? globalThis : this);
