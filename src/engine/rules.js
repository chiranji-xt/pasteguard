/* Paste Guard: the detection rules.
 *
 * Each rule is plain data, so adding one is easy:
 *   id        unique, kebab-case. Also names the placeholder: "openai-api-key" -> [REDACTED:OPENAI_API_KEY]
 *   label     what the person sees ("OpenAI-style API key")
 *   category  apiKey | privateKey | token | credential | financial | government | email | phone | highEntropy
 *   severity  high | medium | low
 *   priority  when two findings overlap the higher one wins, so specific rules beat generic ones
 *   keywords  optional lowercase strings; the rule only runs on text that contains one (a speed-up)
 *   pattern   a RegExp. The detector adds the g and d flags.
 *   group     which capture group is the secret (the rest of the match is left alone). 0 = whole match.
 *             An array means "the first of these groups that matched".
 *   validate  optional (value, ctx) => boolean to cut false positives (checksums, placeholders, entropy)
 *
 * Every rule needs positive and negative examples in test/fixtures.js. The tests enforce that.
 */
(function (global) {
  'use strict';

  const PG = (global.PasteGuard = global.PasteGuard || {});
  const V = PG.validators || require('./validators.js');

  const B = '(?<![A-Za-z0-9_-])'; // not glued to a longer token on the left
  const E = '(?![A-Za-z0-9_-])'; // ...or on the right

  // password, passwd, pwd, passphrase anywhere in the name; or "pass" / "pw" as a whole word of it (DB_PASS, user.pw),
  // never inside another word (bypass, compass).
  const PASSWORD_KEY =
    '(?:[A-Za-z0-9_.\\-]{0,40}(?:password|passwd|pwd|passphrase)[A-Za-z0-9_.\\-]{0,40}|(?:[A-Za-z0-9]{1,20}[_.\\-])?(?:pass|pw)(?:[_.\\-][A-Za-z0-9_.\\-]{0,30})?)';
  const SECRET_KEY =
    '[A-Za-z0-9_.\\-]{0,40}(?:secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|auth[_-]?key|client[_-]?secret|credential|session[_-]?key|encryption[_-]?key|signing[_-]?key|master[_-]?key|app[_-]?key)[A-Za-z0-9_.\\-]{0,40}';
  // key = value, key: value, "key": "value". The value may be quoted or bare.
  // The key and its value share a line: spaces and tabs only between them, never a line break.
  const assignment = (key) =>
    `(?:^|[\\s,;{(\\[])(["']?)(${key})\\1[ \\t]*[:=][ \\t]*(?:"([^"\\n]{6,200})"|'([^'\\n]{6,200})'|([^\\s"'\`,;)}\\]]{6,200}))`;

  /** Provider keys with a fixed prefix: flag unless the body is an obvious stand-in like "xxxxxxxx". */
  const notPlaceholderKey = (value) => !V.isRepetitive(value) && !/x{6,}|\*{3,}|\.{3,}|example/i.test(value);

  const looksLikeUrlOrPath = (v) => /^(?:https?:\/\/|\/|\.{1,2}[\\/]|[A-Za-z]:[\\/])/.test(v);
  // "library/pwd.html#module-pwd", "creds.json": a file or a page anchor, not a secret.
  const looksLikeFileName = (v) => /\.(?:html?|py|txt|md|rst|json|ya?ml|xml|cfg|ini|conf|toml|php|js|css|pem|key|csv)(?:#\S*)?$/i.test(v) || /#module-|#[a-z]+-[a-z]/i.test(v);
  // token_type, secret_name, key_path, password_field...: the name says it describes a secret rather than holds one.
  const DESCRIBES_A_SECRET = /(?:type|name|kind|count|length|len|limit|url|uri|path|file|filename|dir|format|class|cls|endpoint|expiry|expires|expiration|ttl|lifetime|version|label|description|desc|message|msg|status|mode|algorithm|alg|encoding|prefix|suffix|header|field|scheme|style|hint|placeholder|help|text|title|source|provider|env|var|variable|param|option|flag|setting|config|prompt)$/i;
  const keyDescribesASecret = (ctx) => !!ctx.match[2] && DESCRIBES_A_SECRET.test(ctx.match[2]);
  // token = (tokenize.NAME, 'Hello'), tokens = [a, b]: an unquoted value that opens a list or tuple is code.
  const isCodeLiteral = (value, ctx) => ctx.match[5] !== undefined && /^[[({]/.test(value);
  // snake-case or kebab-case words ("quoted-string", "bare_quoted_string") are names, not keys.
  const looksLikeWords = (v) => /^[A-Za-z]+(?:[-_][A-Za-z]+)+$/.test(v);

  function apiKey(id, label, pattern, keywords, extra) {
    return Object.assign(
      { id, label, category: 'apiKey', severity: 'high', priority: 90, keywords, pattern, group: 1, validate: notPlaceholderKey },
      extra || {}
    );
  }

  /**
   * More providers whose keys identify themselves by a distinctive prefix. Formats follow each provider's published
   * format and the public rule sets of established scanners (gitleaks, MIT licensed) as a reference; the patterns are
   * written here. Keys with no prefix at all are left to the "name = value" rules, which already catch
   * CLOUDFLARE_API_TOKEN=..., DATADOG_API_KEY=... and the like.
   * [id, label, pattern (the secret is group 1), keywords, extra options]
   */
  const lowEntropyTail = (prefixLength) => (value) => notPlaceholderKey(value.slice(prefixLength)) && V.shannonEntropy(value.slice(prefixLength)) >= 3.2;
  const HEX = '[a-f0-9]';
  const PROVIDERS = [
    ['onepassword-secret-key', '1Password secret key', `\\b(A3-[A-Z0-9]{6}-(?:[A-Z0-9]{11}|[A-Z0-9]{6}-[A-Z0-9]{5})-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5})\\b`, ['a3-']],
    ['onepassword-service-token', '1Password service account token', `${B}(ops_eyJ[A-Za-z0-9+/]{250,}={0,3})`, ['ops_eyj']],
    ['age-secret-key', 'age encryption secret key', `${B}(AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58})${E}`, ['age-secret-key-1']],
    ['airtable-token', 'Airtable personal access token', `${B}(pat[A-Za-z0-9]{14}\\.${HEX}{64})${E}`, ['pat']],
    ['aws-bedrock-key', 'AWS Bedrock API key', `${B}(ABSK[A-Za-z0-9+/]{109,269}={0,2})`, ['absk']],
    ['alibaba-access-key', 'Alibaba Cloud access key ID', `${B}(LTAI[A-Za-z0-9]{20})${E}`, ['ltai']],
    ['atlassian-token', 'Atlassian API token', `${B}(ATATT3[A-Za-z0-9_=-]{150,})`, ['atatt3']],
    ['bitbucket-app-password', 'Bitbucket app password', `${B}(ATBB[A-Za-z0-9_=.-]{30,})${E}`, ['atbb']],
    ['circleci-token', 'CircleCI personal token', `${B}(CCIPAT_[A-Za-z0-9]{12}_${HEX}{40})${E}`, ['ccipat_']],
    ['clojars-token', 'Clojars deploy token', `${B}(CLOJARS_[a-z0-9]{60})${E}`, ['clojars_']],
    ['cloudflare-origin-ca-key', 'Cloudflare Origin CA key', `${B}(v1\\.0-${HEX}{24}-${HEX}{146})${E}`, ['v1.0-'], { validate: (v) => !/(.)\1{7,}/.test(v) }],
    ['docker-hub-token', 'Docker Hub access token', `${B}(dckr_pat_[A-Za-z0-9_-]{27})${E}`, ['dckr_pat_']],
    ['doppler-token', 'Doppler token', `${B}(dp\\.(?:pt|st|sa|ct)\\.[A-Za-z0-9]{40,44})${E}`, ['dp.']],
    ['dropbox-token', 'Dropbox access token', `${B}(sl\\.[A-Za-z0-9_=-]{130,140})${E}`, ['sl.']],
    ['duffel-token', 'Duffel API token', `${B}(duffel_(?:test|live)_[A-Za-z0-9_=-]{43})${E}`, ['duffel_']],
    ['dynatrace-token', 'Dynatrace API token', `${B}(dt0c01\\.[A-Za-z0-9]{24}\\.[A-Za-z0-9]{64})${E}`, ['dt0c01.']],
    ['easypost-key', 'EasyPost API key', `${B}(EZ[AT]K[A-Za-z0-9]{54})${E}`, ['ezak', 'eztk']],
    ['facebook-token', 'Facebook / Meta access token', `${B}(EAA[MC][A-Za-z0-9]{100,})`, ['eaam', 'eaac']],
    ['figma-token', 'Figma personal access token', `${B}(figd_[A-Za-z0-9_-]{40})${E}`, ['figd_']],
    ['flyio-token', 'Fly.io access token', `${B}(fo1_[A-Za-z0-9_-]{43}|fm1[ar]_[A-Za-z0-9+/]{100,}={0,3}|fm2_[A-Za-z0-9+/]{100,}={0,3})`, ['fo1_', 'fm1', 'fm2_']],
    ['frameio-token', 'Frame.io API token', `${B}(fio-u-[A-Za-z0-9_=-]{64})${E}`, ['fio-u-']],
    ['gitlab-other-token', 'GitLab token', `${B}((?:glcbt|gldt|glffct|glft|glimt|glagent|gloas|glptt|glrt|glsoat)-[A-Za-z0-9_-]{20,70})${E}`, ['glcbt-', 'gldt-', 'glffct-', 'glft-', 'glimt-', 'glagent-', 'gloas-', 'glptt-', 'glrt-', 'glsoat-']],
    ['gitlab-runner-token', 'GitLab runner registration token', `${B}(GR1348941[A-Za-z0-9_-]{20})${E}`, ['gr1348941']],
    ['google-client-secret', 'Google OAuth client secret', `${B}(GOCSPX-[A-Za-z0-9_-]{28})${E}`, ['gocspx-']],
    ['google-refresh-token', 'Google OAuth refresh token', `${B}(1//0[A-Za-z0-9_-]{40,})${E}`, ['1//0']],
    ['firebase-server-key', 'Firebase Cloud Messaging server key', `${B}(AAAA[A-Za-z0-9_-]{7}:APA91b[A-Za-z0-9_-]{134})${E}`, ['apa91b']],
    ['grafana-service-key', 'Grafana API key', `${B}(eyJrIjoi[A-Za-z0-9]{70,400}={0,3})`, ['eyjrijoi']],
    ['grafana-cloud-token', 'Grafana Cloud token', `${B}(glc_[A-Za-z0-9+/]{32,400}={0,3})`, ['glc_']],
    ['grafana-service-account', 'Grafana service account token', `${B}(glsa_[A-Za-z0-9]{32}_${HEX}{8})${E}`, ['glsa_']],
    ['harness-token', 'Harness API key', `${B}((?:pat|sat)\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9]{24}\\.[A-Za-z0-9]{20})${E}`, ['pat.', 'sat.']],
    ['terraform-cloud-token', 'Terraform Cloud API token', `${B}([A-Za-z0-9]{14}\\.atlasv1\\.[A-Za-z0-9_=-]{60,70})${E}`, ['.atlasv1.']],
    ['vault-token', 'HashiCorp Vault token', `${B}(hv[sb]\\.[A-Za-z0-9_-]{90,300})${E}`, ['hvs.', 'hvb.']],
    ['heroku-key', 'Heroku API key', `${B}(HRKU-AA[A-Za-z0-9_-]{58})${E}`, ['hrku-']],
    ['hubspot-token', 'HubSpot private app token', `${B}(pat-(?:na|eu)\\d-${HEX}{8}-${HEX}{4}-${HEX}{4}-${HEX}{4}-${HEX}{12})${E}`, ['pat-na', 'pat-eu']],
    ['huggingface-org-token', 'Hugging Face organization token', `${B}(api_org_[A-Za-z]{34})${E}`, ['api_org_']],
    ['infracost-key', 'Infracost API key', `${B}(ico-[A-Za-z0-9]{32})${E}`, ['ico-']],
    ['mailchimp-key', 'Mailchimp API key', `(?<![A-Za-z0-9-])(${HEX}{32}-us\\d{1,2})${E}`, ['-us']],
    ['mapbox-secret-token', 'Mapbox secret token', `${B}(sk\\.eyJ[A-Za-z0-9_-]{20,}\\.[A-Za-z0-9_-]{20,})${E}`, ['sk.eyj']],
    ['teams-webhook', 'Microsoft Teams webhook URL', `(https://[A-Za-z0-9.-]+\\.webhook\\.office\\.com/webhook(?:b2)?/[A-Za-z0-9@/_-]{40,})`, ['webhook.office.com']],
    ['netlify-token', 'Netlify personal access token', `${B}(nfp_[A-Za-z0-9]{30,})${E}`, ['nfp_']],
    ['newrelic-user-key', 'New Relic user API key', `${B}(NRAK-[A-Z0-9]{27})${E}`, ['nrak-']],
    ['newrelic-insert-key', 'New Relic insert key', `${B}(NRII-[A-Za-z0-9-]{32})${E}`, ['nrii-']],
    ['newrelic-browser-key', 'New Relic browser key', `${B}(NRJS-${HEX}{19})${E}`, ['nrjs-']],
    ['openshift-token', 'OpenShift user token', `${B}(sha256~[A-Za-z0-9_-]{43})${E}`, ['sha256~']],
    ['planetscale-token', 'PlanetScale token', `${B}(pscale_(?:tkn|oauth|pw)_[A-Za-z0-9_=.-]{32,64})${E}`, ['pscale_']],
    ['plaid-token', 'Plaid access token', `${B}(access-(?:sandbox|development|production)-${HEX}{8}-${HEX}{4}-${HEX}{4}-${HEX}{4}-${HEX}{12})${E}`, ['access-sandbox-', 'access-development-', 'access-production-']],
    ['postman-key', 'Postman API key', `${B}(PMAK-${HEX}{24}-${HEX}{34})${E}`, ['pmak-']],
    ['prefect-key', 'Prefect API key', `${B}(pnu_[A-Za-z0-9]{36})${E}`, ['pnu_']],
    ['pulumi-token', 'Pulumi access token', `${B}(pul-${HEX}{40})${E}`, ['pul-']],
    ['readme-key', 'ReadMe API key', `${B}(rdme_[a-z0-9]{70})${E}`, ['rdme_']],
    ['rubygems-key', 'RubyGems API key', `${B}(rubygems_${HEX}{48})${E}`, ['rubygems_']],
    ['scalingo-token', 'Scalingo API token', `${B}(tk-us-[A-Za-z0-9_-]{48})${E}`, ['tk-us-']],
    ['brevo-key', 'Brevo (Sendinblue) API key', `${B}(xkeysib-${HEX}{64}-[A-Za-z0-9]{16})${E}`, ['xkeysib-']],
    ['sentry-user-token', 'Sentry user token', `${B}(sntryu_${HEX}{64})${E}`, ['sntryu_']],
    ['sentry-org-token', 'Sentry organization token', `${B}(sntrys_[A-Za-z0-9+/_=]{60,400})${E}`, ['sntrys_']],
    ['settlemint-token', 'SettleMint access token', `${B}(sm_(?:aat|pat|sat)_[A-Za-z0-9]{16})${E}`, ['sm_aat_', 'sm_pat_', 'sm_sat_'], { severity: 'medium', priority: 75 }],
    ['shippo-key', 'Shippo API key', `${B}(shippo_(?:live|test)_${HEX}{40})${E}`, ['shippo_']],
    ['sonarqube-token', 'SonarQube token', `${B}(sq[pau]_${HEX}{40})${E}`, ['sqp_', 'sqa_', 'squ_']],
    ['sourcegraph-token', 'Sourcegraph access token', `${B}(sgp_(?:(?:${HEX}{16}|local)_)?${HEX}{40})${E}`, ['sgp_']],
    ['square-access-token', 'Square access token', `${B}(EAAA[A-Za-z0-9_-]{60})${E}`, ['eaaa']],
    ['stripe-webhook-secret', 'Stripe webhook signing secret', `${B}(whsec_[A-Za-z0-9]{32,})${E}`, ['whsec_']],
    ['tailscale-key', 'Tailscale key', `${B}(tskey-(?:api|auth|client|scim)-[A-Za-z0-9]{6,}(?:CNTRL)?-[A-Za-z0-9]{20,})${E}`, ['tskey-']],
    ['typeform-token', 'Typeform personal token', `${B}(tfp_[A-Za-z0-9_.=-]{59})${E}`, ['tfp_']],
    ['octopus-deploy-key', 'Octopus Deploy API key', `${B}(API-[A-Z0-9]{26})${E}`, ['api-'], { severity: 'medium', priority: 70, validate: (v) => notPlaceholderKey(v) && V.shannonEntropy(v.slice(4)) >= 3.4 }],
    ['twitter-bearer-token', 'X / Twitter bearer token', `${B}(A{22}[A-Za-z0-9%]{80,100})${E}`, ['aaaaaaaaaaaaaaaaaaaaaa'], { validate: (v) => V.shannonEntropy(v.slice(22)) >= 3.8 }],
    ['dropbox-long-lived-token', 'Dropbox long-lived token', `${B}([a-z0-9]{11}AAAAAAAAAA[A-Za-z0-9_=-]{43})${E}`, ['aaaaaaaaaa'], { validate: (v) => V.shannonEntropy(v.replace(/AAAAAAAAAA/, '')) >= 3.6 }],
  ];

  function providerRules() {
    return PROVIDERS.map(([id, label, source, keywords, extra]) => apiKey(id, label, new RegExp(source), keywords, extra));
  }

  const rules = [
    // --- private keys -----------------------------------------------------------------------
    {
      id: 'private-key',
      label: 'Private key',
      category: 'privateKey',
      severity: 'high',
      priority: 100,
      keywords: ['private key'],
      pattern: /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----|(?![\s\S]))/,
      group: 0,
      // A header with no real key material (docs show "XXXX" or "...") is not a key.
      validate(value) {
        // The "\n" in a service-account JSON or an env var is the two characters backslash and n, not a line break.
        const body = value
          .replace(/\\r\\n|\\n|\\r/g, '\n')
          .split(/\r?\n/)
          .filter((line) => !/^-----/.test(line) && !/^[A-Za-z-]+:/.test(line))
          .join('')
          .replace(/\s+/g, '');
        return body.length >= 40 && !V.isRepetitive(body) && V.shannonEntropy(body) >= 3.5;
      },
    },

    // --- provider API keys (fixed prefixes) ---------------------------------------------------
    apiKey('anthropic-api-key', 'Anthropic API key', new RegExp(`${B}(sk-ant-[a-z]{3,5}\\d{2}-[A-Za-z0-9_-]{60,220})${E}`), ['sk-ant-']),
    apiKey('openrouter-api-key', 'OpenRouter API key', new RegExp(`${B}(sk-or-v1-[a-f0-9]{64})${E}`), ['sk-or-']),
    apiKey('openai-api-key', 'OpenAI-style API key (sk-...)', new RegExp(`${B}(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,250})${E}`), ['sk-'], {
      priority: 50,
      validate(value) {
        const body = value.replace(/^sk-(?:proj-|svcacct-|admin-)?/, '');
        const hyphens = (body.match(/-/g) || []).length;
        // Hex-only keys (some providers use sk- plus 32 hex) cannot exceed 4.0 bits per character.
        const enough = /^[a-f0-9]+$/i.test(body) ? 3.3 : 4.0;
        return notPlaceholderKey(value) && /\d/.test(body) && /[A-Za-z]/.test(body) && hyphens <= 4 && V.shannonEntropy(body) >= enough;
      },
    }),
    apiKey('google-api-key', 'Google API key', new RegExp(`${B}(AIza[0-9A-Za-z_-]{35})${E}`), ['aiza']),
    apiKey('google-oauth-token', 'Google OAuth access token', new RegExp(`${B}(ya29\\.[0-9A-Za-z_-]{30,300})${E}`), ['ya29.']),
    apiKey('aws-access-key-id', 'AWS access key ID', new RegExp(`${B}((?:AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})${E}`), ['akia', 'asia', 'abia', 'acca']),
    apiKey(
      'aws-secret-key',
      'AWS secret access key',
      /(?:aws[_-]?secret[_-]?(?:access[_-]?)?key|secret[_-]?access[_-]?key)["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])/i,
      ['secret'],
      { priority: 92 }
    ),
    apiKey('github-token', 'GitHub token', new RegExp(`${B}(gh[pousr]_[A-Za-z0-9]{36,251})${E}`), ['ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_']),
    apiKey('github-fine-grained-token', 'GitHub fine-grained token', new RegExp(`${B}(github_pat_[A-Za-z0-9_]{22,255})${E}`), ['github_pat_']),
    apiKey('gitlab-token', 'GitLab token', new RegExp(`${B}(glpat-[A-Za-z0-9_-]{20,})${E}`), ['glpat-']),
    apiKey('slack-token', 'Slack token', new RegExp(`${B}(xox[baprs]-[A-Za-z0-9-]{10,250})${E}`), ['xox']),
    apiKey('slack-webhook', 'Slack webhook URL', /(https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8,12}\/B[A-Z0-9]{8,12}\/[A-Za-z0-9]{20,30})/, ['hooks.slack.com']),
    apiKey('stripe-live-key', 'Stripe live secret key', new RegExp(`${B}([rs]k_live_[A-Za-z0-9]{20,99})${E}`), ['_live_']),
    apiKey('stripe-test-key', 'Stripe test secret key', new RegExp(`${B}([rs]k_test_[A-Za-z0-9]{20,99})${E}`), ['_test_'], { severity: 'medium', priority: 85 }),
    apiKey('sendgrid-api-key', 'SendGrid API key', new RegExp(`${B}(SG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43})${E}`), ['sg.']),
    apiKey('npm-token', 'npm access token', new RegExp(`${B}(npm_[A-Za-z0-9]{36})${E}`), ['npm_']),
    apiKey('pypi-token', 'PyPI upload token', new RegExp(`${B}(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,})${E}`), ['pypi-']),
    apiKey('huggingface-token', 'Hugging Face token', new RegExp(`${B}(hf_[A-Za-z0-9]{34,})${E}`), ['hf_']),
    apiKey('groq-api-key', 'Groq API key', new RegExp(`${B}(gsk_[A-Za-z0-9]{40,})${E}`), ['gsk_']),
    apiKey('replicate-token', 'Replicate API token', new RegExp(`${B}(r8_[A-Za-z0-9]{37})${E}`), ['r8_']),
    apiKey('perplexity-api-key', 'Perplexity API key', new RegExp(`${B}(pplx-[A-Za-z0-9]{40,})${E}`), ['pplx-']),
    apiKey('xai-api-key', 'xAI API key', new RegExp(`${B}(xai-[A-Za-z0-9]{60,})${E}`), ['xai-']),
    apiKey('telegram-bot-token', 'Telegram bot token', new RegExp(`(?<![\\d:A-Za-z_-])(\\d{8,10}:[A-Za-z0-9_-]{35})${E}`), [':'], {
      validate: (value) => notPlaceholderKey(value) && V.shannonEntropy(value.split(':')[1]) >= 3.5,
    }),
    // Three dotted segments also describe plenty of code identifiers, so insist on digits and randomness.
    apiKey('discord-bot-token', 'Discord bot token', new RegExp(`${B}([MNO][A-Za-z0-9_-]{23,25}\\.[A-Za-z0-9_-]{6}\\.[A-Za-z0-9_-]{27,38})${E}`), ['.'], {
      validate: (value) => notPlaceholderKey(value) && /\d/.test(value) && V.shannonEntropy(value) >= 4.0,
    }),
    apiKey('shopify-token', 'Shopify access token', new RegExp(`${B}(shp(?:at|ca|pa|ss)_[a-f0-9]{32})${E}`), ['shp']),
    apiKey('digitalocean-token', 'DigitalOcean token', new RegExp(`${B}(do[opr]_v1_[a-f0-9]{64})${E}`), ['_v1_']),
    apiKey('databricks-token', 'Databricks token', new RegExp(`${B}(dapi[a-f0-9]{32})${E}`), ['dapi']),
    apiKey('slack-app-token', 'Slack app token', new RegExp(`${B}(xapp-\\d-[A-Z0-9]{8,}-\\d{8,}-[a-f0-9]{32,})${E}`), ['xapp-']),
    apiKey('supabase-token', 'Supabase access token', new RegExp(`${B}(sbp_[a-f0-9]{40})${E}`), ['sbp_']),
    apiKey('linear-api-key', 'Linear API key', new RegExp(`${B}(lin_api_[A-Za-z0-9]{40})${E}`), ['lin_api_']),
    apiKey('notion-token', 'Notion integration token', new RegExp(`${B}((?:ntn_[A-Za-z0-9]{40,}|secret_[A-Za-z0-9]{43}))${E}`), ['ntn_', 'secret_'], {
      validate: (value) => notPlaceholderKey(value) && V.shannonEntropy(value.replace(/^(?:ntn_|secret_)/, '')) >= 3.8,
    }),
    apiKey('pinecone-key', 'Pinecone API key', new RegExp(`${B}(pcsk_[A-Za-z0-9_]{50,})${E}`), ['pcsk_']),
    apiKey('square-token', 'Square access token', new RegExp(`${B}(sq0atp-[A-Za-z0-9_-]{22})${E}`), ['sq0atp-']),
    apiKey('mailgun-key', 'Mailgun API key', new RegExp(`${B}(key-[0-9a-f]{32})${E}`), ['key-'], { severity: 'medium', priority: 80 }),
    apiKey('twilio-api-key', 'Twilio API key SID', new RegExp(`${B}(SK[0-9a-f]{32})${E}`), ['sk'], { severity: 'medium', priority: 80 }),
    apiKey('azure-storage-key', 'Azure storage account key', /AccountKey=([A-Za-z0-9+/]{70,100}={0,2})/, ['accountkey=']),

    ...providerRules(),

    // --- tokens -------------------------------------------------------------------------------
    {
      id: 'jwt',
      label: 'JSON Web Token (JWT)',
      category: 'token',
      severity: 'medium',
      priority: 60,
      keywords: ['eyj'],
      pattern: new RegExp(`${B}(eyJ[A-Za-z0-9_-]{8,}\\.eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,})${E}`),
      group: 1,
      validate: (value) => V.jwtLooksValid(value),
    },
    {
      id: 'bearer-token',
      label: 'Bearer token',
      category: 'token',
      severity: 'medium',
      priority: 65,
      keywords: ['bearer', 'token '],
      pattern: /\bauthorization\b["']?\s*[:=]\s*["']?(?:bearer|token)\s+([A-Za-z0-9._~+/=-]{16,})/i,
      group: 1,
      validate: (value) => !V.isPlaceholder(value) && !V.looksLikeCodeReference(value) && V.shannonEntropy(value) >= 3.0,
    },
    {
      id: 'basic-auth-header',
      label: 'Basic auth credentials',
      category: 'token',
      severity: 'medium',
      priority: 65,
      keywords: ['basic'],
      pattern: /\bauthorization\b["']?\s*[:=]\s*["']?basic\s+([A-Za-z0-9+/]{8,}={0,2})/i,
      group: 1,
      validate(value) {
        if (V.isPlaceholder(value)) return false;
        try {
          const decoded = typeof atob === 'function' ? atob(value) : Buffer.from(value, 'base64').toString('binary');
          return /^[^:]+:.+/.test(decoded) && !V.isPlaceholder(decoded.split(':').slice(1).join(':'));
        } catch (e) {
          return false;
        }
      },
    },

    // --- credentials ---------------------------------------------------------------------------
    {
      id: 'url-credentials',
      label: 'Password in a URL',
      category: 'credential',
      severity: 'high',
      priority: 70,
      keywords: ['://'],
      pattern: /\b[a-z][a-z0-9+.-]{1,24}:\/\/[^\s:/@?#"'<>]{1,100}:([^\s@/?#"'<>]{3,200})@[^\s/?#"'<>]+/i,
      group: 1,
      validate(value, ctx) {
        if (V.isPlaceholder(value) || /^(?:pass|pwd|secret|user|root|admin|xxx+)$/i.test(value)) return false;
        const url = ctx.match[0];
        const host = url.slice(url.indexOf('@') + 1).split(/[/:?#]/)[0];
        return !V.isExampleDomain(host); // a URL at example.com is documentation
      },
    },
    {
      id: 'password-assignment',
      label: 'Password',
      category: 'credential',
      severity: 'medium',
      priority: 40,
      keywords: ['pass', 'pw'],
      pattern: new RegExp(assignment(PASSWORD_KEY), 'i'),
      group: [3, 4, 5],
      validate: (value, ctx) =>
        value.length <= 128 &&
        !keyDescribesASecret(ctx) &&
        !isCodeLiteral(value, ctx) &&
        !V.isPlaceholder(value) &&
        !V.looksLikeCodeReference(value) &&
        !V.isRepetitive(value) &&
        !looksLikeUrlOrPath(value) &&
        !looksLikeFileName(value) &&
        !/:\s*$/.test(value), // "npm password: " is a prompt, not a password
    },
    {
      id: 'secret-assignment',
      label: 'Secret value',
      category: 'credential',
      severity: 'medium',
      priority: 38,
      keywords: ['secret', 'token', 'key', 'credential'],
      pattern: new RegExp(assignment(SECRET_KEY), 'i'),
      group: [3, 4, 5],
      validate: (value, ctx) =>
        value.length >= 12 &&
        value.length <= 400 &&
        !/\s/.test(value) && // a sentence, not a key
        !keyDescribesASecret(ctx) &&
        !isCodeLiteral(value, ctx) &&
        !V.isPlaceholder(value) &&
        !V.looksLikeCodeReference(value) &&
        !V.isRepetitive(value) &&
        !looksLikeUrlOrPath(value) &&
        !looksLikeFileName(value) &&
        !looksLikeWords(value) &&
        V.shannonEntropy(value) >= 3.0,
    },
    {
      id: 'url-query-secret',
      label: 'Secret in a URL',
      category: 'credential',
      severity: 'medium',
      priority: 45,
      keywords: ['='],
      // ?api_key=..., &token=...: a parameter whose whole name says it is a credential. Exact names only, so
      // ?token_type=bearer and ?sort=name are left alone.
      pattern: /[?&](?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|token|secret|client[_-]?secret|password|passwd|pwd|signature|key)=([^&\s"'<>#]{8,400})/i,
      group: 1,
      validate(value, ctx) {
        const name = ctx.match[0].slice(1, ctx.match[0].indexOf('=')).toLowerCase();
        if (V.isPlaceholder(value) || V.looksLikeCodeReference(value) || V.isRepetitive(value) || looksLikeWords(value)) return false;
        if (name === 'key') return value.length >= 16 && V.shannonEntropy(value) >= 3.5; // "?key=" is also an ordinary lookup parameter
        return V.shannonEntropy(value) >= 3.0;
      },
    },
    {
      id: 'cli-credentials',
      label: 'Password on a command line',
      category: 'credential',
      severity: 'medium',
      priority: 44,
      keywords: ['-u', '--user', '-p', '-a '],
      // curl -u user:pass | docker login ... -p pass, sshpass -p pass | mysql -ppass | redis-cli -a pass
      pattern: new RegExp(
        [
          '(?:^|\\s)(?:-u|--user|--proxy-user)(?:\\s+|=)["\']?[^\\s:"\']{1,60}:([^\\s"\']{4,200})',
          '(?:docker\\s+login|sshpass)\\b[^\\n]*?\\s-p\\s+["\']?([^\\s"\']{4,200})',
          '\\bmysql(?:dump|admin)?\\b[^\\n]*?\\s-p([^\\s"\'\\-][^\\s"\']{3,200})',
          '\\bredis-cli\\b[^\\n]*?\\s-a\\s+["\']?([^\\s"\']{4,200})',
        ].join('|'),
        'i'
      ),
      group: [1, 2, 3, 4],
      validate: (value) => !V.isPlaceholder(value) && !V.looksLikeCodeReference(value) && !V.isRepetitive(value),
    },
    {
      id: 'netrc-password',
      label: 'Password in a .netrc entry',
      category: 'credential',
      severity: 'medium',
      priority: 44,
      keywords: ['machine'],
      pattern: /\bmachine\s+\S+\s+login\s+\S+\s+password\s+(\S{4,200})/i,
      group: 1,
      validate: (value) => !V.isPlaceholder(value) && !V.looksLikeCodeReference(value),
    },
    {
      id: 'cli-secret-flag',
      label: 'Secret on a command line',
      category: 'credential',
      severity: 'medium',
      priority: 42,
      keywords: ['--'],
      pattern: /(?:^|\s)--(?:password|passwd|token|secret|api-key|apikey|access-token|auth-token|client-secret)(?:=|\s+)(?:"([^"\n]{6,200})"|'([^'\n]{6,200})'|([^\s"']{6,200}))/i,
      group: [1, 2, 3],
      validate: (value) => !V.isPlaceholder(value) && !V.looksLikeCodeReference(value) && !V.isRepetitive(value),
    },

    // --- financial -----------------------------------------------------------------------------
    {
      id: 'credit-card',
      label: 'Payment card number',
      category: 'financial',
      severity: 'high',
      priority: 80,
      // Not glued to letters, a decimal point or a sign: that is a long decimal such as 1.5707963267948966, not a card.
      pattern: /(?<![\w.+-])(\d(?:[ -]?\d){12,18})(?![\w-]|\.\d)/,
      group: 1,
      // Written with optional spaces or dashes; only the digits are checked.
      validate: (value) => V.cardNumberValid(value.replace(/[ -]/g, '')),
    },
    {
      id: 'iban',
      label: 'Bank account number (IBAN)',
      category: 'financial',
      severity: 'high',
      priority: 75,
      pattern: /(?<![A-Za-z0-9])([A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?)(?![A-Za-z0-9])/,
      group: 1,
      validate: (value) => V.ibanValid(value),
    },

    // --- government IDs -----------------------------------------------------------------------
    {
      id: 'us-ssn',
      label: 'US Social Security number',
      category: 'government',
      severity: 'high',
      priority: 80,
      pattern: /(?<![\d-])(?!000|666|9\d\d)(\d{3}-(?!00)\d{2}-(?!0000)\d{4})(?![\d-])/,
      group: 1,
      validate: (value) => !V.isRepetitive(value.replace(/-/g, '')),
    },
    {
      id: 'aadhaar',
      label: 'Aadhaar number',
      category: 'government',
      severity: 'high',
      priority: 78,
      pattern: /(?<![\d-])([2-9]\d{3}[ -]?\d{4}[ -]?\d{4})(?![\d-])/,
      group: 1,
      validate(value, ctx) {
        const digits = value.replace(/[ -]/g, '');
        if (!V.verhoeff(digits) || /^(\d)\1+$/.test(digits)) return false;
        if (/[ -]/.test(value)) return true; // written the usual way, in groups of four
        return /aadhaar|aadhar|uidai|\buid\b/i.test(ctx.before.slice(-80) + ' ' + ctx.after.slice(0, 20)); // a bare 12-digit number needs a label
      },
    },
    {
      id: 'india-pan',
      label: 'PAN (Indian tax ID)',
      category: 'government',
      severity: 'medium',
      priority: 60,
      pattern: /(?<![A-Za-z0-9])([A-Z]{3}[ABCFGHLJPTK][A-Z]\d{4}[A-Z])(?![A-Za-z0-9])/,
      group: 1,
      validate: (value, ctx) => /\bpan\b|permanent account|income[- ]tax|\bitr\b/i.test(ctx.before.slice(-60) + ' ' + ctx.after.slice(0, 20)),
    },

    // --- contact details (off by default) ------------------------------------------------------
    {
      id: 'email',
      label: 'Email address',
      category: 'email',
      severity: 'low',
      priority: 20,
      keywords: ['@'],
      pattern: /(?<![A-Za-z0-9._%+-])([A-Za-z0-9][A-Za-z0-9._%+-]{0,63}@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.){1,5}[A-Za-z]{2,24})(?![A-Za-z0-9@-])/,
      group: 1,
      validate: (value) => !V.isExampleDomain(value.slice(value.lastIndexOf('@') + 1)),
    },
    {
      id: 'phone',
      label: 'Phone number',
      category: 'phone',
      severity: 'low',
      priority: 15,
      keywords: ['+'],
      pattern: /(?<![\w+.-])(\+\d{1,3}[ .-]?\(?\d{1,4}\)?(?:[ .-]?\d{2,4}){2,4})(?!\d)/,
      group: 1,
      validate(value) {
        const digits = value.replace(/\D/g, '');
        return digits.length >= 10 && digits.length <= 15 && !V.isRepetitive(digits);
      },
    },

    // --- random-looking strings (off by default) -------------------------------------------------
    {
      id: 'high-entropy-string',
      label: 'Random-looking string',
      category: 'highEntropy',
      severity: 'low',
      priority: 10,
      pattern: /(?<![A-Za-z0-9+_=-])([A-Za-z0-9+_-]{32,128}={0,2})(?![A-Za-z0-9+_=-])/,
      group: 1,
      validate(value) {
        const bare = value.replace(/=+$/, '');
        if (/^[a-f0-9]+$/i.test(bare) && [32, 40, 56, 64, 96, 128].includes(bare.length)) return false; // a hash, usually
        return /\d/.test(bare) && /[A-Za-z]/.test(bare) && !V.isRepetitive(bare) && V.shannonEntropy(bare) >= 4.2;
      },
    },
  ];

  /** Every category a rule can belong to, with the default on/off setting and a plain-English name. */
  const categories = {
    apiKey: { label: 'API keys', defaultOn: true },
    privateKey: { label: 'Private keys', defaultOn: true },
    token: { label: 'Tokens (JWT, bearer, basic auth)', defaultOn: true },
    credential: { label: 'Passwords and secrets in code or URLs', defaultOn: true },
    financial: { label: 'Card and bank numbers', defaultOn: true },
    government: { label: 'Government IDs (SSN, Aadhaar, PAN)', defaultOn: true },
    email: { label: 'Email addresses', defaultOn: false },
    phone: { label: 'Phone numbers', defaultOn: false },
    highEntropy: { label: 'Random-looking strings (noisy)', defaultOn: false },
  };

  PG.rules = rules;
  PG.categories = categories;

  if (typeof module !== 'undefined' && module.exports) module.exports = { rules, categories };
})(typeof globalThis !== 'undefined' ? globalThis : this);
