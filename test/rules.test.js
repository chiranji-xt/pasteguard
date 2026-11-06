const test = require('node:test');
const assert = require('node:assert/strict');
const { rules, categories } = require('../src/engine/rules.js');
const { scan } = require('../src/engine/detect.js');
const { fixtures } = require('../test/fixtures.js');

// Everything on, so a rule is judged on its own merits and not on a default setting.
const ALL = { minSeverity: 'low', categories: Object.fromEntries(Object.keys(categories).map((c) => [c, true])) };

test('every rule is well formed', () => {
  const ids = new Set();
  for (const rule of rules) {
    assert.match(rule.id, /^[a-z0-9]+(?:-[a-z0-9]+)*$/, `${rule.id}: id must be kebab-case`);
    assert.ok(!ids.has(rule.id), `${rule.id}: duplicate id`);
    ids.add(rule.id);
    assert.ok(rule.label && rule.label.length > 3, `${rule.id}: needs a label`);
    assert.ok(categories[rule.category], `${rule.id}: unknown category ${rule.category}`);
    assert.ok(['high', 'medium', 'low'].includes(rule.severity), `${rule.id}: bad severity`);
    assert.ok(rule.pattern instanceof RegExp, `${rule.id}: needs a pattern`);
    assert.ok(Number.isInteger(rule.priority), `${rule.id}: needs a priority`);
    if (rule.keywords) for (const k of rule.keywords) assert.equal(k, k.toLowerCase(), `${rule.id}: keywords must be lowercase`);
  }
});

test('every rule has positive and negative examples', () => {
  for (const rule of rules) {
    const fx = fixtures[rule.id];
    assert.ok(fx, `${rule.id}: add examples to test/fixtures.js`);
    assert.ok(fx.positive && fx.positive.length >= 1, `${rule.id}: needs at least one positive example`);
    assert.ok(fx.negative && fx.negative.length >= 1, `${rule.id}: needs at least one negative example`);
  }
  for (const id of Object.keys(fixtures)) assert.ok(rules.some((r) => r.id === id), `fixtures mention unknown rule ${id}`);
});

for (const rule of rules) {
  const fx = fixtures[rule.id];
  if (!fx) continue;

  test(`${rule.id}: finds its positive examples`, () => {
    fx.positive.forEach((make, i) => {
      const text = make();
      const hit = scan(text, ALL).findings.find((f) => f.ruleId === rule.id);
      assert.ok(hit, `positive #${i + 1} was not found:\n${text.slice(0, 160)}`);
      assert.ok(text.includes(hit.value), 'the reported value must be a slice of the text');
    });
  });

  test(`${rule.id}: ignores its negative examples`, () => {
    fx.negative.forEach((text, i) => {
      const hit = scan(text, ALL).findings.find((f) => f.ruleId === rule.id);
      assert.equal(hit, undefined, `negative #${i + 1} wrongly matched: ${JSON.stringify(text.slice(0, 120))}`);
    });
  });
}
