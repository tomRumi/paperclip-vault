import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { loadSites, needsOwnerAck, urlAllowed, validateSite } from '../sites.js';
import { scratch } from './support.js';

const good = () => ({
  schema: 1,
  id: 'example-admin',
  displayName: 'Example admin',
  type: 'password-totp',
  kind: 'test',
  purpose: 'Admin panel of the example app',
  loginUrl: 'https://app.example.org/login',
  logoutUrl: 'https://app.example.org/logout',
  allowedHosts: ['app.example.org'],
  allowedAgents: ['11111111-2222-3333-4444-555555555555'],
  roles: ['QA'],
  maxMinutes: 60,
  recipe: {
    steps: [
      { fill: '#email', from: 'username' },
      { click: 'button[type=submit]' },
      { fill: '#password', from: 'password' },
      { click: '#login' },
      { fill: '#otp', from: 'totp', optional: true },
      { press: 'Enter', selector: '#otp', optional: true },
      { waitFor: '#avatar' },
    ],
    successCheck: { urlMatches: '^https://app\\.example\\.org/dashboard', selector: '#avatar' },
    logout: { steps: [{ click: '#logout' }] },
    challenge: { codeSelector: '#code', submit: '#go' },
    trustCookies: ['^device_', '^remember'],
    timeoutSeconds: 45,
  },
  oauth: null,
});

const rejects = (mutate, pattern) => {
  const site = good();
  mutate(site);
  assert.throws(() => validateSite(site), (e) => e.code === 'bad_site' && pattern.test(e.message), `expected ${pattern}`);
};

test('the example site of docs/DESIGN.md validates, defaults are filled and the result is frozen', () => {
  const site = validateSite(good());
  assert.equal(site.recipe.timeoutSeconds, 45);
  assert.equal(site.acceptNoLogout, false);
  assert.equal(Object.isFrozen(site.recipe.steps[0]), true);
  const minimal = good();
  delete minimal.maxMinutes;
  delete minimal.logoutUrl;
  delete minimal.recipe.trustCookies;
  delete minimal.recipe.timeoutSeconds;
  const s = validateSite(minimal);
  assert.deepEqual([s.maxMinutes, s.logoutUrl, s.recipe.trustCookies, s.recipe.timeoutSeconds], [60, null, [], 45]);
});

test('unknown keys are rejected at every level', () => {
  rejects((s) => (s.extra = 1), /unknown key "extra"/);
  rejects((s) => (s.recipe.extra = 1), /recipe: unknown key "extra"/);
  rejects((s) => (s.recipe.steps[0].extra = 1), /steps\[0\]: unknown key "extra"/);
  rejects((s) => (s.recipe.successCheck.extra = 1), /successCheck: unknown key/);
  rejects((s) => (s.recipe.logout.extra = 1), /logout: unknown key/);
  rejects((s) => (s.recipe.challenge.extra = 1), /challenge: unknown key/);
});

test('schema violations are all reported', () => {
  rejects((s) => (s.schema = 2), /schema/);
  rejects((s) => (s.id = 'Bad_Id'), /id:/);
  rejects((s) => (s.type = 'magic'), /type:/);
  rejects((s) => (s.kind = 'prod'), /kind:/);
  rejects((s) => (s.purpose = 'x'.repeat(201)), /purpose/);
  rejects((s) => (s.maxMinutes = 481), /maxMinutes/);
  rejects((s) => (s.allowedHosts = []), /allowedHosts/);
  rejects((s) => (s.allowedHosts = ['App.Example.org']), /allowedHosts\[0\]/);
  rejects((s) => (s.allowedAgents = ['not-a-uuid']), /allowedAgents\[0\]/);
  rejects((s) => (s.loginUrl = 'http://app.example.org/login'), /https/);
  rejects((s) => (s.loginUrl = 'https://other.example.org/login'), /not in allowedHosts/);
  rejects((s) => (s.logoutUrl = 'https://evil.example.net/logout'), /logoutUrl: host is not in allowedHosts/);
  rejects((s) => (s.loginUrl = 'https://user:pw@app.example.org/'), /credentials/);
  rejects((s) => delete s.recipe.successCheck, /successCheck/);
  rejects((s) => (s.recipe.successCheck = {}), /mandatory/);
  rejects((s) => (s.recipe.successCheck = { urlMatches: '(' }), /regular expression/);
  rejects((s) => (s.recipe.steps = []), /steps/);
  rejects((s) => (s.recipe.trustCookies = ['[']), /trustCookies\[0\]/);
  rejects((s) => (s.recipe.timeoutSeconds = 2), /timeoutSeconds/);
  rejects((s) => (s.oauth = { flow: 'device' }), /oauth/);
  rejects((s) => (s.acceptNoLogout = 'yes'), /acceptNoLogout/);
});

test('steps: exactly one op, no scripts, from only on fill', () => {
  rejects((s) => (s.recipe.steps[0] = { evaluate: 'alert(1)' }), /unknown key "evaluate"/);
  rejects((s) => (s.recipe.steps[0] = { fill: '#a', click: '#b', from: 'username' }), /exactly one/);
  rejects((s) => (s.recipe.steps[0] = { fill: '#a', from: 'secret' }), /from/);
  rejects((s) => (s.recipe.steps[0] = { fill: '#a' }), /from/);
  rejects((s) => (s.recipe.steps[0] = { click: '#a', from: 'password' }), /only valid on a fill/);
  rejects((s) => (s.recipe.steps[0] = { click: '#a', selector: '#b' }), /only valid on a press/);
  rejects((s) => (s.recipe.steps[0] = { click: '#a', optional: 'yes' }), /optional/);
});

test('loopback http is allowed (tests), other http is not; ports are part of the host', () => {
  const s = good();
  s.loginUrl = 'http://127.0.0.1:8080/login';
  s.logoutUrl = null;
  s.allowedHosts = ['127.0.0.1:8080'];
  validateSite(s);
  assert.equal(urlAllowed('http://127.0.0.1:8080/x', ['127.0.0.1:8080']), true);
  assert.equal(urlAllowed('http://127.0.0.1:8081/x', ['127.0.0.1:8080']), false);
  assert.equal(urlAllowed('https://app.example.org:8443/', ['app.example.org']), false);
  assert.equal(urlAllowed('https://app.example.org/', ['app.example.org']), true);
  assert.equal(urlAllowed('http://localhost:8080/', ['127.0.0.1:8080']), false);
  assert.equal(urlAllowed('file:///etc/passwd', ['app.example.org']), false);
  // https only, except loopback
  assert.equal(urlAllowed('http://app.example.org/', ['app.example.org']), false);
  assert.equal(urlAllowed('http://app.example.org:8080/', ['app.example.org:8080']), false);
  assert.equal(urlAllowed('http://localhost:8080/', ['localhost:8080']), true);
  assert.equal(urlAllowed('http://[::1]:8080/', ['[::1]:8080']), true);
});

test('interactive and oauth sites', () => {
  const inter = good();
  inter.type = 'interactive';
  delete inter.recipe.steps;
  delete inter.recipe.logout;
  assert.equal(needsOwnerAck(validateSite(inter)), true);
  inter.acceptNoLogout = true;
  assert.equal(needsOwnerAck(validateSite(inter)), false);
  const withLogout = good();
  withLogout.type = 'interactive';
  assert.equal(needsOwnerAck(validateSite(withLogout)), false);
  assert.equal(needsOwnerAck(validateSite(good())), false);

  const o = good();
  o.type = 'oauth';
  o.recipe = null;
  o.loginUrl = null;
  o.logoutUrl = null;
  o.oauth = {
    flow: 'device', deviceUrl: 'https://auth.example.org/device', tokenUrl: 'https://auth.example.org/token',
    clientId: 'abc', scopes: ['read'], accessTtlMaxMinutes: 30,
  };
  o.allowedHosts = ['auth.example.org'];
  assert.equal(validateSite(o).oauth.flow, 'device');
  o.oauth.extra = 1;
  assert.throws(() => validateSite(o), /unknown key "extra"/);
});

test('loadSites reports invalid files without failing and enforces <id>.json', () => {
  const env = scratch();
  try {
    fs.writeFileSync(path.join(env.sites, 'example-admin.json'), JSON.stringify(good()));
    fs.writeFileSync(path.join(env.sites, 'broken.json'), '{nope');
    fs.writeFileSync(path.join(env.sites, 'wrong-name.json'), JSON.stringify(good()));
    const extra = good();
    extra.id = 'extra-key';
    extra.surprise = true;
    fs.writeFileSync(path.join(env.sites, 'extra-key.json'), JSON.stringify(extra));
    const { sites, errors } = loadSites(env.sites);
    assert.deepEqual([...sites.keys()], ['example-admin']);
    assert.deepEqual(errors.map((e) => e.file).sort(), ['broken.json', 'extra-key.json', 'wrong-name.json']);
    assert.match(errors.find((e) => e.file === 'extra-key.json').message, /unknown key "surprise"/);
    assert.equal(loadSites(path.join(env.root, 'missing')).sites.size, 0);
  } finally {
    env.cleanup();
  }
});

test('challenge.remember and recipe.trustStorageKeys', () => {
  const s = good();
  s.recipe.challenge = { codeSelector: '#code', submit: '#go', remember: '#remember' };
  s.recipe.trustStorageKeys = ['^device_', 'remember$'];
  const v = validateSite(s);
  assert.equal(v.recipe.challenge.remember, '#remember');
  assert.deepEqual(v.recipe.trustStorageKeys, ['^device_', 'remember$']);
  assert.deepEqual(validateSite(good()).recipe.trustStorageKeys, []);

  const bad = (mutate, re) => {
    const x = good();
    x.recipe.challenge = { codeSelector: '#code', submit: '#go' };
    mutate(x);
    assert.throws(() => validateSite(x), re);
  };
  bad((x) => (x.recipe.challenge.remember = ''), /recipe\.challenge\.remember/);
  bad((x) => (x.recipe.challenge.remember = 5), /recipe\.challenge\.remember/);
  bad((x) => (x.recipe.challenge.other = '#x'), /unknown key "other"/);
  bad((x) => (x.recipe.trustStorageKeys = ['(unclosed']), /not a valid regular expression/);
  bad((x) => (x.recipe.trustStorageKeys = 'x'), /array of at most 20 patterns/);
});
