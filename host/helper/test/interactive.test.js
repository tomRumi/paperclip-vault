// Interactive-site rule (docs/DESIGN.md section 4) and session.import. No browser: a stub
// strategy stands in for the real one (interactive-login.test.js has that).
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { after, before, describe, test } from 'node:test';
import { Sealer } from '../seal.js';
import { fakeSite, inSeconds, open, scratch, startHelper, teardown } from './support.js';

const cookie = (domain) => ({ name: 's', value: 'v', domain, path: '/', expires: -1, httpOnly: true, secure: false, sameSite: 'Lax' });

describe('interactive sites', () => {
  let env, h, calls, site;
  before(async () => {
    env = scratch();
    calls = [];
    site = { origin: 'http://127.0.0.1:9', host: '127.0.0.1:9' };
    const stub = {
      async login(s) {
        calls.push(s.id);
        const state = { cookies: [cookie('127.0.0.1')], origins: [] };
        return { kind: 'done', session: { liveState: state, deliverState: state, landingUrl: s.loginUrl, trustUsed: false } };
      },
    };
    h = await startHelper(env, { extensions: { strategies: { interactive: stub } } });
  });
  after(() => teardown(() => h?.stop(), () => env?.cleanup()));

  const interactive = (over = {}) => {
    const s = fakeSite(site, { id: 'inter', type: 'interactive', ...over });
    delete s.recipe.challenge;
    s.recipe.steps = [];
    return s;
  };
  const install = async (s) => {
    env.writeSite(s);
    await h.ok('site.reload');
  };

  test('without recipe.logout and without acceptNoLogout: needs_owner_ack, nothing runs', async () => {
    const s = interactive();
    delete s.recipe.logout;
    await install(s);
    const res = await open(h, { siteId: 'inter' });
    assert.equal(res.error.code, 'needs_owner_ack');
    assert.equal((await h.call('site.test', { siteId: 'inter' })).error.code, 'needs_owner_ack');
    assert.deepEqual(calls, []);
    assert.equal(h.helper.deps.leases.list().length, 0);
  });

  test('with acceptNoLogout: the lease opens, expires with the lease, and closing reports unsupported', async () => {
    const s = interactive({ acceptNoLogout: true });
    delete s.recipe.logout;
    await install(s);
    const endsAt = inSeconds(120);
    const res = await h.ok('session.open', { leaseId: 'lse_ack1', siteId: 'inter', minutes: 5, endsAt });
    assert.deepEqual(calls, ['inter']);
    assert.equal(res.storageState.cookies[0].expires, Math.floor(Date.parse(endsAt) / 1000));
    assert.deepEqual(await h.ok('session.close', { leaseId: 'lse_ack1' }), { loggedOut: 'unsupported' });
  });

  test('a recipe.logout satisfies the rule without acceptNoLogout', async () => {
    await install(interactive());
    const res = await h.ok('session.open', { leaseId: 'lse_ack2', siteId: 'inter', minutes: 5, endsAt: inSeconds(120) });
    assert.equal(res.trustUsed, false);
    assert.equal(h.helper.deps.leases.list().length, 1);
  });

  test('an oauth site is not opened as a session: it is used through token.mint', async () => {
    const s = fakeSite(site, { id: 'oa', type: 'oauth', recipe: null, loginUrl: null, oauth: { flow: 'device', deviceUrl: 'http://127.0.0.1:9/d', tokenUrl: 'http://127.0.0.1:9/t', clientId: 'c', scopes: [], accessTtlMaxMinutes: 10 } });
    await install(s);
    assert.equal((await open(h, { siteId: 'oa' })).error.code, 'bad_request');
  });
});

describe('session.import', () => {
  let env, h;
  before(async () => {
    env = scratch();
    h = await startHelper(env);
  });
  after(() => teardown(() => h?.stop(), () => env?.cleanup()));

  test('validated and sealed; foreign-host cookies and non-interactive sites are refused', async () => {
    const site = { origin: 'https://app.example.org', host: 'app.example.org' };
    const inter = fakeSite(site, { id: 'inter', type: 'interactive', acceptNoLogout: true });
    inter.recipe.steps = [];
    env.writeSite(inter);
    env.writeSite(fakeSite(site, { id: 'pw' }));
    await h.ok('site.reload');

    const state = { cookies: [{ ...cookie('.example.org'), value: 'TOPSECRETCOOKIE' }], origins: [] };
    assert.deepEqual(await h.ok('session.import', { siteId: 'inter', storageState: state }), { imported: true, cookies: 1 });
    const file = `${env.state}/store/session/inter.enc`;
    assert.equal(fs.statSync(file).mode & 0o777, 0o600);
    assert.equal(fs.readFileSync(file).includes('TOPSECRETCOOKIE'), false);
    assert.equal(new Sealer(env.storeKey).open('session', 'inter', fs.readFileSync(file)).cookies[0].value, 'TOPSECRETCOOKIE');

    const code = async (params) => (await h.call('session.import', params)).error.code;
    assert.equal(await code({ siteId: 'inter', storageState: { cookies: [cookie('evil.example.net')], origins: [] } }), 'bad_request');
    assert.equal(await code({ siteId: 'inter', storageState: { cookies: [], origins: [] } }), 'bad_request');
    assert.equal(await code({ siteId: 'inter', storageState: { cookies: [{ name: 'x' }] } }), 'bad_request');
    assert.equal(await code({ siteId: 'inter', storageState: 'nope' }), 'bad_request');
    assert.equal(await code({ siteId: 'pw', storageState: state }), 'bad_request');
    assert.equal(await code({ siteId: 'ghost', storageState: state }), 'not_found');
  });
});
