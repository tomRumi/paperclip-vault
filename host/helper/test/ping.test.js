// ping: per-site state from the credential files and the sealed store. No browser.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { after, before, describe, test } from 'node:test';
import { fakeSite, oauthSite, scratch, startHelper, teardown } from './support.js';

describe('ping sites', () => {
  let env, h;
  const origin = { origin: 'http://127.0.0.1:9', host: '127.0.0.1:9' };
  const states = async () => Object.fromEntries((await h.ok('ping')).sites.map((s) => [s.siteId, s.state]));
  const cred = (siteId, part) => path.join(env.creds, `vault-helper.site.${siteId}.${part}`);

  before(async () => {
    env = scratch();
    h = await startHelper(env);
  });
  after(() => teardown(() => h?.stop(), () => env?.cleanup()));

  test('password-totp: ready with username and password (the TOTP step is optional), missing_credential without', async () => {
    env.writeSite(fakeSite(origin, { id: 'pw' }));
    await h.ok('site.reload');
    assert.equal((await states()).pw, 'missing_credential');
    env.writeCreds('pw');
    assert.equal((await states()).pw, 'ready');
    fs.rmSync(cred('pw', 'totp'));
    assert.equal((await states()).pw, 'ready');
    fs.rmSync(cred('pw', 'password'));
    assert.equal((await states()).pw, 'missing_credential');
    fs.writeFileSync(cred('pw', 'password'), '');
    assert.equal((await states()).pw, 'missing_credential', 'an empty file is not a credential');
  });

  test('a required TOTP step needs the seed', async () => {
    const s = fakeSite(origin, { id: 'pw-totp' });
    s.recipe.steps[4].optional = false;
    env.writeSite(s);
    await h.ok('site.reload');
    env.writeCreds('pw-totp', { totp: null });
    assert.equal((await states())['pw-totp'], 'missing_credential');
    env.writeCreds('pw-totp');
    assert.equal((await states())['pw-totp'], 'ready');
  });

  test('interactive: needs_interactive until a session is sealed, then needs_owner_ack without logout and acceptNoLogout', async () => {
    const s = fakeSite(origin, { id: 'inter', type: 'interactive' });
    s.recipe.logout = null;
    s.recipe.steps = [];
    env.writeSite(s);
    await h.ok('site.reload');
    assert.equal((await states()).inter, 'needs_interactive');
    const state = { cookies: [{ name: 's', value: 'v', domain: '127.0.0.1', path: '/', expires: -1, httpOnly: true, secure: false, sameSite: 'Lax' }], origins: [] };
    await h.ok('session.import', { siteId: 'inter', storageState: state });
    assert.equal((await states()).inter, 'needs_owner_ack');
    env.writeSite({ ...s, acceptNoLogout: true });
    await h.ok('site.reload');
    assert.equal((await states()).inter, 'ready');
    await h.ok('site.forget', { siteId: 'inter' });
    assert.equal((await states()).inter, 'needs_interactive');
  });

  test('oauth: needs_authorize until a refresh token is sealed', async () => {
    env.writeSite(oauthSite(origin, { id: 'drive' }));
    await h.ok('site.reload');
    assert.equal((await states()).drive, 'needs_authorize');
    await h.helper.deps.store.put('oauth', 'drive', { v: 1, refreshToken: 'rt', scopes: [] });
    assert.equal((await states()).drive, 'ready');
  });

  test('the list holds exactly the loaded sites and nothing secret', async () => {
    const ping = await h.ok('ping');
    assert.deepEqual(ping.sites.map((s) => s.siteId).sort(), ['drive', 'inter', 'pw', 'pw-totp']);
    for (const s of ping.sites) assert.deepEqual(Object.keys(s).sort(), ['siteId', 'state']);
  });
});
