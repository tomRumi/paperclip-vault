"""vaultd against the real helper (Node) and a fake OAuth provider: authorize once, then the token lease path end to end
(request -> helper token.mint -> lease.fetch payload -> lease end -> helper token.revoke -> provider). Starting the helper
probes Chromium once (main.js), so this is a heavy test: run it under the shared lock. The broker is told the helper is up
instead of pinging it (a ping would start a browser again)."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request

import support
from support import AGENT_ENG, Env, approve, oauth_site_json
from vaultd.helperclient import HelperClient, HelperError

HELPER = os.path.join(support.HOST, "helper")
FAKE_OAUTH = os.path.join(support.REPO, "tests", "fakes", "fake_oauth.py")
NODE = shutil.which("node")
HAVE_HELPER = NODE is not None and os.path.isdir(os.path.join(HELPER, "node_modules", "playwright-core"))


def wait_for(cond, seconds=20):
    end = time.time() + seconds
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.05)
    return False


@unittest.skipUnless(HAVE_HELPER, "node or the helper's node_modules are not available")
class TokenLeaseEndToEnd(unittest.TestCase):
    def setUp(self):
        self.procs = []
        self.addCleanup(self.stop_all)
        self.dir = tempfile.mkdtemp(prefix="vte", dir="/tmp")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        oauth = subprocess.Popen([sys.executable, "-I", "-B", FAKE_OAUTH, "--interval", "1", "--pending", "1"], stdout=subprocess.PIPE, text=True)
        self.procs.append(oauth)
        self.provider = "http://127.0.0.1:%d" % json.loads(oauth.stdout.readline())["port"]

        d = self.dir
        for sub in ("sites", "creds", "state"):
            os.mkdir(os.path.join(d, sub), 0o700)
        with open(os.path.join(d, "creds", "vault-helper.storekey"), "wb") as f:
            f.write(os.urandom(32))
        self.token_file, self.admin_file = os.path.join(d, "helper.token"), os.path.join(d, "helper-admin.token")
        for path in (self.token_file, self.admin_file):
            with open(path, "w") as f:
                f.write(os.urandom(32).hex() + "\n")
        self.sock = os.path.join(d, "h.sock")
        site = oauth_site_json(allowedAgents=[AGENT_ENG], allowedHosts=[self.provider[len("http://"):]])
        site["oauth"].update(authUrl=self.provider + "/authorize", tokenUrl=self.provider + "/token",
                             deviceUrl=self.provider + "/device", revokeUrl=self.provider + "/revoke")
        with open(os.path.join(d, "sites", "drive.json"), "w") as f:
            json.dump(site, f)
        cfg = {"socketPath": self.sock, "socketGroup": None, "tokenFile": self.token_file, "adminTokenFile": self.admin_file,
               "sitesDir": os.path.join(d, "sites"), "stateDir": os.path.join(d, "state"), "credentialsDir": os.path.join(d, "creds"),
               "allowNoSandbox": True}
        with open(os.path.join(d, "helper.json"), "w") as f:
            json.dump(cfg, f)
        env = dict(os.environ, PLAYWRIGHT_BROWSERS_PATH=os.path.expanduser("~/.cache/ms-playwright"), CREDENTIALS_DIRECTORY="")
        helper = subprocess.Popen([NODE, os.path.join(HELPER, "main.js"), "--config", os.path.join(d, "helper.json")], env=env,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.procs.append(helper)
        self.assertTrue(wait_for(lambda: os.path.exists(self.sock)), "helper did not start")
        self.admin = HelperClient(self.sock, self.admin_file)

        self.env = Env(sites=[oauth_site_json(allowedAgents=[AGENT_ENG])])
        self.addCleanup(self.env.close)
        self.env.write_site(site)
        self.env.helper.path, self.env.token_path = self.sock, self.token_file          # vaultd now talks to the real helper
        self.env.build()
        self.env.broker.helper_seen, self.env.broker.helper_up = 1e18, True      # no ping: only the token ops are under test
        self.env.record_clean()

    def stop_all(self):
        for p in reversed(self.procs):
            p.terminate()
            if p.stdout:
                p.stdout.close()
        for p in self.procs:
            try:
                p.wait(10)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()

    def debug(self):
        with urllib.request.urlopen(self.provider + "/_debug") as r:
            return json.load(r)

    def resource(self, token):
        req = urllib.request.Request(self.provider + "/api/me", headers={"Authorization": "Bearer " + token})
        try:
            with urllib.request.urlopen(req) as r:
                return r.status
        except urllib.error.HTTPError as e:
            e.close()
            return e.code

    def request(self, minutes=30):
        c = self.env.create(agent=AGENT_ENG, credential="oauth-drive", minutes=minutes)
        self.env.verdict(c, [approve(minutes), approve(minutes)])
        return c

    def test_not_authorized_then_authorized_mint_fetch_revoke(self):
        c = self.request()
        st = self.env.ok("request.status", {"requestId": c["requestId"]})
        self.assertEqual((st["state"], st["code"]), ("failed", "needs_authorize"))
        self.assertEqual({s["id"]: s["state"] for s in self.env.ok("sites.list")["sites"]}["drive"], "needs_authorize")

        # the owner authorizes (device flow, as `vault-site authorize` does through the admin token)
        started = self.admin.call("oauth.start", siteId="drive", flow="device")
        self.assertRegex(started["userCode"], r"^WDJB-")
        self.assertEqual(self.admin.call("oauth.finish", handle=started["handle"])["authorized"], True)
        with self.assertRaises(HelperError) as cm:                     # vaultd's own token cannot do that
            HelperClient(self.sock, self.token_file).call("oauth.start", siteId="drive", flow="device")
        self.assertEqual(cm.exception.code, "unauthorized")

        self.env.clock.advance(200)                                    # past the loop guards and the failure note
        c = self.request()
        got = self.env.ok("lease.fetch", {"requestId": c["requestId"]})
        payload = got["payload"]
        self.assertEqual((got["kind"], got["name"]), ("token", "oauth-drive"))
        self.assertEqual(set(payload), {"accessToken", "tokenType", "expiresAt", "scopes"})
        self.assertEqual((payload["tokenType"], payload["scopes"]), ("Bearer", ["drive.read"]))
        self.assertTrue(payload["accessToken"].startswith("at-"))
        self.assertEqual(self.resource(payload["accessToken"]), 200)
        lease_id = self.env.ok("request.status", {"requestId": c["requestId"]})["leaseId"]
        self.assertEqual([l["leaseId"] for l in self.admin.ping()["leases"]], [lease_id])

        self.env.broker.admin({"cmd": "revoke", "lease": lease_id})        # lease end at vaultd -> token.revoke at the helper
        self.assertEqual(self.resource(payload["accessToken"]), 401)
        self.assertEqual(self.debug()["revocations"], 1)
        self.assertEqual(self.admin.ping()["leases"], [])
        self.assertEqual(self.env.ok("request.status", {"requestId": c["requestId"]})["state"], "revoked")

    def test_expiry_at_the_lease_end(self):
        started = self.admin.call("oauth.start", siteId="drive", flow="device")
        self.admin.call("oauth.finish", handle=started["handle"])
        c = self.request(minutes=10)
        got = self.env.ok("lease.fetch", {"requestId": c["requestId"]})
        left = time.mktime(time.strptime(got["payload"]["expiresAt"], "%Y-%m-%dT%H:%M:%SZ")) - time.mktime(time.gmtime())
        self.assertTrue(0 < left <= 600, left)                         # the helper clamps to the lease: 10 minutes, not the provider's hour
        self.env.broker.admin({"cmd": "revoke", "lease": self.env.ok("request.status", {"requestId": c["requestId"]})["leaseId"]})


if __name__ == "__main__":
    unittest.main()
