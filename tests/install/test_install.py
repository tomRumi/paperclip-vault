"""The installer, the release script and vault-site, in a scratch directory only (never as root, never on the system):
scripts/release.sh builds a release with a file:// download URL, then install-vault.sh runs with --prefix (a fake root: no
useradd/systemctl/chown/apt/runuser, "would run" lines instead) and vault-site runs against a fake helper socket.
  VAULT_TEST_SCRATCH  parent directory for the scratch files (default /tmp; unix socket paths must stay short)
Heavy: release.sh runs `npm ci` twice (helper, plugin) once per run; on a shared host run it under the host's job lock.
Run: python3 -I -B -m unittest discover -s tests/install"""
import base64
import hashlib
import importlib.util
import io
import json
import os
import shutil
import socketserver
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import unittest.mock
from importlib.machinery import SourceFileLoader

PKG = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
CODE = "WXYZ-2345-6789-ABCD"
COMPANY = "11111111-2222-4333-8444-555555555555"
AGENT = "00000000-0000-4000-8000-000000000002"
USER, PASSWORD, TOTP = "alice@example.org", "S3cr3t-Passw0rd!", "JBSWY3DPEHPK3PXP"
NEEDED = all(shutil.which(c) for c in ("curl", "sha256sum", "tar", "gzip", "bash", "npm", "python3"))
ME = subprocess.run(["id", "-un"], capture_output=True, text=True).stdout.strip()

SITE = {
    "schema": 1, "id": "example-admin", "displayName": "Example admin", "type": "password-totp", "kind": "test",
    "purpose": "QA login for the example app", "loginUrl": "https://app.example.org/login",
    "logoutUrl": "https://app.example.org/logout", "allowedHosts": ["app.example.org"], "allowedAgents": [AGENT],
    "roles": ["QA"], "maxMinutes": 60,
    "recipe": {"steps": [{"fill": "#email", "from": "username"}, {"click": "button[type=submit]"},
                         {"fill": "#password", "from": "password"}, {"click": "#login"},
                         {"fill": "#otp", "from": "totp", "optional": True}],
               "successCheck": {"urlMatches": "^https://app\\.example\\.org/dashboard"}, "timeoutSeconds": 45},
    "oauth": None,
}
INTERACTIVE = {
    "schema": 1, "id": "google-owner", "displayName": "Google owner", "type": "interactive", "kind": "owner",
    "purpose": "owner session", "loginUrl": "https://accounts.example.org/login", "logoutUrl": None,
    "allowedHosts": ["accounts.example.org"], "allowedAgents": [AGENT], "roles": ["Researcher"], "maxMinutes": 30,
    "recipe": {"successCheck": {"urlMatches": "^https://accounts\\.example\\.org/home"}}, "oauth": None,
}
OAUTH = {
    "schema": 1, "id": "tracker-api", "displayName": "Tracker API", "type": "oauth", "kind": "research",
    "purpose": "read the tracker", "loginUrl": None, "logoutUrl": None, "allowedHosts": ["api.example.org"],
    "allowedAgents": [AGENT], "roles": ["Researcher"], "maxMinutes": 30, "recipe": None,
    "oauth": {"flow": "device", "authUrl": "https://api.example.org/auth", "tokenUrl": "https://api.example.org/token",
              "deviceUrl": "https://api.example.org/device", "revokeUrl": None, "clientId": "cid", "scopes": ["read"]},
}

STUB_CREDS = r'''#!/usr/bin/env python3
"""Test double for systemd-creds: records argv and stdin, writes a blob that holds only the SHA-256 of the secret."""
import hashlib, os, sys
log = os.environ["STUB_CREDS_LOG"]
data = sys.stdin.buffer.read()
with open(log, "a") as f:
    f.write("\t".join(sys.argv[1:]) + "\n")
with open(log + ".stdin", "ab") as f:
    f.write(data + b"\n--\n")
dest = sys.argv[-1]
with open(dest, "w") as f:
    f.write("BLOB sha256=" + hashlib.sha256(data).hexdigest() + "\n")
'''


def sha(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


class FakeHelper:
    """A helper.sock stand-in: line JSON, the admin token required, every call recorded."""

    def __init__(self, path, token, handlers=None):
        self.calls, self.token, self.handlers = [], token, handlers or {}
        outer = self

        class H(socketserver.StreamRequestHandler):
            def handle(self):
                req = json.loads(self.rfile.readline())
                if req.pop("token", None) != outer.token:
                    reply = {"ok": False, "error": {"code": "unauthorized", "message": "wrong token"}}
                else:
                    op = req.pop("op")
                    outer.calls.append((op, req))
                    fn = outer.handlers.get(op)
                    reply = {"ok": True, "data": fn(req) if fn else {}}
                    if isinstance(reply["data"], Exception):
                        reply = {"ok": False, "error": {"code": reply["data"].args[0], "message": "no"}}
                self.wfile.write((json.dumps(reply) + "\n").encode())

        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.srv = socketserver.ThreadingUnixStreamServer(path, H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def ops(self):
        return [c[0] for c in self.calls]

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


@unittest.skipUnless(NEEDED, "curl, sha256sum, tar, gzip, bash, npm and python3 are needed")
class Installer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="vault-install-test-", dir=os.environ.get("VAULT_TEST_SCRATCH", "/tmp"))
        cls.dist = os.path.join(cls.tmp, "dist")
        r = subprocess.run(["bash", os.path.join(PKG, "scripts", "release.sh"), "--version", "9.9.9",
                            "--base-url", f"file://{cls.dist}/", "--out", cls.dist], capture_output=True, text=True)
        if r.returncode != 0:
            raise AssertionError(r.stderr)
        cls.release_out = r.stdout
        cls.n = 0
        cls.bin = os.path.join(cls.tmp, "bin")
        os.makedirs(cls.bin)
        cls.stub_log = os.path.join(cls.tmp, "creds.log")
        with open(os.path.join(cls.bin, "systemd-creds"), "w") as f:
            f.write(STUB_CREDS)
        os.chmod(os.path.join(cls.bin, "systemd-creds"), 0o755)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        Installer.n += 1
        self.root = os.path.join(self.tmp, f"r{self.n}")
        self.helpers = []
        self.addCleanup(lambda: [h.close() for h in self.helpers])
        for f in (self.stub_log, self.stub_log + ".stdin"):
            if os.path.exists(f):
                os.remove(f)

    # ------------------------------------------------------------------ plumbing
    def env(self, **extra):
        e = dict(os.environ)
        for k in ("VAULT_CREDS_KEY", "VAULT_INSTALL_PROBE_RESULT", "VAULT_INSTALL_NODE_CANDIDATES", "VAULT_BASE_URL"):
            e.pop(k, None)
        e.update(extra)
        return e

    def install(self, *args, dist=None, script="install-vault.sh", stub=False, **env):
        cmd = ["bash", os.path.join(dist or self.dist, script), "--prefix", self.root, *args]
        e = self.env(**env)
        if stub:
            e.update(PATH=self.bin + os.pathsep + e["PATH"], STUB_CREDS_LOG=self.stub_log, VAULT_CREDS_KEY="null")
        return subprocess.run(cmd, capture_output=True, text=True, env=e, stdin=subprocess.DEVNULL)

    def fresh(self, *extra, **kw):
        r = self.install("--service-user", ME, "--company", COMPANY, "--enrol", CODE, "--skip-deps", *extra, **kw)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r

    def p(self, rel):
        return os.path.join(self.root, rel.lstrip("/"))

    def read(self, rel):
        with open(self.p(rel), "rb") as f:
            return f.read()

    def json(self, rel):
        with open(self.p(rel)) as f:
            return json.load(f)

    def mode(self, rel):
        return os.stat(self.p(rel)).st_mode & 0o777

    def site_tool(self, *args, stdin=None, helper_dir=True, **env):
        cmd = ["python3", "-I", "-B", self.p("opt/vault/bin/vault-site"), "--prefix", self.root, *args]
        e = self.env(**env)
        e.update(PATH=self.bin + os.pathsep + e["PATH"], STUB_CREDS_LOG=self.stub_log, VAULT_CREDS_KEY="null")
        return subprocess.run(cmd, capture_output=True, text=True, env=e, input=stdin if stdin is not None else "", )

    def fake_helper(self, **handlers):
        token = self.read("etc/vault/helper-admin.token").decode().strip()
        h = FakeHelper(self.p("run/vault-helper/helper.sock"), token, handlers)
        self.helpers.append(h)
        return h

    def b64(self, site):
        return base64.b64encode(json.dumps(site).encode()).decode()

    # ------------------------------------------------------------------ release
    def test_release_assets_pins_and_reproducible_layout(self):
        names = sorted(os.listdir(self.dist))
        self.assertEqual(names, ["SHA256SUMS", "install-vault.sh", "paperclip-vault-host-9.9.9.tar.gz", "paperclip-vault-plugin-9.9.9.tgz"])
        self.assertEqual(subprocess.run(["sha256sum", "-c", "SHA256SUMS"], cwd=self.dist, capture_output=True).returncode, 0)
        with open(os.path.join(self.dist, "install-vault.sh")) as f:
            text = f.read()
        bundle = os.path.join(self.dist, "paperclip-vault-host-9.9.9.tar.gz")
        self.assertIn(f'BUNDLE_SHA256="{sha(bundle)}"', text)
        self.assertIn('VERSION="9.9.9"', text)
        self.assertIn(f'DEFAULT_BASE_URL="file://{self.dist}/"', text)
        self.assertRegex(text, r'NODE_VERSION="\d+\.\d+\.\d+"')
        self.assertRegex(text, r'NODE_X64_SHA256="[0-9a-f]{64}"')
        self.assertNotRegex(text, r"__[A-Z0-9_]+__")
        self.assertIn(f"{sha(os.path.join(self.dist, 'install-vault.sh'))}  install-vault.sh", self.release_out)
        # bundle: root-owned numbers, mtime 0, sorted, no links/tests/caches, helper dependencies vendored
        listing = subprocess.run(["tar", "-tvzf", bundle, "--numeric-owner"], capture_output=True, text=True).stdout.splitlines()
        self.assertTrue(all(" 0/0 " in l and "1970-01-01" in l for l in listing))
        self.assertFalse([l for l in listing if l[0] in "lh"])
        members = [l.split()[-1] for l in listing]
        self.assertEqual(members, sorted(members))
        for want in ("paperclip-vault-host/helper/node_modules/playwright-core/cli.js", "paperclip-vault-host/bin/vault-site",
                     "paperclip-vault-host/units/vault-helper.service", "paperclip-vault-host/install/probe-chromium.mjs",
                     "paperclip-vault-host/judge-tests/scenarios.jsonl", "paperclip-vault-host/VERSION"):
            self.assertIn(want, members)
        self.assertFalse([m for m in members if "__pycache__" in m or m.startswith(("paperclip-vault-host/helper/test/", "paperclip-vault-host/tests/"))])
        # plugin tarball: pins filled inside, working tree untouched, dependencies installed
        plugin = os.path.join(self.dist, "paperclip-vault-plugin-9.9.9.tgz")
        pins = json.loads(subprocess.run(["tar", "-xzOf", plugin, "plugin/src/release-pins.json"], capture_output=True, text=True).stdout)
        self.assertEqual((pins["version"], pins["baseUrl"]), ("9.9.9", f"file://{self.dist}/"))
        self.assertEqual(pins["installVaultSha256"], sha(os.path.join(self.dist, "install-vault.sh")))
        pnames = subprocess.run(["tar", "-tzf", plugin], capture_output=True, text=True).stdout.split()
        self.assertIn("plugin/node_modules/@paperclipai/plugin-sdk/package.json", pnames)
        self.assertIn("plugin/package.json", pnames)
        self.assertFalse([n for n in pnames if n.startswith("plugin/test/")])
        with open(os.path.join(PKG, "plugin", "src", "release-pins.json")) as f:
            self.assertIsNone(json.load(f)["installVaultSha256"])

    # ------------------------------------------------------------------ install
    def test_fresh_install_in_a_fake_root(self):
        r = self.fresh(stub=True)
        out = r.stdout + r.stderr
        self.assertNotIn(CODE, out)
        self.assertNotIn("PRIVATE KEY", out)
        for rel in ("opt/vault/vaultd/__main__.py", "opt/vault/helper/main.js", "opt/vault/helper/node_modules/playwright-core/cli.js",
                    "opt/vault/bin/vault-site", "opt/vault/bin/vaultctl", "opt/vault/sbin/vault-audit-rotate", "opt/vault/VERSION",
                    "opt/vault/judge-tests/scenarios.jsonl", "opt/vault/install/probe-chromium.mjs", "usr/local/sbin/vault-site",
                    "usr/local/sbin/vaultctl", "etc/vault/config.json", "etc/vault/helper.json", "etc/vault/helper.token",
                    "etc/vault/helper-admin.token", "etc/vault/policy.json", "etc/vault/enrol.json", "etc/vault/installed-by",
                    "etc/credstore.encrypted/vault-helper.storekey", "var/log/vault/audit.jsonl",
                    "etc/systemd/system/vaultd.service", "etc/systemd/system/vaultd.socket", "etc/systemd/system/vault-helper.service",
                    "etc/systemd/system/vault-audit-rotate.service", "etc/systemd/system/vault-audit-rotate.timer"):
            self.assertTrue(os.path.exists(self.p(rel)), rel)
        self.assertEqual(self.read("opt/vault/VERSION").strip(), b"9.9.9")
        self.assertFalse(os.path.exists(self.p("opt/vault/helper/test")))
        # modes
        for rel, mode in (("etc/vault/config.json", 0o640), ("etc/vault/helper.json", 0o640), ("etc/vault/helper.token", 0o640),
                          ("etc/vault/helper-admin.token", 0o600), ("etc/vault/policy.json", 0o640), ("etc/vault/enrol.json", 0o640),
                          ("etc/vault/installed-by", 0o600), ("etc/vault", 0o750), ("etc/vault/sites", 0o750),
                          ("etc/credstore.encrypted", 0o700), ("var/lib/vault", 0o700), ("var/lib/vault-helper", 0o700),
                          ("var/log/vault", 0o750), ("var/log/vault/audit.jsonl", 0o600), ("usr/local/sbin/vault-site", 0o755),
                          ("etc/systemd/system/vault-helper.service", 0o644), ("opt/vault", 0o755)):
            self.assertEqual(self.mode(rel), mode, rel)
        self.assertEqual(self.mode("opt/vault/bin/vault-site") & 0o022, 0)
        # owners and system changes are only printed
        for line in ("would run: groupadd --system vaultaudit",
                     "would run: useradd --system --user-group --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin vault",
                     "would run: useradd --system --user-group --home-dir /var/lib/vault-helper --no-create-home --shell /usr/sbin/nologin vault-helper",
                     "would run: chown root:vault /etc/vault",
                     "would run: chown root:vault /etc/vault/config.json", "would run: chown root:vault /etc/vault/helper.token",
                     "would run: chown root:root /etc/vault/helper-admin.token", "would run: chown root:vault /etc/vault/enrol.json",
                     "would run: chown vault:vault /var/lib/vault", "would run: chown vault-helper:vault-helper /var/lib/vault-helper",
                     "would run: chown -R root:root /opt/vault", "would run: chown vault:vault /var/log/vault/audit.jsonl",
                     "would run: chattr +a /var/log/vault/audit.jsonl",
                     "would run: runuser -u vault-helper -- env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/var/lib/vault-helper "
                     "PLAYWRIGHT_BROWSERS_PATH=/var/lib/vault-helper/browsers",
                     "would run: setfacl -m g:vaultaudit:r /var/log/vault/audit.jsonl",
                     "would run: systemctl daemon-reload",
                     "would run: systemctl enable vault-helper.service vaultd.socket vaultd.service vault-audit-rotate.timer",
                     "would run: systemctl restart vault-helper.service", "would run: systemctl restart vaultd.socket",
                     "would run: systemctl restart vaultd.service",
                     "would run: wait for /run/vault/plugin.sock"):
            self.assertIn(line, r.stdout)
        # config.json: the service user's uid, the company; helper.json: sandbox result and the admin token path
        cfg = self.json("etc/vault/config.json")
        self.assertEqual(cfg["plugin_uid"], os.getuid())
        self.assertEqual(cfg["allowed_company_ids"], [COMPANY])
        self.assertNotIn("plugin_group", cfg)
        hc = self.json("etc/vault/helper.json")
        self.assertEqual(hc, {"socketGroup": "vault", "allowNoSandbox": False,
                              "adminTokenFile": "/run/credentials/vault-helper.service/helper-admin.token"})
        # tokens are base64 of 32 bytes and differ
        t1, t2 = (self.read(f"etc/vault/{n}").decode() for n in ("helper.token", "helper-admin.token"))
        self.assertEqual(len(base64.b64decode(t1)), 32)
        self.assertEqual(len(base64.b64decode(t2)), 32)
        self.assertNotEqual(t1, t2)
        # enrol.json: the hash of the normalised code, never the code
        enrol = self.json("etc/vault/enrol.json")
        self.assertEqual(enrol["codeHash"], hashlib.sha256(("pcvault-enrol:" + CODE.replace("-", "")).encode()).hexdigest())
        self.assertRegex(enrol["installId"], r"^inst-[0-9a-f]{24}$")
        self.assertEqual(enrol["serviceUid"], os.getuid())
        self.assertRegex(enrol["expiresAt"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        left = time.mktime(time.strptime(enrol["expiresAt"], "%Y-%m-%dT%H:%M:%SZ")) - time.mktime(time.gmtime())
        self.assertTrue(60 * 60 - 120 < left <= 60 * 60 + 1, left)                # 60 minutes from when it was written
        for rel in ("etc/vault/enrol.json", "etc/vault/config.json", "etc/vault/helper.json", "etc/vault/installed-by"):
            self.assertNotIn(CODE.encode(), self.read(rel))
        # the store key went through systemd-creds on stdin, with the null key and the right name
        with open(self.stub_log) as f:
            self.assertIn("encrypt\t--with-key=null\t--name=vault-helper.storekey\t-\t", f.read())
        # units: the node is substituted, no placeholder left; the admin token is a credential
        unit = self.read("etc/systemd/system/vault-helper.service").decode()
        self.assertNotIn("@NODE@", unit)
        self.assertRegex(unit, r"(?m)^ExecStart=/\S+/node /opt/vault/helper/main\.js --config /etc/vault/helper\.json$")
        self.assertIn("LoadCredential=helper-admin.token:/etc/vault/helper-admin.token", unit)
        self.assertIn("ImportCredential=vault-helper.*", unit)
        self.assertIn("SupplementaryGroups=vault", unit)
        self.assertIn("exec /usr/bin/python3 -I /opt/vault/bin/vault-site", self.read("usr/local/sbin/vault-site").decode())
        manifest = self.read("etc/vault/installed-by").decode().split()
        for line in ("user:vault", "user:vault-helper", "group:vaultaudit", "path:/etc/vault", "path:/var/lib/vault",
                     "path:/var/lib/vault-helper", "path:/var/log/vault", "path:/etc/credstore.encrypted",
                     "cred:vault-helper.storekey"):
            self.assertIn(line, manifest)
        self.assertNotIn("group:vault-plugin", manifest)
        self.assertNotIn("path:/opt/vault", manifest)
        # the output ends with the fingerprint and the next step
        self.assertIn(f"fingerprint (sha256 of the host bundle): {sha(os.path.join(self.dist, 'paperclip-vault-host-9.9.9.tar.gz'))}", r.stdout)
        self.assertIn("complete the enrolment (up to 60 minutes)", r.stdout)
        self.assertIn("Chromium sandbox: active", r.stdout)
        # no group, no Paperclip restart; plugin.sock is a socket unit with an ACL entry for the service user
        self.assertNotIn("vault-plugin", r.stdout + r.stderr)
        self.assertNotIn("restart Paperclip", r.stdout + r.stderr)
        self.assertNotIn("usermod", r.stdout)
        vaultd_unit = self.read("etc/systemd/system/vaultd.service").decode()
        self.assertNotIn("vault-plugin", vaultd_unit)
        self.assertIn("Requires=vaultd.socket", vaultd_unit)
        sock = self.read("etc/systemd/system/vaultd.socket").decode()
        self.assertNotIn("@SVC@", sock)
        for line in ("ListenStream=/run/vault/plugin.sock", "SocketUser=vault", "SocketGroup=vault", "SocketMode=0600",
                     f"ExecStartPost=/usr/bin/setfacl -m u:{ME}:rw /run/vault/plugin.sock"):
            self.assertIn(line, sock.splitlines())
        self.assertEqual(self.mode("etc/systemd/system/vaultd.socket"), 0o644)
        # enrol.json is the last file written before the units start
        enrol_t = os.stat(self.p("etc/vault/enrol.json")).st_mtime_ns
        for base, _, files in os.walk(self.root):
            for n in files:
                if n not in ("enrol.json", "installed-by") and not n.startswith("enrol.json"):
                    self.assertLessEqual(os.lstat(os.path.join(base, n)).st_mtime_ns, enrol_t, os.path.join(base, n))

    def test_sandbox_probe_result_decides_allow_no_sandbox(self):
        r = self.fresh(VAULT_INSTALL_PROBE_RESULT="off")
        self.assertTrue(self.json("etc/vault/helper.json")["allowNoSandbox"])
        self.assertIn("--no-sandbox", r.stdout)
        r = self.install("--skip-deps", VAULT_INSTALL_PROBE_RESULT="none")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(self.json("etc/vault/helper.json")["allowNoSandbox"])
        self.assertIn("Chromium does not start", r.stderr)
        r = self.install("--skip-deps", VAULT_INSTALL_PROBE_RESULT="bogus")
        self.assertIn("must be on, off or none", r.stderr)

    def test_deps_are_installed_with_apt_or_listed_with_skip_deps(self):
        r = self.install("--service-user", ME, "--enrol", CODE)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("would run: apt-get update", r.stdout)
        self.assertIn("apt-get install -y --no-install-recommends xvfb x11vnc acl", r.stdout)
        self.assertIn("install-deps chromium", r.stdout)
        self.assertIn("allow a company with: sudo vaultctl company add", r.stdout)
        r = self.install("--service-user", ME, "--enrol", CODE, "--skip-deps")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("apt-get", r.stdout.replace("apt-get install xvfb", ""))
        self.assertIn("--skip-deps: not running apt", r.stdout)
        self.assertIn("apt-get install xvfb x11vnc acl", r.stdout)
        self.assertIn("install-deps chromium", r.stdout)
        self.assertIn("would run: runuser -u vault-helper", r.stdout, "Chromium itself is still installed")

    def test_rerun_is_idempotent_and_keeps_keys_policy_sites_and_credentials(self):
        self.fresh(stub=True)
        keep = {n: self.read(n) for n in ("etc/vault/helper.token", "etc/vault/helper-admin.token", "etc/credstore.encrypted/vault-helper.storekey",
                                          "etc/vault/enrol.json", "etc/vault/installed-by")}
        with open(self.p("etc/vault/policy.json"), "w") as f:
            f.write('{"agents": {}, "edited": true}')
        with open(self.p("etc/vault/sites/x.json"), "w") as f:
            f.write("{}")
        with open(self.p("etc/credstore.encrypted/vault-helper.site.x.password"), "w") as f:
            f.write("blob")
        cfg = self.json("etc/vault/config.json")
        cfg["verdict_timeout_s"] = 99                                       # an admin edit survives
        with open(self.p("etc/vault/config.json"), "w") as f:
            json.dump(cfg, f)
        other = "99999999-2222-4333-8444-555555555555"
        r = self.install("--company", other, "--skip-deps", stub=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        for n, data in keep.items():
            self.assertEqual(self.read(n), data, n)
        self.assertEqual(self.read("etc/vault/policy.json"), b'{"agents": {}, "edited": true}')
        self.assertEqual(self.read("etc/vault/sites/x.json"), b"{}")
        self.assertEqual(self.read("etc/credstore.encrypted/vault-helper.site.x.password"), b"blob")
        cfg = self.json("etc/vault/config.json")
        self.assertEqual(cfg["verdict_timeout_s"], 99)
        self.assertEqual(cfg["allowed_company_ids"], [COMPANY, other])
        self.assertEqual(cfg["plugin_uid"], os.getuid())
        self.assertNotIn("starter /etc/vault/policy.json", r.stdout)
        self.assertEqual(self.mode("etc/vault/helper-admin.token"), 0o600)
        # a new code replaces the enrolment record but keeps the install id
        old = self.json("etc/vault/enrol.json")
        r = self.install("--enrol", "ABCD-EFGH-JKMN-PQRS", "--skip-deps")
        self.assertEqual(r.returncode, 0, r.stderr)
        new = self.json("etc/vault/enrol.json")
        self.assertEqual(new["installId"], old["installId"])
        self.assertNotEqual(new["codeHash"], old["codeHash"])
        # the manifest does not grow duplicates
        lines = self.read("etc/vault/installed-by").decode().split()
        self.assertEqual(len(lines), len(set(lines)))

    def test_sha_mismatch_stops_before_anything_is_installed(self):
        bad = os.path.join(self.tmp, f"dist-bad-{self.n}")
        shutil.copytree(self.dist, bad)
        with open(os.path.join(bad, "paperclip-vault-host-9.9.9.tar.gz"), "ab") as f:
            f.write(b"\0")
        r = self.install("--service-user", ME, "--enrol", CODE, "--base-url", f"file://{bad}/")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("fingerprint does not match", r.stderr)
        for rel in ("opt/vault", "etc/vault", "var/lib/vault"):
            self.assertFalse(os.path.exists(self.p(rel)), rel)
        self.assertNotIn("would run", r.stdout)
        self.assertNotIn(CODE, r.stdout + r.stderr)

    def test_refusals(self):
        r = self.install("--service-user", ME, "--enrol", CODE, dist=os.path.join(PKG, "host", "install"))
        self.assertIn("not a release build", r.stderr)
        r = self.install("--service-user", ME, "--enrol", CODE, "--base-url", "http://example.invalid/")
        self.assertIn("must be https://", r.stderr)
        r = self.install("--service-user", ME, "--enrol", "bad code; rm -rf /")
        self.assertIn("malformed", r.stderr)
        self.assertNotIn("rm -rf", r.stderr)
        r = self.install("--service-user", ME, "--enrol", CODE, "--company", "not-a-uuid")
        self.assertIn("--company must be a Paperclip company UUID", r.stderr)
        r = self.install("--service-user", "root", "--enrol", CODE)
        self.assertIn("must be the account Paperclip runs as", r.stderr)
        r = self.install("--service-user", "no-such-user-xyz", "--enrol", CODE)
        self.assertIn("does not exist", r.stderr)
        r = self.install("--service-user", "Bad User", "--enrol", CODE)
        self.assertIn("not a valid user name", r.stderr)
        r = self.install("--enrol", CODE)
        self.assertIn("first install: --service-user U is required", r.stderr)
        r = self.install("--service-user", ME)
        self.assertIn("--enrol CODE is required", r.stderr)
        r = self.install("--purge")
        self.assertIn("--purge only goes with --uninstall", r.stderr)
        r = self.install("--frobnicate")
        self.assertIn("unknown option", r.stderr)
        self.assertFalse(os.path.exists(self.p("opt/vault")))
        if os.getuid() != 0:                    # without --prefix: root (sudo) only, and file:// only in a fake root
            r = subprocess.run(["bash", os.path.join(self.dist, "install-vault.sh"), "--service-user", ME, "--enrol", CODE],
                               capture_output=True, text=True, env=self.env())
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("run this with sudo", r.stderr)
        r = self.install("--service-user", ME, "--enrol", CODE, "--base-url", f"file://{self.dist}/", "--prefix", "relative/dir")
        self.assertIn("must be an absolute path", r.stderr)

    def test_prefix_must_be_a_real_directory_that_is_not_the_root(self):
        base = ["--service-user", ME, "--enrol", CODE, "--skip-deps"]
        for bad in ("/", "//", "///", "/./", "/.", "/..", "/tmp/..", "/tmp/../", "//./"):
            r = subprocess.run(["bash", os.path.join(self.dist, "install-vault.sh"), "--prefix", bad, *base],
                               capture_output=True, text=True, env=self.env(), stdin=subprocess.DEVNULL)
            self.assertNotEqual(r.returncode, 0, bad)
            self.assertIn("must not be /", r.stderr, bad)
            self.assertNotIn("run this with sudo", r.stderr, bad)         # it must not fall through to the live-install path
            self.assertNotIn("would run", r.stdout, bad)
        r = self.install("--service-user", ME, "--enrol", CODE, "--prefix", "/tmp/with space")
        self.assertIn("--prefix may only hold", r.stderr)
        afile = os.path.join(self.tmp, "afile")
        with open(afile, "w") as f:
            f.write("x")
        r = subprocess.run(["bash", os.path.join(self.dist, "install-vault.sh"), "--prefix", afile, *base],
                           capture_output=True, text=True, env=self.env(), stdin=subprocess.DEVNULL)
        self.assertIn("is not a directory", r.stderr)
        r = subprocess.run(["bash", os.path.join(self.dist, "install-vault.sh"), "--prefix", afile + "/sub", *base],
                           capture_output=True, text=True, env=self.env(), stdin=subprocess.DEVNULL)
        self.assertIn("cannot be created", r.stderr)
        # a non-normal spelling of a good directory is accepted and normalised
        odd = self.root + "//sub/../"
        os.makedirs(self.root, exist_ok=True)
        r = subprocess.run(["bash", os.path.join(self.dist, "install-vault.sh"), "--prefix", odd, *base],
                           capture_output=True, text=True, env=self.env(), stdin=subprocess.DEVNULL)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.exists(self.p("etc/vault/config.json")))
        # vault-site: the same rule
        for bad in ("/", "//", "/./"):
            r = subprocess.run(["python3", "-I", "-B", os.path.join(PKG, "host", "bin", "vault-site"), "--prefix", bad, "list"],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 2, bad)
            self.assertIn("must not be /", r.stderr)

    def test_unfilled_placeholders_are_refused_by_name(self):
        with open(os.path.join(self.dist, "install-vault.sh")) as f:
            text = f.read()
        for var, shown in (("NODE_VERSION", "Node version"), ("NODE_X64_SHA256", "Node x64"), ("NODE_ARM64_SHA256", "Node arm64"),
                           ("VERSION", "no version"), ("DEFAULT_BASE_URL", "download URL")):
            import re
            broken = re.sub(r'(?m)^%s="[^"]*"' % var, '%s="__%s__"' % (var, var), text)
            self.assertNotEqual(broken, text, var)
            path = os.path.join(self.tmp, f"unfilled-{var}.sh")
            with open(path, "w") as f:
                f.write(broken)
            r = subprocess.run(["bash", path, "--prefix", self.root, "--service-user", ME, "--enrol", CODE, "--skip-deps"],
                               capture_output=True, text=True, env=self.env(), stdin=subprocess.DEVNULL)
            self.assertNotEqual(r.returncode, 0, var)
            self.assertIn("not a release build", r.stderr, var)
            self.assertIn(shown, r.stderr, var)
        self.assertFalse(os.path.exists(self.p("opt/vault")))

    def test_special_files_in_the_bundle_are_refused(self):
        bundle = os.path.join(self.dist, "paperclip-vault-host-9.9.9.tar.gz")
        for kind in ("fifo", "chardev", "dir-ok"):
            work = os.path.join(self.tmp, f"evil-{kind}-{self.n}")
            os.makedirs(os.path.join(work, "x"))
            subprocess.run(["tar", "-xzf", bundle, "-C", os.path.join(work, "x")], check=True)
            host = os.path.join(work, "x", "paperclip-vault-host")
            if kind == "fifo":
                os.mkfifo(os.path.join(host, "bin", "pipe"))
            elif kind == "chardev":
                if os.getuid() != 0:
                    continue                                   # mknod needs root; the FIFO case covers the check
                os.mknod(os.path.join(host, "bin", "dev"), 0o600 | stat.S_IFCHR, os.makedev(1, 3))
            else:
                os.makedirs(os.path.join(host, "bin", "emptydir"))
            evil = os.path.join(work, "dist")
            os.makedirs(evil)
            subprocess.run(["tar", "--sort=name", "--owner=0", "--group=0", "--numeric-owner", "-C", os.path.join(work, "x"), "-czf",
                            os.path.join(evil, "paperclip-vault-host-9.9.9.tar.gz"), "paperclip-vault-host"], check=True)
            with open(os.path.join(self.dist, "install-vault.sh")) as f:
                text = f.read()
            new_sha = sha(os.path.join(evil, "paperclip-vault-host-9.9.9.tar.gz"))
            with open(os.path.join(evil, "install-vault.sh"), "w") as f:
                f.write(text.replace(f'BUNDLE_SHA256="{sha(bundle)}"', f'BUNDLE_SHA256="{new_sha}"'))
            root = os.path.join(self.tmp, f"evilroot-{kind}-{self.n}")
            r = subprocess.run(["bash", os.path.join(evil, "install-vault.sh"), "--prefix", root, "--service-user", ME, "--enrol", CODE,
                                "--skip-deps", "--base-url", f"file://{evil}/"], capture_output=True, text=True, env=self.env(),
                               stdin=subprocess.DEVNULL)
            if kind == "dir-ok":
                self.assertEqual(r.returncode, 0, r.stderr)
            else:
                self.assertNotEqual(r.returncode, 0, kind)
                self.assertIn("links, devices, FIFOs or other special files", r.stderr, kind)
                self.assertFalse(os.path.exists(os.path.join(root, "opt")), "nothing was installed")

    def test_the_node_must_be_root_owned_and_never_under_a_home(self):
        d = tempfile.mkdtemp(prefix="vault-node-", dir=os.environ.get("VAULT_TEST_SCRATCH", "/tmp"))
        self.addCleanup(shutil.rmtree, d, True)

        def fake(name, version):
            path = os.path.join(d, name)
            with open(path, "w") as f:
                f.write(f"#!/bin/sh\necho {version}\n")
            os.chmod(path, 0o755)
            return path

        good = os.path.realpath(fake("node24", "24.3.0"))
        r = self.install("--service-user", ME, "--enrol", CODE, "--skip-deps", "--node", good)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(f"ExecStart={good} /opt/vault/helper/main.js", self.read("etc/systemd/system/vault-helper.service").decode())
        r = self.install("--service-user", ME, "--enrol", CODE, "--skip-deps", "--node", fake("node23", "23.9.0"))
        self.assertIn("Node 23.9.0; 24 or newer is needed", r.stderr)
        r = self.install("--service-user", ME, "--enrol", CODE, "--skip-deps", "--node", os.path.join(d, "missing"))
        self.assertIn("not an executable file", r.stderr)
        home = os.path.expanduser("~")
        if home.startswith("/home/") and os.access(home, os.W_OK):
            h = tempfile.mkdtemp(prefix="vault-node-home-", dir=home)
            self.addCleanup(shutil.rmtree, h, True)
            shutil.copy(good, os.path.join(h, "node"))
            link = os.path.join(d, "node-link")
            os.symlink(os.path.join(h, "node"), link)               # a link into a home does not help either
            for cand in (os.path.join(h, "node"), link):
                root_before = os.path.exists(self.p("opt/vault/units"))
                r = self.install("--service-user", ME, "--enrol", CODE, "--skip-deps", "--node", cand)
                self.assertNotEqual(r.returncode, 0)
                self.assertIn("home directory", r.stderr)
                self.assertEqual(os.path.exists(self.p("opt/vault/units")), root_before)
        else:
            self.skipTest("the test user's home is not under /home")

    def test_a_host_without_a_usable_node_vendors_the_pinned_tarball(self):
        r = self.install("--service-user", ME, "--enrol", CODE, "--skip-deps", VAULT_INSTALL_NODE_CANDIDATES="")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("vendoring Node", r.stdout)
        with open(os.path.join(self.dist, "install-vault.sh")) as f:
            text = f.read()
        with open(os.path.join(PKG, "scripts", "node-pin.env")) as f:
            pin = dict(l.split("=") for l in f.read().split("\n") if l and l[0] != "#")
        arch = "x64" if os.uname().machine == "x86_64" else "arm64"
        self.assertIn(f"would run: curl -fsSL --proto =https https://nodejs.org/dist/v{pin['NODE_VERSION']}/node-v{pin['NODE_VERSION']}-linux-{arch}.tar.xz "
                      f"(sha256 {pin['NODE_' + arch.upper() + '_SHA256']})", r.stdout)
        self.assertIn("ExecStart=/opt/vault/node/bin/node /opt/vault/helper/main.js", self.read("etc/systemd/system/vault-helper.service").decode())
        self.assertIn(f'NODE_VERSION="{pin["NODE_VERSION"]}"', text)

    def test_uninstall_keeps_data_and_purge_removes_only_what_the_installer_created(self):
        self.fresh(stub=True)
        with open(self.p("etc/vault/sites/x.json"), "w") as f:
            f.write("{}")
        with open(self.p("etc/credstore.encrypted/vault.github-ro"), "w") as f:
            f.write("blob")                                               # the admin's own credential, never the installer's
        os.makedirs(self.p("run/vault"))
        r = self.install("--uninstall")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("would run: systemctl disable --now vault-audit-rotate.timer vaultd.socket vaultd.service vault-helper.service", r.stdout)
        self.assertNotIn("userdel", r.stdout)
        for rel in ("opt/vault", "usr/local/sbin/vault-site", "usr/local/sbin/vaultctl", "run/vault"):
            self.assertFalse(os.path.exists(self.p(rel)), rel)
        self.assertEqual(os.listdir(self.p("etc/systemd/system")), [])
        for rel in ("etc/vault/config.json", "etc/vault/policy.json", "etc/vault/sites/x.json", "etc/vault/helper.token",
                    "etc/credstore.encrypted/vault-helper.storekey", "etc/credstore.encrypted/vault.github-ro",
                    "var/lib/vault", "var/lib/vault-helper", "var/log/vault/audit.jsonl", "etc/vault/installed-by"):
            self.assertTrue(os.path.exists(self.p(rel)), rel)
        self.assertIn("kept:", r.stdout)
        self.assertIn("Plugins", r.stdout)
        self.assertEqual(self.install("--uninstall").returncode, 0, "idempotent")
        # a reinstall resumes with the same keys
        token = self.read("etc/vault/helper-admin.token")
        self.assertEqual(self.install("--skip-deps", stub=True).returncode, 0)
        self.assertEqual(self.read("etc/vault/helper-admin.token"), token)
        # purge: what was created goes, the admin's own vault.* blob stays (so does the directory that holds it)
        r = self.install("--uninstall", "--purge")
        self.assertEqual(r.returncode, 0, r.stderr)
        for line in ("would run: userdel vault", "would run: userdel vault-helper", "would run: groupdel vaultaudit",
                     "would run: find /var/log/vault -maxdepth 1 -type f -exec chattr -a {} +"):
            self.assertIn(line, r.stdout)
        self.assertNotIn("groupdel vault\n", r.stdout)
        for rel in ("etc/vault", "etc/credstore.encrypted/vault-helper.storekey", "var/lib/vault", "var/lib/vault-helper", "var/log/vault"):
            self.assertFalse(os.path.exists(self.p(rel)), rel)
        self.assertEqual(os.listdir(self.p("etc/credstore.encrypted")), ["vault.github-ro"])
        self.assertIn("purged what this installer created", r.stdout)
        self.assertIn("kept, because it was there before", r.stdout)
        self.assertIn("vault.*", r.stdout)

    def test_purge_keeps_everything_that_was_there_before(self):
        # a vault from a hand install: /etc/vault with content, the audit log, a vault.* credential, and the log directory
        for rel, data in (("etc/vault/policy.json", b'{"mine": true}'), ("etc/vault/notes.txt", b"keep me"),
                          ("var/log/vault/audit.jsonl", b'{"event":"old"}\n'), ("etc/credstore.encrypted/vault.github-ro", b"blob"),
                          ("var/lib/vault/ledger.db", b"ledger")):
            os.makedirs(os.path.dirname(self.p(rel)), exist_ok=True)
            with open(self.p(rel), "wb") as f:
                f.write(data)
        self.fresh(stub=True)
        manifest = self.read("etc/vault/installed-by").decode().split()
        for line in ("path:/etc/vault", "path:/var/log/vault", "path:/var/log/vault/audit.jsonl", "path:/etc/vault/policy.json",
                     "path:/var/lib/vault", "path:/etc/credstore.encrypted"):
            self.assertNotIn(line, manifest, "it was there before")
        for line in ("path:/etc/vault/config.json", "path:/etc/vault/sites", "path:/var/lib/vault-helper", "cred:vault-helper.storekey"):
            self.assertIn(line, manifest)
        self.assertEqual(self.read("var/log/vault/audit.jsonl"), b'{"event":"old"}\n', "an existing audit log is not touched")
        r = self.install("--uninstall", "--purge")
        self.assertEqual(r.returncode, 0, r.stderr)
        for rel, data in (("etc/vault/policy.json", b'{"mine": true}'), ("etc/vault/notes.txt", b"keep me"),
                          ("var/log/vault/audit.jsonl", b'{"event":"old"}\n'), ("etc/credstore.encrypted/vault.github-ro", b"blob"),
                          ("var/lib/vault/ledger.db", b"ledger")):
            self.assertEqual(self.read(rel), data, rel)
        for rel in ("etc/vault/config.json", "etc/vault/helper.json", "etc/vault/helper.token", "etc/vault/helper-admin.token",
                    "etc/vault/enrol.json", "etc/vault/sites", "var/lib/vault-helper", "etc/credstore.encrypted/vault-helper.storekey",
                    "etc/vault/installed-by"):
            self.assertFalse(os.path.exists(self.p(rel)), rel)
        self.assertNotIn("find /var/log/vault -maxdepth 1", r.stdout, "the append-only flag of a log that is not ours is not touched")
        self.assertIn("kept, because it was there before", r.stdout)
        self.assertIn("/etc/vault", r.stdout.split("kept, because it was there before")[1])
        self.assertIn("/var/log/vault", r.stdout.split("kept, because it was there before")[1])

    def test_a_failing_chattr_does_not_abort_the_purge_halfway(self):
        self.fresh(stub=True)
        r = self.install("--uninstall", "--purge", VAULT_INSTALL_FAIL="chattr")
        self.assertEqual(r.returncode, 1, "reported, not hidden")
        self.assertIn("PURGE INCOMPLETE", r.stderr)
        self.assertIn("chattr -a", r.stderr)
        # everything else was still done: accounts, the other directories
        for line in ("would run: userdel vault", "would run: userdel vault-helper", "would run: groupdel vaultaudit"):
            self.assertIn(line, r.stdout)
        for rel in ("etc/vault", "var/lib/vault", "var/lib/vault-helper", "etc/credstore.encrypted"):
            self.assertFalse(os.path.exists(self.p(rel)), rel)
        # a failing userdel is reported too
        self.fresh(stub=True)
        os.makedirs(self.p("run"), exist_ok=True)
        r = self.install("--uninstall", "--purge", VAULT_INSTALL_FAIL="userdel")
        self.assertEqual(r.returncode, 1)
        self.assertIn("removing account vault", r.stderr)
        self.assertNotIn("kept:", r.stdout)

    def test_purge_ignores_manifest_entries_outside_the_allow_list(self):
        self.fresh(stub=True)
        victim = os.path.join(self.tmp, f"victim{self.n}")
        os.makedirs(victim)
        with open(self.p("etc/vault/installed-by"), "a") as f:
            f.write(f"path:{victim}\npath:/etc/vault/../../..\ncred:vault.github-ro\npath:/\n")
        with open(self.p("etc/credstore.encrypted/vault.github-ro"), "w") as f:
            f.write("blob")
        r = self.install("--uninstall", "--purge")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.isdir(victim))
        self.assertTrue(os.path.exists(self.p("etc/credstore.encrypted/vault.github-ro")))
        self.assertIn("ignoring an unexpected manifest entry", r.stderr)

    # ------------------------------------------------------------------ vault-site
    def installed(self):
        self.fresh(stub=True)

    def test_add_encrypts_through_stdin_and_never_prints_a_secret(self):
        self.installed()
        secrets = json.dumps({"username": USER, "password": PASSWORD, "totp": TOTP})
        r = self.site_tool("add", "--site-json-b64", self.b64(SITE), "--stdin-secrets", "--no-test", stdin=secrets)
        self.assertEqual(r.returncode, 0, r.stderr)
        out = r.stdout + r.stderr
        for secret in (USER, PASSWORD, TOTP):
            self.assertNotIn(secret, out)
        self.assertIn("site example-admin (password-totp)", r.stdout)
        # blobs exist, named as the helper expects, and went through the stub on stdin
        for part, value in (("username", USER), ("password", PASSWORD), ("totp", TOTP)):
            blob = f"etc/credstore.encrypted/vault-helper.site.example-admin.{part}"
            self.assertEqual(self.mode(blob), 0o600)
            self.assertEqual(self.read(blob).decode().strip(), "BLOB sha256=" + hashlib.sha256(value.encode()).hexdigest())
        with open(self.stub_log) as f:
            calls = [l.rstrip("\n").split("\t") for l in f if "example-admin" in l]
        self.assertEqual(len(calls), 3)
        for argv in calls:
            self.assertEqual(argv[:2], ["encrypt", "--with-key=null"])
            self.assertTrue(argv[2].startswith("--name=vault-helper.site.example-admin."))
            self.assertEqual(argv[3], "-")
            for secret in (USER, PASSWORD, TOTP):
                self.assertFalse(any(secret in a for a in argv), "a secret in argv")
        # the plaintext is nowhere in the fake root, and no temp file was left
        for base, _, files in os.walk(self.root):
            for name in files:
                with open(os.path.join(base, name), "rb") as f:
                    data = f.read()
                self.assertNotIn(PASSWORD.encode(), data, os.path.join(base, name))
                self.assertNotIn(TOTP.encode(), data, os.path.join(base, name))
        self.assertEqual(sorted(os.listdir(self.p("etc/vault/sites"))), ["example-admin.json"])
        self.assertEqual(self.mode("etc/vault/sites/example-admin.json"), 0o640)
        self.assertEqual(self.json("etc/vault/sites/example-admin.json")["id"], "example-admin")
        self.assertIn("would run: chown root:vault /etc/vault/sites/example-admin.json", r.stdout)
        self.assertIn("would run: systemctl restart vault-helper.service", r.stdout)
        # no tty and no --stdin-secrets: refused; an existing id: refused
        r = self.site_tool("add", "--site-json-b64", self.b64(dict(SITE, id="other")))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("needs a terminal", r.stderr)
        self.assertFalse(os.path.exists(self.p("etc/vault/sites/other.json")))
        r = self.site_tool("add", "--site-json-b64", self.b64(SITE), "--stdin-secrets", "--no-test", stdin=secrets)
        self.assertIn("exists already", r.stderr)
        r = self.site_tool("list")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertRegex(r.stdout, r"example-admin\s+password-totp\s+test\s+app\.example\.org\s+agents 1\s+credentials ok")

    def test_add_validates_and_with_real_systemd_creds_when_it_works(self):
        self.installed()
        r = self.site_tool("add", "--site-json-b64", self.b64(dict(SITE, type="nonsense")), "--stdin-secrets", stdin="{}")
        self.assertIn("the site file is invalid", r.stderr)
        r = self.site_tool("add", "--site-json-b64", self.b64(SITE), "--stdin-secrets", "--no-test",
                           stdin=json.dumps({"username": USER, "password": PASSWORD, "totp": "short"}))
        self.assertIn("TOTP seed must be a base32", r.stderr)
        self.assertEqual(os.listdir(self.p("etc/vault/sites")), [])
        r = self.site_tool("add", "--site-file", os.path.join(self.tmp, "nope.json"), "--stdin-secrets", stdin="{}")
        self.assertNotEqual(r.returncode, 0)
        # --no-totp
        r = self.site_tool("add", "--site-json-b64", self.b64(SITE), "--stdin-secrets", "--no-test", "--no-totp",
                           stdin=json.dumps({"username": USER, "password": PASSWORD}))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(os.path.exists(self.p("etc/credstore.encrypted/vault-helper.site.example-admin.totp")))
        # the real systemd-creds with the null key, where this host lets a normal user run it
        probe = subprocess.run(["systemd-creds", "encrypt", "--with-key=null", "--name=t", "-", os.path.join(self.tmp, "probe.blob")],
                               input=b"x", capture_output=True) if shutil.which("systemd-creds") else None
        if probe is None or probe.returncode != 0:
            self.skipTest("systemd-creds --with-key=null does not work without root on this host")
        root2 = os.path.join(self.tmp, f"real{self.n}")
        env = self.env(VAULT_CREDS_KEY="null")
        r = subprocess.run(["python3", "-I", "-B", self.p("opt/vault/bin/vault-site"), "--prefix", root2, "add", "--stdin-secrets", "--no-test",
                            "--site-json-b64", self.b64(SITE)], capture_output=True, text=True, env=env,
                           input=json.dumps({"username": USER, "password": PASSWORD, "totp": TOTP}))
        self.assertEqual(r.returncode, 0, r.stderr)
        blob = os.path.join(root2, "etc/credstore.encrypted/vault-helper.site.example-admin.password")
        with open(blob, "rb") as f:
            self.assertNotIn(PASSWORD.encode(), f.read())

    def test_add_runs_the_login_test_and_asks_for_a_challenge_code(self):
        self.installed()
        h = self.fake_helper(**{"site.test": lambda p: {"state": "challenge", "handle": "chl_abcdef0123456789"},
                                "challenge.submit": lambda p: {"state": "ok", "trustUsed": False, "loggedOut": True}})
        secrets = json.dumps({"username": USER, "password": PASSWORD, "totp": TOTP, "code": "123456"})
        r = self.site_tool("add", "--site-json-b64", self.b64(SITE), "--stdin-secrets", stdin=secrets)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(h.ops(), ["site.test", "challenge.submit"])
        self.assertEqual(h.calls[0][1], {"siteId": "example-admin", "attended": False})
        self.assertEqual(h.calls[1][1], {"handle": "chl_abcdef0123456789", "code": "123456"})
        self.assertIn("login test for example-admin passed", r.stdout)
        self.assertNotIn(PASSWORD, r.stdout + r.stderr)
        # test --attended: the same prompt; a failing helper answer is reported with its code
        r = self.site_tool("test", "example-admin", "--attended", "--stdin-secrets", stdin=json.dumps({"code": "654321"}))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(h.calls[2][1], {"siteId": "example-admin", "attended": True})
        h.handlers["site.test"] = lambda p: Exception("login_failed")
        r = self.site_tool("test", "example-admin")
        self.assertEqual(r.returncode, 1)
        self.assertIn("login_failed", r.stderr)
        # a wrong admin token is not accepted by the helper (the tool reads the installed token)
        with open(self.p("etc/vault/helper-admin.token"), "w") as f:
            f.write("tampered")
        r = self.site_tool("test", "example-admin")
        self.assertIn("unauthorized", r.stderr)

    def test_remove_wipes_files_leases_and_helper_state(self):
        self.installed()
        secrets = json.dumps({"username": USER, "password": PASSWORD, "totp": TOTP})
        self.assertEqual(self.site_tool("add", "--site-json-b64", self.b64(SITE), "--stdin-secrets", "--no-test", stdin=secrets).returncode, 0)
        h = self.fake_helper(**{"site.forget": lambda p: {"forgotten": True}})
        revoked = []
        admin_path = self.p("run/vault/admin.sock")
        os.makedirs(os.path.dirname(admin_path))
        admin = FakeAdmin(admin_path, [{"leaseId": "lse_aaaaaaaaaaaaaaaa", "target": "web-example-admin"},
                                       {"leaseId": "lse_bbbbbbbbbbbbbbbb", "target": "web-other"}], revoked)
        self.addCleanup(admin.close)
        r = self.site_tool("remove", "example-admin", "--keep-creds")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(revoked, ["lse_aaaaaaaaaaaaaaaa"])
        self.assertEqual(h.ops(), ["site.forget"])
        self.assertEqual(h.calls[0][1], {"siteId": "example-admin"})
        self.assertFalse(os.path.exists(self.p("etc/vault/sites/example-admin.json")))
        self.assertTrue(os.path.exists(self.p("etc/credstore.encrypted/vault-helper.site.example-admin.password")), "--keep-creds")
        self.assertIn("would run: systemctl restart vault-helper.service", r.stdout)
        r = self.site_tool("remove", "example-admin")
        self.assertIn("no site example-admin", r.stderr)
        # without --keep-creds the blobs go
        self.assertEqual(self.site_tool("add", "--site-json-b64", self.b64(SITE), "--stdin-secrets", "--no-test", "--replace",
                                        stdin=secrets).returncode, 0)
        self.assertEqual(self.site_tool("remove", "example-admin").returncode, 0)
        self.assertEqual(os.listdir(self.p("etc/credstore.encrypted")), ["vault-helper.storekey"])
        self.assertEqual(self.site_tool("list").stdout.strip().startswith("no sites yet"), True)

    def test_interactive_asks_before_accepting_a_site_without_logout(self):
        self.installed()
        self.assertEqual(self.site_tool("add", "--site-json-b64", self.b64(INTERACTIVE), "--stdin-secrets", stdin="{}").returncode, 0)
        self.assertEqual(os.listdir(self.p("etc/credstore.encrypted")), ["vault-helper.storekey"], "no credentials for interactive sites")
        seen = []
        h = self.fake_helper(**{"site.reload": lambda p: seen.append(self.json("etc/vault/sites/google-owner.json").get("acceptNoLogout")) or {},
                                "interactive.start": lambda p: {"display": ":99", "vncPort": 5901, "vncPassword": "vncpw123",
                                                               "expiresAt": "2099-01-01T00:00:00Z"},
                                "interactive.finish": lambda p: {"stored": True, "cookies": 7}})
        r = self.site_tool("interactive", "google-owner", "--stdin-secrets", stdin=json.dumps({"acceptNoLogout": "n"}))
        self.assertEqual(r.returncode, 1)
        self.assertIn("not accepted", r.stderr)
        self.assertEqual(h.calls, [])
        self.assertNotIn("acceptNoLogout", self.json("etc/vault/sites/google-owner.json"))
        r = self.site_tool("interactive", "google-owner", "--stdin-secrets", stdin=json.dumps({"acceptNoLogout": "y"}))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(self.json("etc/vault/sites/google-owner.json")["acceptNoLogout"])
        self.assertEqual(seen, [True], "the helper is told to reload after the file is written, and sees the change")
        self.assertEqual(h.ops(), ["site.reload", "interactive.start", "interactive.finish"])
        self.assertEqual(h.calls[1][1], {"siteId": "google-owner", "minutes": 15})
        self.assertIn("vncpw123", r.stdout)
        self.assertRegex(r.stdout, r"ssh -L 5900:127\.0\.0\.1:5901 \S+@\S+")
        self.assertIn("login stored for google-owner (7 cookies)", r.stdout)
        # import-session
        state = os.path.join(self.tmp, f"state{self.n}.json")
        with open(state, "w") as f:
            json.dump({"cookies": [{"name": "sid", "value": "v", "domain": "accounts.example.org", "path": "/"}], "origins": []}, f)
        h.handlers["session.import"] = lambda p: {"imported": True, "cookies": 1}
        r = self.site_tool("import-session", "google-owner", "--file", state)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(h.calls[-1][0], "session.import")
        self.assertEqual(h.calls[-1][1]["siteId"], "google-owner")
        self.assertNotIn('"v"', r.stdout)
        with open(state, "w") as f:
            f.write('{"cookies": []}')
        self.assertIn("non-empty 'cookies'", self.site_tool("import-session", "google-owner", "--file", state).stderr)

    def test_authorize_prints_the_device_code_or_the_ssh_line(self):
        self.installed()
        self.assertEqual(self.site_tool("add", "--site-json-b64", self.b64(OAUTH), "--stdin-secrets",
                                        stdin=json.dumps({"oauth-client-secret": "CLIENT-SECRET-XYZ"})).returncode, 0)
        with open(self.stub_log + ".stdin", "rb") as f:
            self.assertIn(b"CLIENT-SECRET-XYZ", f.read())
        h = self.fake_helper(**{"oauth.start": lambda p: {"handle": "oah_0123456789abcdef", "userCode": "ABCD-EFGH",
                                                         "verificationUri": "https://api.example.org/device", "interval": 5},
                                "oauth.finish": lambda p: {"authorized": True, "scopes": ["read"]}})
        r = self.site_tool("authorize", "tracker-api")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("ABCD-EFGH", r.stdout)
        self.assertIn("https://api.example.org/device", r.stdout)
        self.assertEqual(h.calls[0][1], {"siteId": "tracker-api", "flow": "device"})
        self.assertNotIn("CLIENT-SECRET-XYZ", r.stdout + r.stderr)
        # redirect flow
        site = json.loads(json.dumps(OAUTH))
        site.update(id="tracker-web")
        site["oauth"]["flow"] = "redirect"
        self.assertEqual(self.site_tool("add", "--site-json-b64", self.b64(site), "--stdin-secrets", stdin="{}").returncode, 0)
        h.handlers["oauth.start"] = lambda p: {"handle": "oah_0123456789abcdef", "authUrl": "https://api.example.org/auth?x=1",
                                               "listen": {"host": "127.0.0.1", "port": 8765}}
        r = self.site_tool("authorize", "tracker-web", "--redirect", "8765")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(h.calls[-2][1], {"siteId": "tracker-web", "flow": "redirect", "port": 8765})
        self.assertRegex(r.stdout, r"ssh -L 8765:127\.0\.0\.1:8765 \S+@\S+")
        self.assertIn("https://api.example.org/auth?x=1", r.stdout)
        self.assertIn("--redirect belongs to", self.site_tool("authorize", "tracker-api", "--redirect", "9").stderr)

    def vault_site_module(self):
        path = os.path.join(PKG, "host", "bin", "vault-site")
        sys.dont_write_bytecode = True
        spec = importlib.util.spec_from_loader("vault_site_under_test", SourceFileLoader("vault_site_under_test", path))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_helper_error_codes_get_a_clear_next_step(self):
        self.installed()
        self.assertEqual(self.site_tool("add", "--site-json-b64", self.b64(SITE), "--stdin-secrets", "--no-test",
                                        stdin=json.dumps({"username": USER, "password": PASSWORD, "totp": TOTP})).returncode, 0)
        h = self.fake_helper()
        want = {"needs_authorize": "vault-site authorize example-admin", "oauth_denied": "was denied at the provider",
                "oauth_error": "answered with an error", "dependency_missing": "apt-get install xvfb x11vnc",
                "needs_interactive": "vault-site interactive example-admin", "needs_owner_ack": "answer y"}
        for code, text in want.items():
            h.handlers["site.test"] = lambda p, code=code: Exception(code)
            r = self.site_tool("test", "example-admin")
            self.assertEqual(r.returncode, 1, code)
            self.assertIn(text, r.stderr, code)
            self.assertIn(code, r.stderr, "the helper's own code stays visible")
            self.assertNotIn("Traceback", r.stderr)
        self.assertNotIn(PASSWORD, r.stdout + r.stderr)

    def test_oauth_finish_waits_as_long_as_the_code_lives_at_most_30_minutes(self):
        m = self.vault_site_module()
        iso = lambda t: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))
        self.assertEqual(m.oauth_wait({"expires_in": 600}), 600 + m.OAUTH_WAIT_SLACK)
        self.assertEqual(m.oauth_wait({"expires_in": 5 * 3600}), 30 * 60, "capped")
        self.assertAlmostEqual(m.oauth_wait({"expiresAt": iso(time.time() + 1500)}), 1500 + m.OAUTH_WAIT_SLACK, delta=3)
        self.assertEqual(m.oauth_wait({"expiresAt": iso(time.time() + 86400)}), 30 * 60)
        for junk in ({}, {"expires_in": 0}, {"expires_in": -5}, {"expires_in": "9"}, {"expires_in": True}, {"expiresAt": "soon"},
                     {"expiresAt": iso(time.time() - 60)}):
            self.assertEqual(m.oauth_wait(junk), 15 * 60, junk)
        # end to end through cmd_authorize: the timeout handed to the socket call
        self.installed()
        self.assertEqual(self.site_tool("add", "--site-json-b64", self.b64(OAUTH), "--stdin-secrets", stdin="{}").returncode, 0)
        calls = []

        def fake_line_call(path, msg, timeout):
            calls.append((msg["op"], timeout))
            if msg["op"] == "oauth.start":
                return {"ok": True, "data": {"handle": "oah_0123456789abcdef", "userCode": "ABCD-EFGH", "verificationUri": "https://x.example/d",
                                             "interval": 5, "expiresAt": iso(time.time() + 1800)}}
            return {"ok": True, "data": {"authorized": True, "scopes": ["read"]}}

        m.line_call = fake_line_call
        env = m.Env(m.Paths(self.root), False)
        a = type("A", (), {"id": "tracker-api", "redirect": None})()
        with unittest.mock.patch("sys.stdout", new=io.StringIO()):
            self.assertEqual(m.cmd_authorize(env, a), 0)
        finish = [t for op, t in calls if op == "oauth.finish"]
        self.assertEqual(len(finish), 1)
        self.assertTrue(1800 <= finish[0] <= 1800 + 5, finish)

    def test_credentials_made_by_vault_site_are_recorded_for_purge(self):
        self.installed()
        self.assertEqual(self.site_tool("add", "--site-json-b64", self.b64(SITE), "--stdin-secrets", "--no-test",
                                        stdin=json.dumps({"username": USER, "password": PASSWORD, "totp": TOTP})).returncode, 0)
        manifest = self.read("etc/vault/installed-by").decode().split()
        for part in ("username", "password", "totp"):
            self.assertIn(f"cred:vault-helper.site.example-admin.{part}", manifest)
        self.assertEqual(len(manifest), len(set(manifest)))
        self.assertNotIn(PASSWORD, self.read("etc/vault/installed-by").decode())

    def test_vault_site_is_root_only_without_prefix(self):
        if os.getuid() == 0:
            self.skipTest("running as root")
        r = subprocess.run(["python3", "-I", "-B", os.path.join(PKG, "host", "bin", "vault-site"), "list"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 1)
        self.assertIn("run this with sudo", r.stderr)


class FakeAdmin:
    """vaultd's admin.sock: lists leases and records revokes."""

    def __init__(self, path, leases, revoked):
        class H(socketserver.StreamRequestHandler):
            def handle(self):
                req = json.loads(self.rfile.readline())
                if req["cmd"] == "leases":
                    reply = {"ok": True, "leases": leases}
                else:
                    revoked.append(req["lease"])
                    reply = {"ok": True, "state": "revoked"}
                self.wfile.write((json.dumps(reply) + "\n").encode())

        self.srv = socketserver.ThreadingUnixStreamServer(path, H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


if __name__ == "__main__":
    unittest.main()
