"""Shared test helpers: paths, the scenario ceiling model, and a signing client that speaks plugin.sock's protocol."""
import base64
import hashlib
import json
import os
import sys

HOST = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, HOST)
from vaultd import ed25519  # noqa: E402
from vaultd.policy import Policy  # noqa: E402

REPO = os.path.join(HOST, "..")
SCENARIOS = os.path.join(HOST, "judge-tests", "scenarios.jsonl")


def scenarios():
    with open(SCENARIOS, encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]


def scenario_ceiling(policy, scn):
    """The ceiling code a scenario meets in production ('' = it reaches the gatekeeper), under the model the beyond_ceiling tags
    use: the policy pins each scenario agent to its role, and every web-/oauth- site file lists as allowedAgents all agents whose
    role holds the web-login/oauth-token class (the site's `roles` text is the gatekeeper's rule 10 to enforce, not a ceiling).
    'scope' = the scenario asks for a scope text outside the class scopes, which vaultd never sends (it derives the scope
    from the class), so such a request cannot reach the gatekeeper."""
    r = scn["request"]
    agents = {s["request"]["agent_id"]: s["request"]["role"] for s in scenarios()}
    pol = Policy(dict(policy_data(policy), agents=agents))
    site = None
    name, _ = pol.classify(r["credential"])
    if name in ("web-login", "oauth-token"):
        site = {"allowedAgents": [a for a, role in agents.items() if name in pol.roles.get(role, [])], "maxMinutes": 60}
    ck = pol.check(r["role"], r["credential"], r["duration_min"], r["agent_id"], site)
    if ck.ok and r["scope"] != "+".join(ck.scopes):
        return "scope"
    return ck.code


def policy_data(path):
    with open(path) as f:
        return json.load(f)


class Signer:
    """What the plugin does: signs {"v":1,...} bodies with an Ed25519 key. Test-only RFC 8032 signing on vaultd's curve code."""

    def __init__(self, seed=b"\x01" * 32):
        h = hashlib.sha512(seed).digest()
        self.a = (int.from_bytes(h[:32], "little") & ((1 << 254) - 8)) | (1 << 254)
        self.prefix = h[32:]
        self.public = ed25519.encode(ed25519.mul(self.a, ed25519.BASE))
        self.spki = base64.b64encode(ed25519.SPKI_PREFIX + self.public).decode()
        self.kid = ed25519.key_id(self.spki)

    def sign(self, msg):
        r = int.from_bytes(hashlib.sha512(self.prefix + msg).digest(), "little") % ed25519.L
        rb = ed25519.encode(ed25519.mul(r, ed25519.BASE))
        k = int.from_bytes(hashlib.sha512(rb + self.public + msg).digest(), "little") % ed25519.L
        return rb + ((r + k * self.a) % ed25519.L).to_bytes(32, "little")

    def line(self, body, kid=None, tamper=False):
        msg = json.dumps(body).encode()
        sig = self.sign(b"pcvault-v1\n" + (msg + b" " if tamper else msg))
        return json.dumps({"msg": base64.urlsafe_b64encode(msg).decode().rstrip("="), "sig": base64.b64encode(sig).decode(),
                           "kid": kid or self.kid}).encode()


# ---- a whole vaultd in a scratch directory ---------------------------------------------------------------------------------
import socket  # noqa: E402
import socketserver  # noqa: E402
import tempfile  # noqa: E402
import threading  # noqa: E402

from vaultd import judge  # noqa: E402
from vaultd.__main__ import DEFAULTS  # noqa: E402
from vaultd.broker import iso  # noqa: E402
from vaultd.helperclient import HelperError  # noqa: E402

AGENT_ENG = "aaaaaaaa-0000-4000-8000-000000000001"
AGENT_QA = "aaaaaaaa-0000-4000-8000-000000000002"
AGENT_OTHER = "aaaaaaaa-0000-4000-8000-000000000003"
AGENT_UNPINNED = "aaaaaaaa-0000-4000-8000-0000000000ff"
COMPANY = "cccccccc-0000-4000-8000-000000000001"
ISSUE = "dddddddd-0000-4000-8000-000000000001"
INSTALL_ID = "inst-" + "ab" * 12

POLICY = {
    "agents": {AGENT_ENG: "Engineer", AGENT_QA: "QA", AGENT_OTHER: "Engineer"},
    "never": ["openrouter*", "*admin*", "*prod-deploy*"],
    "roles": {"Engineer": ["github", "api-key", "web-login", "oauth-token"], "QA": ["api-key", "web-login"]},
    "classes": {
        "github": {"description": "Fine-grained token, one repo.", "match": "github-*", "max_minutes": 480,
                   "scopes": ["contents:read", "contents:write"], "narrow_minutes": 20},
        "api-key": {"match": ["api-*", "svc-*"], "scopes": ["use"]},           # no max_minutes: default 60
        "web-login": {"match": "web-*", "max_minutes": 120, "scopes": ["use"]},
        "oauth-token": {"match": "oauth-*", "max_minutes": 60, "scopes": ["use"]}},
}
SECRETS = {"github-repo1": "FAKE-gh-secret-111", "api-weather": "FAKE-api-secret-222", "openrouter-key": "FAKE-or-secret-444",
           "vault-master": "FAKE-vm-secret-555"}


def site_json(site_id="todo-staging", **over):
    site = {"schema": 1, "id": site_id, "displayName": "Todo staging", "type": "password-totp", "kind": "test",
            "purpose": "UI and flow testing of the todo-api staging app", "loginUrl": "https://app.example.org/login", "logoutUrl": None,
            "allowedHosts": ["app.example.org"], "allowedAgents": [AGENT_QA, AGENT_ENG], "roles": ["QA", "UI Tester"], "maxMinutes": 60,
            "recipe": {"steps": [{"fill": "#email", "from": "username"}, {"click": "button[type=submit]"},
                                 {"fill": "#password", "from": "password"}, {"click": "#login"},
                                 {"fill": "#otp", "from": "totp", "optional": True}],
                       "successCheck": {"urlMatches": "^https://app\\.example\\.org/dashboard", "selector": "#avatar"},
                       "logout": {"steps": [{"click": "#logout"}]}, "trustCookies": ["^device_"], "timeoutSeconds": 45},
            "oauth": None}
    site.update(over)
    return site


def oauth_site_json(site_id="drive", **over):
    fields = dict(type="oauth", loginUrl=None, logoutUrl=None, recipe=None, kind="owner", purpose="read the shared drive",
                  oauth={"flow": "device", "authUrl": "https://auth.example.org/a", "tokenUrl": "https://auth.example.org/t",
                         "deviceUrl": "https://auth.example.org/d", "revokeUrl": "https://auth.example.org/r", "clientId": "cid",
                         "scopes": ["drive.read"], "accessTtlMaxMinutes": 45})
    fields.update(over)
    return site_json(site_id, **fields)


class Clock:
    def __init__(self, t=1_800_000_000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t += seconds


class FakeHelper:
    """A helper.sock stand-in: records calls, answers from `reply[op]` (dict, callable(params) or HelperError)."""

    def __init__(self, path, token="tok-" + "x" * 20):
        self.path, self.token, self.calls, self.leases = path, token, [], []
        self.site_states = None       # {site id: state}: what ping reports per site (None: the key is absent, like an older helper)
        self.reply = {}
        outer = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                req = json.loads(self.rfile.readline())
                if req.get("token") != outer.token:
                    return self._send({"ok": False, "error": {"code": "unauthorized", "message": "token"}})
                params = {k: v for k, v in req.items() if k not in ("op", "token")}
                outer.calls.append((req["op"], params))
                r = outer.reply.get(req["op"], outer.defaults(req["op"], params))
                if callable(r):
                    r = r(params)
                if isinstance(r, HelperError):
                    return self._send({"ok": False, "error": {"code": r.code, "message": r.message}})
                self._send({"ok": True, "data": r})

            def _send(self, obj):
                self.wfile.write((json.dumps(obj) + "\n").encode())

        self.srv = socketserver.ThreadingUnixStreamServer(path, Handler)
        self.srv.daemon_threads = True
        threading.Thread(target=lambda: self.srv.serve_forever(0.02), daemon=True).start()

    def defaults(self, op, p):
        if op == "ping":
            out = {"version": "test", "browsers": True, "leases": list(self.leases)}
            if self.site_states is not None:
                out["sites"] = [{"siteId": k, "state": v} for k, v in self.site_states.items()]
            return out
        if op == "session.open":
            return {"storageState": {"cookies": [{"name": "sid", "value": "FAKE-cookie", "domain": "app.example.org"}], "origins": []},
                    "expiresAt": p["endsAt"], "trustUsed": False}
        if op == "session.close":
            return {"loggedOut": True}
        if op == "token.mint":
            return {"accessToken": "FAKE-oauth-token", "tokenType": "Bearer", "expiresAt": "2099-01-01T00:00:00Z", "scopes": p["scopes"]}
        if op == "token.revoke":
            return {"revoked": True}
        return HelperError("unknown_op", op)

    def ops(self, name=None):
        return [c for c in self.calls if name is None or c[0] == name]

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


class Env:
    """vaultd (Broker + PluginProtocol) over a scratch directory, a fake clock, a fake helper socket and an enrolled test signer."""

    def __init__(self, sites=None, policy=None, spawn="inline", enrolled=True, **cfg_over):
        self.dir = tempfile.mkdtemp(prefix="vt", dir="/tmp")
        d = self.dir
        for sub in ("sites", "creds", "state", "log"):
            os.mkdir(os.path.join(d, sub))
        self.policy_path = os.path.join(d, "policy.json")
        with open(self.policy_path, "w") as f:
            json.dump(policy or POLICY, f)
        self.sites_dir = os.path.join(d, "sites")
        for s in (sites if sites is not None else [site_json()]):
            self.write_site(s)
        self.creds = os.path.join(d, "creds")
        for name, value in SECRETS.items():
            with open(os.path.join(self.creds, "vault." + name), "w") as f:
                f.write(value + "\n")
        self.token_path = os.path.join(d, "helper.token")
        self.helper = FakeHelper(os.path.join(d, "h.sock"))
        with open(self.token_path, "w") as f:
            f.write(self.helper.token + "\n")
        self.uid = os.getuid()
        self.cfg = dict(DEFAULTS, plugin_uid=self.uid, policy_path=self.policy_path, sites_dir=self.sites_dir,
                        enrol_path=os.path.join(d, "enrol.json"), plugin_socket=os.path.join(d, "p.sock"),
                        admin_socket=os.path.join(d, "a.sock"), helper_socket=self.helper.path, helper_token_path=self.token_path,
                        audit_path=os.path.join(d, "log", "audit.jsonl"), db_path=os.path.join(d, "state", "vault.db"),
                        key_path=os.path.join(d, "state", "plugin-key.json"), allowed_company_ids=[COMPANY])
        self.cfg.update(cfg_over)
        self.clock = Clock()
        self.signer = Signer()
        if enrolled:
            self.write_key()
        self.inline = spawn == "inline"
        self.n = 0
        self.build()

    def build(self):
        from vaultd import audit, broker as brk, server
        from vaultd.helperclient import HelperClient
        from vaultd.policy import Policy
        from vaultd.store import Store
        if hasattr(self, "store"):
            self.store.close()                                  # a restart: the old ledger connection goes away
        self.audit_log = audit.AuditLog(self.cfg["audit_path"])
        self.store = Store(self.cfg["db_path"])
        self.enrolment = server.Enrolment(self.cfg["key_path"], self.cfg["enrol_path"], self.cfg["plugin_uid"], self.clock)
        self.alerts = []
        self.broker = brk.Broker(self.cfg, Policy.load(self.policy_path), self.store, HelperClient(self.helper.path, self.token_path),
                                 self.audit_log, self.creds, self.enrolment.install_id, clock=self.clock, alert=self.alerts.append,
                                 spawn=(lambda fn, *a: fn(*a)) if self.inline else None)
        self.proto = server.PluginProtocol(self.broker, self.enrolment, self.store, self.audit_log, self.cfg["plugin_uid"], self.clock)

    def close(self):
        self.store.close()
        self.helper.close()
        import shutil
        shutil.rmtree(self.dir, ignore_errors=True)

    def write_site(self, site):
        with open(os.path.join(self.sites_dir, site["id"] + ".json"), "w") as f:
            json.dump(site, f)

    def write_key(self, signer=None):
        s = signer or self.signer
        with open(self.cfg["key_path"], "w") as f:
            json.dump({"installId": INSTALL_ID, "kid": s.kid, "publicKey": s.spki, "serviceUid": self.uid,
                       "enrolledAt": "2026-01-01T00:00:00Z", "codeHash": "0" * 64}, f)

    # ---- talking to the protocol ----
    def body(self, type_, data=None, **over):
        self.n += 1
        b = {"v": 1, "type": type_, "installId": INSTALL_ID, "ts": iso(self.clock()), "nonce": "n%023d" % self.n, "data": data or {}}
        b.update(over)
        return b

    def send(self, body, uid=None, signer=None, **line_kw):
        raw = self.proto.handle((signer or self.signer).line(body, **line_kw), self.uid if uid is None else uid)
        return None if raw is None else json.loads(raw)

    def ask(self, type_, data=None, **over):
        """Reply of a correctly signed message."""
        return self.send(self.body(type_, data, **over))

    def ok(self, type_, data=None):
        r = self.ask(type_, data)
        assert r["ok"], r
        return r["data"]

    def err(self, type_, data=None):
        r = self.ask(type_, data)
        assert not r["ok"], r
        return r["error"]["code"]

    # ---- request / verdict shortcuts ----
    def create_data(self, agent=AGENT_QA, site="todo-staging", credential=None, minutes=30, reason="Click through the forms to test the due-date field.", **over):
        """request.create data: a login for `site`, or (credential=...) a credential request."""
        d = {"agent": {"agentId": agent, "runId": "eeeeeeee-0000-4000-8000-%012d" % (self.n + 1), "companyId": COMPANY, "issueId": ISSUE},
             "kind": "credential" if credential else "login", "target": credential or site, "reason": reason, "minutes": minutes,
             "context": {"issue_title": "[Test] Verify due-date field", "issue_project": "todo-api", "stage": "Test"}}
        d.update(over)
        return d

    def create(self, **kw):
        over = kw.pop("data_over", {})
        return self.ok("request.create", dict(self.create_data(**kw), **over))

    def record_clean(self, model="m1", provider="p1", **metrics):
        t = self.ok("judge.testset", {"limit": 1})
        m = {"n": 420, "injection_granted": 0, "over_grants": 0, "stability": 1.0, "parse_failures_pct": 0.0}
        m.update(metrics)
        return self.ok("judge.record", {"model": model, "provider": provider, "k": 2, "promptSha256": t["promptSha256"],
                                        "scenariosSha256": t["scenariosSha256"], "metrics": m})

    def verdict_data(self, created, samples, model="m1", provider="p1", **over):
        decision, minutes = judge.aggregate(samples, created["requestedMinutes"], created["ceiling"]["maxMinutes"],
                                            created["ceiling"]["narrowMinutes"])
        d = {"requestId": created["requestId"], "decision": decision, "minutes": minutes, "k": len(samples), "raw": samples,
             "model": model, "provider": provider, "promptSha256": created["promptSha256"],
             "renderedSha256": judge.sha256_text(created["prompt"])}
        d.update(over)
        return d

    def verdict(self, created, samples, **over):
        return self.ok("verdict.submit", self.verdict_data(created, samples, **over))


def approve(minutes, d="b"):
    return {"decision": d, "max_minutes": minutes, "reason": "fits the ticket"}


DENY = {"decision": "c", "max_minutes": 0, "reason": "no"}
LOCK = {"decision": "d", "max_minutes": 0, "reason": "hostile"}
