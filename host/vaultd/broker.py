"""The decision core. Transport-free: every operation takes the `data` dict of a verified message and returns a dict or
raises VaultError. server.py does framing, peer checks and signatures; this module does ceilings, the request ledger, verdict
checks, leases and the helper calls.

Request states: awaiting_verdict -> denied | issuing -> ready -> delivered -> ended; side states failed, expired, revoked.
Session and token payloads exist only in memory (self.payloads), from `ready` until fetched, ended or vaultd stops.
"""
import json
import os
import re
import secrets
import sys
import threading
import time
from datetime import datetime, timezone

from . import __version__, audit as auditlog, judge, sites as sitelib
from .helperclient import HelperError
from .policy import NAME_RE

UUID_RE = sitelib.UUID_RE
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
VERDICT_TIMEOUT_DEFAULT, VERDICT_TIMEOUT_MAX = 180, 600
MAX_OPEN_REQUESTS = 3                       # open (awaiting verdict, issuing, ready) requests per agent
BACKOFF_BASE, BACKOFF_MAX = 30, 3600        # loop guard per (agent, target, issue) after a denial
PAIR_DENIES = 3                             # denials/hour for one (agent, target) before it backs off for every issue
HISTORY_WINDOW = 3600
# Denials that count for the loop guards: the agent's own doing, not infrastructure (no verdict, provider error, ...).
GUARD_CODES = ("bad_target", "never_list", "role_class", "site_agent_not_allowed", "judge_deny", "judge_lock")
SESSION_MAX = 2_000_000                     # bytes of session JSON; keeps a lease.fetch answer under the 2 MiB line limit
MAX_K = 10
TESTSET_PAGE = 25
LOG_PAGE_MAX = 200
HELPER_STATE_AGE = 5                        # seconds a helper ping (up/down and the per-site states) is reused
# Failure codes a helper error becomes; anything else is reported as helper_error.
FAIL_CODES = ("login_failed", "totp_failed", "challenge_required", "needs_interactive", "captcha", "site_unreachable",
              "recipe_error", "helper_down", "timeout", "needs_authorize")
# What a failed issuing says about the site itself (the helper has no site-status operation): remembered for NOTE_TTL seconds,
# during which the site is "not ready" at the ceilings, so a broken site costs no gatekeeper calls. Then the next request retries.
SITE_NOTES = {"missing_credential": "missing_credential", "needs_interactive": "needs_interactive", "captcha": "needs_interactive",
              "challenge_required": "needs_interactive", "needs_owner_ack": "needs_interactive", "needs_authorize": "needs_authorize"}
NOTE_TTL = 120


class VaultError(Exception):
    def __init__(self, code, message=""):
        super().__init__(code, message)
        self.code, self.message = code, message


def iso(t):
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _need(cond, message):
    if not cond:
        raise VaultError("bad_request", message)


def _text(v, field, cap, minimum=1):
    _need(isinstance(v, str) and minimum <= len(v) <= cap, f"{field}: need a string of {minimum}..{cap} characters")
    return v


class Broker:
    def __init__(self, cfg, policy, store, helper, audit, creds_dir, install_id, clock=time.time, alert=None, spawn=None):
        """cfg: dict with sites_dir, judge_tests_dir, verdict_timeout_s, allowed_company_ids. install_id: callable returning the
        enrolled installId (or None). spawn(fn, *args): how issuing runs in the background (tests run it inline)."""
        self.cfg, self.policy, self.store, self.helper, self.audit = cfg, policy, store, helper, audit
        self.creds_dir, self.install_id, self.clock = creds_dir, install_id, clock
        self.alert = alert or (lambda msg: print("ALERT " + msg, file=sys.stderr, flush=True))
        self.spawn = spawn or (lambda fn, *a: threading.Thread(target=fn, args=a, daemon=True).start())
        self.verdict_timeout = min(int(cfg.get("verdict_timeout_s", VERDICT_TIMEOUT_DEFAULT)), VERDICT_TIMEOUT_MAX)
        self.template_path = judge.DEFAULT_PROMPT
        self.sec = judge.load_prompt(self.template_path)
        self.prompt_sha = judge.file_sha256(self.template_path)
        self.scenarios_path = os.path.join(cfg["judge_tests_dir"], "scenarios.jsonl")
        self.scenarios_sha = judge.file_sha256(self.scenarios_path)
        self.lock = threading.RLock()
        self.payloads = {}            # request id -> payload for lease.fetch; memory only
        self.helper_seen = 0.0
        self.helper_up = False
        self.helper_sites = {}        # site id -> state the helper reported in its last ping (credentials / sealed store)
        self.site_notes = {}          # site id -> (state, until)
        self._testset = None

    # ---- helpers --------------------------------------------------------------------
    def now(self):
        return self.clock()

    def sites(self):
        found, errors = sitelib.load_all(self.cfg["sites_dir"])
        for name, err in errors.items():
            self.alert(f"site file {name} ignored: {err}")
        return found

    def allowed_companies(self):
        return set(self.cfg.get("allowed_company_ids", [])) | set(self.store.companies())

    def refresh_helper(self, max_age=HELPER_STATE_AGE):
        """Ping the helper (the answer is reused for max_age seconds): whether it is up, and the state it reports per site."""
        with self.lock:
            if self.now() - self.helper_seen < max_age:
                return
            self.helper_seen = self.now()
        try:
            info = self.helper.ping()
            up = True
        except HelperError:
            info, up = {}, False
        reported = info.get("sites")
        states = {e["siteId"]: e["state"] for e in reported if isinstance(e, dict) and isinstance(e.get("siteId"), str)
                  and isinstance(e.get("state"), str)} if isinstance(reported, list) else {}
        with self.lock:
            self.helper_up = up
            self.helper_sites = states

    def site_state(self, site_id):
        """Why the site cannot be used right now, else 'ready': the state the helper reports (credentials missing, not authorized,
        no interactive login yet, ...), then a recent issuing failure (see SITE_NOTES). A helper that is down says nothing here:
        requests then fail when they are issued."""
        reported = self.helper_sites.get(site_id, "ready")
        if reported != "ready":
            return reported
        note = self.site_notes.get(site_id)
        return note[0] if note and self.now() < note[1] else "ready"

    def listed_state(self, site_id):
        """What sites.list shows: site_state, or helper_down when the helper does not answer."""
        return self.site_state(site_id) if self.helper_up else "helper_down"

    def _decision(self, *parts, **f):
        entry = {"event": "decision", "time": iso(self.now())}
        for part in parts:
            entry.update(part)
        entry.update(f)
        self.audit.write(entry)

    @staticmethod
    def _row_audit(row):
        return {"requestId": row["id"], "agentId": row["agent_id"], "role": row["role"], "companyId": row["company_id"],
                "issueId": row["issue_id"], "runId": row["run_id"], "target": row["target"], "kind": row["kind"],
                "class": row["class"], "requestedMinutes": row["minutes_requested"]}

    # ---- hello / read-only operations -----------------------------------------------
    def hello(self, data):
        self.refresh_helper(max_age=5)
        return {"installId": self.install_id(), "vaultdVersion": __version__, "helper": "up" if self.helper_up else "down",
                "time": iso(self.now())}

    def ceilings_get(self, data):
        view = self.policy.view()
        view.update(allowedCompanyIds=sorted(self.allowed_companies()), lockedAgents=self.store.locked_agents(),
                    limits={"absoluteMaxMinutes": sitelib.ABSOLUTE_MAX_MINUTES, "siteDefaultMaxMinutes": sitelib.DEFAULT_MAX_MINUTES,
                            "verdictTimeoutS": self.verdict_timeout, "maxOpenRequestsPerAgent": MAX_OPEN_REQUESTS})
        return view

    def _passes_ceilings(self, agent_id, site):
        """Can this agent get this site at all (pin, class, allowedAgents)? Used to filter lists for an agent."""
        role = self.policy.role_of(agent_id)
        if role is None or self.store.is_locked(agent_id):
            return False
        return self.policy.check(role, sitelib.credential_name(site), 1, agent_id, site).ok

    def sites_list(self, data):
        """Site files with their state. With agentId: only what that agent passes the ceilings for (sites in state ready, and
        the static credentials in its classes)."""
        agent = data.get("agentId")
        _need(agent is None or (isinstance(agent, str) and UUID_RE.match(agent)), "agentId: need a UUID")
        self.refresh_helper()
        out = []
        for s in self.sites().values():
            state = self.listed_state(s["id"])
            if agent and not (self._passes_ceilings(agent, s) and state == "ready"):
                continue
            out.append(dict(s, credential=sitelib.credential_name(s), state=state))
        credentials = []
        for name in self._static_credentials():
            cls, c = self.policy.classify(name)
            if c is None or self.policy.is_never(name):
                continue
            role = self.policy.role_of(agent) if agent else None
            if agent and cls not in self.policy.roles.get(role, []):
                continue
            credentials.append({"name": name, "class": cls, "purpose": self.policy.description(cls), "kind": "token",
                                "maxMinutes": min(self.policy.max_minutes(c), sitelib.ABSOLUTE_MAX_MINUTES)})
        return {"sites": out, "credentials": credentials, "helper": "up" if self.helper_up else "down"}

    def _static_credentials(self):
        try:
            names = sorted(n[6:] for n in os.listdir(self.creds_dir) if n.startswith("vault."))
        except OSError:
            return []
        return [n for n in names if NAME_RE.match(n) and not n.startswith(("web-", "oauth-"))]

    def request_status(self, data):
        row = self._request_of(data)
        out = {"requestId": row["id"], "state": row["state"], "code": row["code"], "agentId": row["agent_id"], "target": row["target"],
               "kind": row["kind"], "requestedMinutes": row["minutes_requested"], "minutes": row["minutes"],
               "deadline": iso(row["deadline"]) if row["deadline"] else None}
        lease = self.store.lease(request_id=row["id"])
        if lease:
            out.update(leaseId=lease["id"], expiresAt=iso(lease["ends"]))
        return out

    def request_list(self, data):
        limit = data.get("limit", 50)
        _need(isinstance(limit, int) and not isinstance(limit, bool) and 1 <= limit <= LOG_PAGE_MAX, f"limit: 1..{LOG_PAGE_MAX}")
        state = data.get("state")
        _need(state is None or isinstance(state, str), "state: need a string")
        return {"requests": [{"requestId": r["id"], "created": iso(r["created"]), "state": r["state"], "code": r["code"],
                              "agentId": r["agent_id"], "role": r["role"], "target": r["target"], "kind": r["kind"],
                              "requestedMinutes": r["minutes_requested"], "minutes": r["minutes"]}
                             for r in self.store.list_requests(state, limit)]}

    def leases_list(self, data):
        return {"leases": [{"leaseId": l["id"], "requestId": l["request_id"], "agentId": l["agent_id"], "role": l["role"],
                            "target": l["target"], "kind": self._lease_kind(l), "state": l["state"], "minutes": l["minutes"],
                            "startedAt": iso(l["starts"]), "expiresAt": iso(l["ends"])} for l in self.store.open_leases()]}

    @staticmethod
    def _lease_kind(lease):
        """What the plugin writes: 'login' (a session file) or 'token' (oauth and static tokens)."""
        return "login" if lease["kind"] == "login" else "token"

    def log_read(self, data):
        limit = data.get("limit", 50)
        before = data.get("beforeSeq")
        _need(isinstance(limit, int) and not isinstance(limit, bool) and 1 <= limit <= LOG_PAGE_MAX, f"limit: 1..{LOG_PAGE_MAX}")
        _need(before is None or (isinstance(before, int) and not isinstance(before, bool)), "beforeSeq: need an integer")
        try:
            entries = auditlog.read_events(self.audit.path, "decision", limit, before)
        except FileNotFoundError:
            entries = []
        return {"entries": entries}

    def _request_of(self, data):
        rid = data.get("requestId")
        _need(isinstance(rid, str) and re.match(r"^req_[0-9a-f]{16}$", rid), "requestId: need req_<16 hex>")
        row = self.store.request(rid)
        agent = data.get("agentId")
        if row is None or (agent is not None and agent != row["agent_id"]):
            raise VaultError("not_found", "no such request")
        return row

    # ---- request.create -------------------------------------------------------------
    def _parse_create(self, data):
        """data: {kind: "login" | "credential", target, reason, minutes, agent, context}. A login target is a site id
        (credential web-<id>); a credential target is an oauth-<id> source or a static vault.<name> secret."""
        a, ctx = data.get("agent"), data.get("context")
        _need(isinstance(a, dict) and set(a) == {"agentId", "runId", "companyId", "issueId"}, "agent: need agentId, runId, companyId, issueId")
        for k, v in a.items():
            _need(isinstance(v, str) and UUID_RE.match(v), f"agent.{k}: need a UUID")
        _need(isinstance(ctx, dict), "context: need an object")
        _need(data.get("kind") in ("login", "credential"), "kind: login or credential")
        target = data.get("target")
        _need(isinstance(target, str) and 0 < len(target) <= 64, "target: need a name")
        return {"agent": a, "kind": data["kind"], "credential": ("web-" + target) if data["kind"] == "login" else target,
                "reason": _text(data.get("reason"), "reason", 2000),
                "minutes": data.get("minutes"),
                "context": {k: str(ctx.get(k, "")) for k in ("issue_title", "issue_project", "stage")}}

    def _insert(self, req, role, state, code, kind="", cls="", ceiling=None, target=None, **extra):
        now = self.now()
        rid = "req_" + secrets.token_hex(8)
        m = req["minutes"] if isinstance(req["minutes"], int) and not isinstance(req["minutes"], bool) else None
        self.store.add_request(
            id=rid, created=now, install_id=self.install_id() or "", agent_id=req["agent"]["agentId"], run_id=req["agent"]["runId"],
            company_id=req["agent"]["companyId"], issue_id=req["agent"]["issueId"], role=role, target=target or req["credential"],
            kind=kind, **{"class": cls}, minutes_requested=m, max_minutes=ceiling.max_minutes if ceiling else 0,
            narrow_minutes=ceiling.narrow_minutes if ceiling else 0, state=state, code=code, **extra)
        return self.store.request(rid)

    def _early_deny(self, req, role, code, **extra):
        """Denied before the request enters the ledger (the agent is not a legitimate asker): audited, not counted by the guards."""
        a = req["agent"]
        self._decision(agentId=a["agentId"], role=role, companyId=a["companyId"], issueId=a["issueId"], runId=a["runId"],
                       target=req["credential"], requestedMinutes=req["minutes"] if isinstance(req["minutes"], int) else None,
                       decision="deny", code=code, reason=req["reason"][:judge.SAMPLE_REASON_CAP])
        return dict({"state": "denied", "code": code}, **extra)

    def _deny_new(self, req, role, code, kind, cls, ceiling, **extra):
        row = self._insert(req, role, "denied", code, kind, cls, ceiling, decided=self.now())
        self._decision(self._row_audit(row), decision="deny", code=code, reason=req["reason"][:judge.SAMPLE_REASON_CAP])
        out = {"requestId": row["id"], "state": "denied", "code": code}
        if ceiling and ceiling.max_minutes and code in ("minutes_over_max", "minutes_missing"):
            out["maxMinutes"] = ceiling.max_minutes
        return dict(out, **extra)

    def _rate_limit(self, agent_id, target, issue_id):
        """Seconds to wait (0 = go ahead): open-request cap, then exponential backoff per (agent, target, issue) and an
        agent-wide backoff after PAIR_DENIES denials in an hour for the same (agent, target)."""
        now = self.now()
        if self.store.open_count(agent_id) >= MAX_OPEN_REQUESTS:
            return 30
        n, last = self.store.denials_since_last_success(agent_id, target, issue_id, GUARD_CODES)
        wait = last + min(BACKOFF_BASE * 2 ** (n - 1), BACKOFF_MAX) - now if n else 0
        times = self.store.denial_times(agent_id, target, now - HISTORY_WINDOW, GUARD_CODES)
        if len(times) >= PAIR_DENIES:
            wait = max(wait, times[-1] + min(BACKOFF_BASE * 2 ** (len(times) - PAIR_DENIES), BACKOFF_MAX) - now)
        return max(0, int(wait) + 1) if wait > 0 else 0

    def _resolve_target(self, credential, sites):
        """(kind, site) for a credential name, or None: web-<id> / oauth-<id> need their site file, anything else needs a
        vault.<name> secret."""
        if not NAME_RE.match(credential):
            return None
        if credential.startswith(("web-", "oauth-")):
            site = sitelib.find(sites, credential)
            return None if site is None else ("oauth" if site["type"] == "oauth" else "login", site)
        return ("token", None) if os.path.exists(os.path.join(self.creds_dir, "vault." + credential)) else None

    def _scope(self, cls, site):
        c = self.policy.classes[cls]
        return "+".join(site["oauth"]["scopes"] if site and site["type"] == "oauth" else c["scopes"])

    def _description(self, cls, site):
        return sitelib.description(site) if site else self.policy.description(cls)

    def request_create(self, data):
        req = self._parse_create(data)
        a, credential = req["agent"], req["credential"]
        role = self.policy.role_of(a["agentId"])
        if role is None:
            return self._early_deny(req, None, "agent_unpinned")
        if a["companyId"] not in self.allowed_companies():
            return self._early_deny(req, role, "company_not_allowed")
        if self.store.is_locked(a["agentId"]):
            return self._early_deny(req, role, "agent_locked")
        if (dup := self.store.blocking_request(a["runId"], credential)):
            raise VaultError("conflict", "request %s already exists for this run and target" % dup["id"])
        if (wait := self._rate_limit(a["agentId"], credential, a["issueId"])):
            return self._early_deny(req, role, "rate_limited", retryAfter=wait)
        sites = self.sites()
        resolved = self._resolve_target(credential, sites)
        if resolved is None:
            return self._deny_new(req, role, "bad_target", "", "", None)
        kind, site = resolved
        if (kind == "login") != (req["kind"] == "login"):      # a web login is asked for as a login, never as a credential
            return self._deny_new(req, role, "bad_target", "", "", None)
        ceiling = self.policy.check(role, credential, req["minutes"], a["agentId"], site)
        if not ceiling.ok:
            return self._deny_new(req, role, ceiling.code, kind, ceiling.cls, ceiling)
        if site is not None:
            self.refresh_helper()
        if site is not None and self.site_state(site["id"]) != "ready":
            return self._deny_new(req, role, "site_not_ready", kind, ceiling.cls, ceiling, siteState=self.site_state(site["id"]))
        now = self.now()
        n, denied = self.store.recent(a["agentId"], credential, now - HISTORY_WINDOW)
        ctx = dict(agent_id=a["agentId"], role=role, credential=credential, credential_description=self._description(ceiling.cls, site),
                   scope=self._scope(ceiling.cls, site), duration_min=req["minutes"], recent_requests=n, recent_denied=denied,
                   reason=req["reason"], **req["context"])
        try:
            prompt = judge.render_prompt(self.sec, ctx)
        except ValueError as e:
            raise VaultError("bad_request", str(e))
        rendered = judge.sha256_text(prompt)
        row = self._insert(req, role, "awaiting_verdict", "", kind, ceiling.cls, ceiling, deadline=now + self.verdict_timeout,
                           prompt_sha=self.prompt_sha, rendered_sha=rendered)
        return {"requestId": row["id"], "state": "awaiting_verdict", "deadline": iso(row["deadline"]),
                "ceiling": {"class": ceiling.cls, "maxMinutes": ceiling.max_minutes, "narrowMinutes": ceiling.narrow_minutes},
                "prompt": prompt, "promptSha256": self.prompt_sha, "requestedMinutes": req["minutes"]}

    # ---- verdict.submit -------------------------------------------------------------
    def _parse_verdict(self, data):
        _need(data.get("decision") in judge.OPTIONS, "decision: one of a, b, c, d")
        m = data.get("minutes")
        _need(isinstance(m, int) and not isinstance(m, bool) and 0 <= m <= sitelib.ABSOLUTE_MAX_MINUTES, "minutes: whole minutes 0..480")
        raw, k = data.get("raw"), data.get("k")
        _need(isinstance(raw, list) and len(raw) <= MAX_K and all(isinstance(s, dict) for s in raw), "raw: need a list of samples")
        _need(isinstance(k, int) and not isinstance(k, bool) and 0 <= k <= MAX_K, "k: whole number")
        for f in ("model", "provider"):
            _text(data.get(f), f, 200)
        for f in ("promptSha256", "renderedSha256"):
            _need(isinstance(data.get(f), str) and HEX64_RE.match(data[f]), f"{f}: need a sha256 hex")
        return raw, k

    def verdict_submit(self, data):
        row = self._request_of(data)
        if row["install_id"] != (self.install_id() or ""):
            raise VaultError("not_found", "no such request")
        if row["state"] != "awaiting_verdict":
            raise VaultError("conflict", "request is %s" % row["state"])
        if data.get("decision") == "c" and data.get("raw") == []:     # the provider failed or timed out: nothing else to check
            return self._conclude_deny(row, "provider_error", {k: data[k] for k in ("model", "provider") if isinstance(data.get(k), str)})
        raw, k = self._parse_verdict(data)
        now = self.now()
        samples = [{"decision": s.get("decision"), "max_minutes": s.get("max_minutes"), "parseFailed": bool(s.get("parseFailed")),
                    "reason": str(s.get("reason", ""))[:judge.SAMPLE_REASON_CAP]} for s in raw]
        info = dict(model=data["model"], provider=data["provider"], k=k, raw=samples, verdict=data["decision"],
                    promptSha256=data["promptSha256"], renderedSha256=data["renderedSha256"])

        def deny(code, **extra):
            return self._conclude_deny(row, code, info, **extra)

        if now >= row["deadline"]:
            return deny("no_verdict")
        if data["promptSha256"] != self.prompt_sha or data["renderedSha256"] != row["rendered_sha"]:
            return deny("prompt_mismatch")
        if not self.store.has_clean_record(data["model"], data["provider"], self.prompt_sha, self.scenarios_sha):
            return deny("model_not_cleared")
        if k < 2 or len(samples) != k:
            return deny("bad_verdict")
        # The aggregate the plugin saw: recomputed from the raw answers with the ceiling this request was created under.
        decision, _ = judge.aggregate(samples, row["minutes_requested"], row["max_minutes"], row["narrow_minutes"])
        info["aggregate"] = decision
        if decision != data["decision"]:
            return deny("aggregate_mismatch")
        if decision == "d":
            self.store.lock_agent(row["agent_id"], now, row["id"])
            self.alert(f"gatekeeper locked agent {row['agent_id']} (request {row['id']}, target {row['target']})")
            return deny("judge_lock")
        if decision == "c":
            return deny("judge_deny")
        # Ceilings again with the CURRENT policy, pin, lock state and site files: the verdict can only equal or narrow them.
        if self.store.is_locked(row["agent_id"]):
            return deny("agent_locked")
        role = self.policy.role_of(row["agent_id"])
        if role is None:
            return deny("agent_unpinned")
        if row["company_id"] not in self.allowed_companies():
            return deny("company_not_allowed")
        resolved = self._resolve_target(row["target"], self.sites())
        if resolved is None:
            return deny("bad_target")
        kind, site = resolved
        ceiling = self.policy.check(role, row["target"], row["minutes_requested"], row["agent_id"], site)
        if not ceiling.ok:
            return deny(ceiling.code)
        decision, minutes = judge.aggregate(samples, row["minutes_requested"], min(row["max_minutes"], ceiling.max_minutes),
                                            min(row["narrow_minutes"], ceiling.narrow_minutes))
        minutes = min(minutes, data["minutes"])          # the plugin may narrow further, never widen
        if minutes < 1:
            return deny("minutes_zero")
        info.update(minutes=minutes)
        lease_id = "lse_" + secrets.token_hex(8)
        if not self.store.set_state(row["id"], "issuing", expect="awaiting_verdict", decided=now, minutes=minutes):
            raise VaultError("conflict", "request is no longer awaiting a verdict")
        self.store.add_lease(id=lease_id, request_id=row["id"], agent_id=row["agent_id"], target=row["target"], kind=kind,
                             site_id=site["id"] if site else None, starts=now, ends=now + minutes * 60)
        self._decision(self._row_audit(row), info, decision="approve", code="", leaseId=lease_id)
        self.spawn(self._issue, row["id"])
        return {"requestId": row["id"], "state": "issuing", "minutes": minutes, "leaseId": lease_id}

    def _conclude_deny(self, row, code, info, **extra):
        if not self.store.set_state(row["id"], "denied", code, expect="awaiting_verdict", decided=self.now()):
            raise VaultError("conflict", "request is no longer awaiting a verdict")
        self._decision(self._row_audit(row), {"minutes": 0}, info, decision="deny", code=code)
        return dict({"requestId": row["id"], "state": "denied", "code": code}, **extra)

    # ---- issuing --------------------------------------------------------------------
    def _issue(self, request_id):
        """Background: log in / mint / read the static token, then `ready`. Failure -> `failed` (or denied site_not_ready)."""
        row, lease = self.store.request(request_id), self.store.lease(request_id=request_id)
        ends_at = iso(lease["ends"])
        try:
            if row["kind"] == "login":
                got = self.helper.session_open(lease["id"], lease["site_id"], row["minutes"], ends_at)
                state = got.get("storageState")
                if not isinstance(state, dict) or len(json.dumps(state)) > SESSION_MAX:
                    raise HelperError("recipe_error", "session missing or larger than the 2 MiB limit")
                payload, expires = state, self._clamp_expiry(got.get("expiresAt"), lease["ends"])
            elif row["kind"] == "oauth":
                site = self.sites().get(lease["site_id"])
                scopes = site["oauth"]["scopes"] if site else []
                got = self.helper.token_mint(lease["id"], lease["site_id"], row["minutes"], scopes)
                if not isinstance(got.get("accessToken"), str):
                    raise HelperError("recipe_error", "helper returned no access token")
                expires = self._clamp_expiry(got.get("expiresAt"), lease["ends"])
                payload = {"accessToken": got["accessToken"], "tokenType": str(got.get("tokenType") or "Bearer"), "expiresAt": expires,
                           "scopes": got.get("scopes", scopes)}
            else:
                with open(os.path.join(self.creds_dir, "vault." + row["target"])) as f:
                    secret = f.read().rstrip("\n")
                expires = ends_at
                payload = {"accessToken": secret, "tokenType": "static", "expiresAt": expires,
                           "scopes": list(self.policy.classes[row["class"]]["scopes"])}
        except HelperError as e:
            return self._issue_failed(row, lease, e.code)
        except OSError:
            return self._issue_failed(row, lease, "no_secret")
        with self.lock:
            if not self.store.set_state(request_id, "ready", expect="issuing"):
                late = True          # revoked or expired while the helper worked: nothing is delivered, close what was opened
            else:
                late, self.payloads[request_id] = False, (payload, expires)
        if late:
            self._close_at_helper(row, lease)
            return
        self.audit.write({"event": "lease_start", "time": iso(self.now()), "requestId": request_id, "leaseId": lease["id"],
                          "agentId": row["agent_id"], "target": row["target"], "kind": row["kind"], "endsAt": ends_at})

    @staticmethod
    def _clamp_expiry(value, ends):
        """The helper's expiresAt, never later than the lease end."""
        try:
            t = datetime.strptime(str(value), "%Y-%m-%dT%H:%M:%S.%fZ" if "." in str(value) else "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            return iso(min(t.timestamp(), ends))
        except ValueError:
            return iso(ends)

    def _issue_failed(self, row, lease, code):
        if code in SITE_NOTES and row["kind"] != "token":
            self.site_notes[lease["site_id"]] = (SITE_NOTES[code], self.now() + NOTE_TTL)
        if code == "needs_owner_ack":
            new_state, code = "denied", "site_not_ready"
        else:
            new_state, code = "failed", code if code in FAIL_CODES or code == "no_secret" else "helper_error"
        if self.store.set_state(row["id"], new_state, code, expect="issuing", decided=self.now()):
            self.store.end_lease(lease["id"], self.now(), "failed", "unsupported")
            self._decision(self._row_audit(row), decision="failed", code=code, leaseId=lease["id"])

    # ---- delivery -------------------------------------------------------------------
    def lease_fetch(self, data):
        """Single use. {leaseId, kind: login | token, name, expiresAt, minutes, payload}: the payload is the Playwright storageState
        of a login or {accessToken, tokenType, expiresAt, scopes} of a token; name is the site id or the credential name."""
        row = self._request_of(data)
        with self.lock:
            held = self.payloads.pop(row["id"], None)
            if held is None or not self.store.set_state(row["id"], "delivered", expect="ready"):
                raise VaultError("conflict", "nothing to fetch: request is %s" % row["state"])
        lease = self.store.lease(request_id=row["id"])
        self.audit.write({"event": "lease_fetch", "time": iso(self.now()), "requestId": row["id"], "leaseId": lease["id"],
                          "agentId": row["agent_id"], "target": row["target"]})
        payload, expires = held
        return {"leaseId": lease["id"], "kind": self._lease_kind(lease), "name": lease["site_id"] if lease["kind"] == "login" else row["target"],
                "expiresAt": expires, "minutes": row["minutes"], "payload": payload}

    def lease_ack(self, data):
        row = self._request_of(data)
        rel = _text(data.get("relPath"), "relPath", 300)
        if row["state"] != "delivered":
            raise VaultError("conflict", "request is %s" % row["state"])
        self.audit.write({"event": "lease_ack", "time": iso(self.now()), "requestId": row["id"], "agentId": row["agent_id"],
                          "target": row["target"], "relPath": rel})
        return {}

    # ---- lease end ------------------------------------------------------------------
    def _close_at_helper(self, row, lease):
        """'ok' | 'unsupported' | 'failed': log out / revoke at the helper. Static tokens have nothing to close."""
        if row["kind"] == "token":
            return "unsupported"
        try:
            if row["kind"] == "login":
                done = self.helper.session_close(lease["id"]).get("loggedOut")
            else:
                done = self.helper.token_revoke(lease["id"]).get("revoked")
        except HelperError:
            return "failed"
        return "unsupported" if done == "unsupported" else "ok" if done is True else "failed"

    def end_lease(self, row, lease, reason, state, code="", expect=("issuing", "ready", "delivered")):
        """Close the lease at the helper, forget the payload, record the end. False if another path ended it first."""
        with self.lock:
            if not self.store.set_state(row["id"], state, code, expect=expect):
                return False
            self.payloads.pop(row["id"], None)
        logout = self._close_at_helper(row, lease)
        self.store.end_lease(lease["id"], self.now(), reason, logout)
        self.audit.write({"event": "lease_end", "time": iso(self.now()), "requestId": row["id"], "leaseId": lease["id"],
                          "agentId": row["agent_id"], "target": row["target"], "reason": "helper_error" if logout == "failed" else reason,
                          "logout": logout})
        return True

    def lease_revoke(self, data):
        """End a request or lease early. by: an admin user id, "vaultctl", or "plugin" when delivery failed (then `reason` is the
        failure code, e.g. no_workspace, and the request becomes failed/<reason> instead of revoked)."""
        by = _text(data.get("by"), "by", 100)
        reason = data.get("reason")
        _need(reason is None or (isinstance(reason, str) and re.match(r"^[a-z][a-z_]{0,39}$", reason)), "reason: a short code")
        failed = by == "plugin"
        state, code = ("failed", reason or "delivery_failed") if failed else ("revoked", "revoked" if reason is None else reason)
        if "leaseId" in data:
            _need(("requestId" not in data) and isinstance(data["leaseId"], str), "need requestId or leaseId")
            lease = self.store.lease(lease_id=data["leaseId"])
            row = self.store.request(lease["request_id"]) if lease else None
            if row is None:
                raise VaultError("not_found", "no such lease")
        else:
            row = self._request_of(data)
            lease = self.store.lease(request_id=row["id"])
        if row["state"] == "awaiting_verdict":
            if not self.store.set_state(row["id"], state, code, expect="awaiting_verdict", decided=self.now()):
                raise VaultError("conflict", "request changed")
            self._decision(self._row_audit(row), decision="deny", code=code, by=by)
            return {"requestId": row["id"], "state": state}
        if lease is None or lease["ended"] is not None or not self.end_lease(row, lease, "delivery_failed" if failed else "revoked", state, code):
            raise VaultError("conflict", "request is %s" % row["state"])
        self.audit.write({"event": "revoke", "time": iso(self.now()), "requestId": row["id"], "leaseId": lease["id"], "by": by,
                          "reason": reason})
        return {"requestId": row["id"], "state": state, "leaseId": lease["id"]}

    # ---- sweeper and start-up -------------------------------------------------------
    def sweep(self):
        """Every few seconds: no verdict by the deadline = deny; end leases at their time; prune."""
        now = self.now()
        for row in self.store.list_requests("awaiting_verdict", 1000):
            if now >= row["deadline"] and self.store.set_state(row["id"], "denied", "no_verdict", expect="awaiting_verdict", decided=now):
                self._decision(self._row_audit(row), decision="deny", code="no_verdict", minutes=0)
        for lease in self.store.open_leases():
            if now >= lease["ends"]:
                row = self.store.request(lease["request_id"])
                self.end_lease(row, lease, "expired", "ended" if row["state"] == "delivered" else "expired")
        self.store.prune(now, nonce_ttl=600)
        self.refresh_helper()

    def reconcile(self):
        """On start: payloads did not survive, so a lease that was not delivered is closed; the helper's own leases that
        vaultd does not know are closed too."""
        self.refresh_helper(max_age=0)
        for lease in self.store.open_leases():
            row = self.store.request(lease["request_id"])
            if row["state"] in ("issuing", "ready"):
                self.end_lease(row, lease, "restart", "failed", code="vaultd_restart", expect=("issuing", "ready"))
        known = {l["id"] for l in self.store.open_leases()}
        try:
            theirs = self.helper.ping().get("leases") or []
        except HelperError:
            return
        sites = self.sites()
        for h in theirs:
            if isinstance(h, dict) and h.get("leaseId") not in known:
                oauth = (sites.get(h.get("siteId")) or {}).get("type") == "oauth"
                try:
                    (self.helper.token_revoke if oauth else self.helper.session_close)(h["leaseId"])
                except (HelperError, KeyError):
                    pass
                self.audit.write({"event": "lease_end", "time": iso(self.now()), "leaseId": h.get("leaseId"), "reason": "orphan"})

    # ---- judge tests ----------------------------------------------------------------
    def _scenarios(self):
        if self._testset is None:
            items = []
            with open(self.scenarios_path, encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        s = json.loads(line)
                        items.append({"id": s["id"], "category": s["category"], "expected": s["expected"],
                                      "acceptable": s.get("acceptable", []), "beyond_ceiling": s.get("beyond_ceiling"),
                                      "prompt": judge.render_prompt(self.sec, s["request"])})
            self._testset = items
        return self._testset

    def judge_testset(self, data):
        off, lim = data.get("offset", 0), data.get("limit", TESTSET_PAGE)
        _need(isinstance(off, int) and not isinstance(off, bool) and off >= 0, "offset: whole number")
        _need(isinstance(lim, int) and not isinstance(lim, bool) and 1 <= lim <= 50, "limit: 1..50")
        items = self._scenarios()
        return {"promptSha256": self.prompt_sha, "scenariosSha256": self.scenarios_sha, "total": len(items), "items": items[off:off + lim]}

    def judge_record(self, data):
        for f in ("model", "provider"):
            _text(data.get(f), f, 200)
        k, metrics = data.get("k"), data.get("metrics")
        _need(isinstance(k, int) and not isinstance(k, bool) and 1 <= k <= MAX_K, "k: whole number")
        _need(isinstance(metrics, dict), "metrics: need an object")
        for f in ("promptSha256", "scenariosSha256"):
            _need(isinstance(data.get(f), str) and HEX64_RE.match(data[f]), f"{f}: need a sha256 hex")
        if (data["promptSha256"], data["scenariosSha256"]) != (self.prompt_sha, self.scenarios_sha):
            raise VaultError("conflict", "record is for a different prompt or scenario file")
        failed = judge.passes(metrics) + (["k"] if k < 2 else [])
        self.store.add_judge_record(data["model"], data["provider"], k, self.prompt_sha, self.scenarios_sha, metrics, not failed, self.now())
        self.audit.write({"event": "judge_record", "time": iso(self.now()), "model": data["model"], "provider": data["provider"],
                          "k": k, "metrics": metrics, "clean": not failed})
        return {"clean": not failed, "failed": failed}

    # ---- admin (admin.sock) ---------------------------------------------------------
    def admin(self, cmd):
        if not isinstance(cmd, dict):
            return {"ok": False, "error": "command must be a JSON object"}
        try:
            reply = dict(self._admin(cmd), ok=True)
        except VaultError as e:
            reply = {"ok": False, "error": e.message or e.code}
        rec = {"event": "admin", "time": iso(self.now()), "cmd": str(cmd.get("cmd"))[:40], "ok": reply["ok"]}
        for k in ("lease", "agent", "action", "id"):
            if k in cmd:
                rec[k] = str(cmd[k])[:200]
        self.audit.write(rec)
        return reply

    def _admin(self, cmd):
        c = cmd.get("cmd")
        if c == "status":
            self.refresh_helper(max_age=0)
            return {"version": __version__, "installId": self.install_id(), "helper": "up" if self.helper_up else "down",
                    "leases": len(self.store.open_leases()), "lockedAgents": self.store.locked_agents(),
                    "companies": sorted(self.allowed_companies())}
        if c == "leases":
            return self.leases_list({})
        if c == "revoke":
            got = self.lease_revoke({"leaseId": str(cmd.get("lease")), "by": "vaultctl"})
            return {"state": got["state"]}
        if c == "unlock":
            return {"unlocked": self.store.unlock_agent(str(cmd.get("agent"))), "lockedAgents": self.store.locked_agents()}
        if c == "company":
            cid = str(cmd.get("id"))
            if not UUID_RE.match(cid):
                raise VaultError("bad_request", "company id must be a UUID")
            if cmd.get("action") == "add":
                self.store.add_company(cid, self.now())
            elif cmd.get("action") == "rm":
                if cid in self.cfg.get("allowed_company_ids", []):
                    raise VaultError("conflict", "listed in config.json: remove it there and restart vaultd")
                if not self.store.remove_company(cid):
                    raise VaultError("not_found", "company not added with vaultctl")
            else:
                raise VaultError("bad_request", "company add|rm UUID")
            return {"companies": sorted(self.allowed_companies())}
        raise VaultError("bad_request", "unknown command")
