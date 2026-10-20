"""The ledger: one sqlite file (/var/lib/vault/vault.db) with requests, leases, judge records, nonces, agent locks and the
companies added with `vaultctl company add`. One connection guarded by one lock: the load is a handful of requests an hour.
Holds no secrets: session and token payloads live in memory only (broker.py)."""
import json
import sqlite3
import threading

OPEN_STATES = ("awaiting_verdict", "issuing", "ready")
ACTIVE_LEASE_STATES = ("issuing", "ready", "delivered")
BLOCKING_STATES = OPEN_STATES + ("delivered", "ended")   # a new request for the same (run, target) is refused while one of these exists
RETAIN_SECONDS = 7 * 86400                                 # finished requests are pruned after a week (the audit log keeps the history)

SCHEMA = """
CREATE TABLE IF NOT EXISTS requests(
  id TEXT PRIMARY KEY, created REAL NOT NULL, install_id TEXT NOT NULL,
  agent_id TEXT NOT NULL, run_id TEXT NOT NULL, company_id TEXT NOT NULL, issue_id TEXT NOT NULL, role TEXT NOT NULL,
  target TEXT NOT NULL, kind TEXT NOT NULL, class TEXT NOT NULL, minutes_requested INTEGER,
  max_minutes INTEGER NOT NULL DEFAULT 0, narrow_minutes INTEGER NOT NULL DEFAULT 0,
  state TEXT NOT NULL, code TEXT NOT NULL DEFAULT '', deadline REAL, decided REAL, minutes INTEGER,
  prompt_sha TEXT, rendered_sha TEXT);
CREATE INDEX IF NOT EXISTS requests_agent ON requests(agent_id, target, created);
CREATE INDEX IF NOT EXISTS requests_run ON requests(run_id, target);
CREATE TABLE IF NOT EXISTS leases(
  id TEXT PRIMARY KEY, request_id TEXT NOT NULL UNIQUE, agent_id TEXT NOT NULL, target TEXT NOT NULL, kind TEXT NOT NULL,
  site_id TEXT, starts REAL NOT NULL, ends REAL NOT NULL, ended REAL, end_reason TEXT, logout TEXT);
CREATE TABLE IF NOT EXISTS judge_records(
  id INTEGER PRIMARY KEY AUTOINCREMENT, model TEXT NOT NULL, provider TEXT NOT NULL, k INTEGER NOT NULL,
  prompt_sha TEXT NOT NULL, scenarios_sha TEXT NOT NULL, metrics TEXT NOT NULL, clean INTEGER NOT NULL, recorded REAL NOT NULL);
CREATE INDEX IF NOT EXISTS judge_records_key ON judge_records(model, provider, prompt_sha, scenarios_sha);
CREATE TABLE IF NOT EXISTS nonces(nonce TEXT PRIMARY KEY, seen REAL NOT NULL);
CREATE TABLE IF NOT EXISTS locks(agent_id TEXT PRIMARY KEY, locked REAL NOT NULL, request_id TEXT);
CREATE TABLE IF NOT EXISTS companies(id TEXT PRIMARY KEY, added REAL NOT NULL);
"""

REQUEST_FIELDS = ("id", "created", "install_id", "agent_id", "run_id", "company_id", "issue_id", "role", "target", "kind", "class",
                  "minutes_requested", "max_minutes", "narrow_minutes", "state", "code", "deadline", "decided", "minutes",
                  "prompt_sha", "rendered_sha")


class Store:
    def __init__(self, path):
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)   # autocommit; explicit transactions below
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript(SCHEMA)

    def close(self):
        with self.lock:
            self.db.close()

    def _one(self, sql, args=()):
        with self.lock:
            row = self.db.execute(sql, args).fetchone()
        return dict(row) if row else None

    def _all(self, sql, args=()):
        with self.lock:
            return [dict(r) for r in self.db.execute(sql, args).fetchall()]

    def _run(self, sql, args=()):
        with self.lock:
            return self.db.execute(sql, args).rowcount

    # ---- requests -------------------------------------------------------------------
    def add_request(self, **f):
        with self.lock:
            self.db.execute("INSERT INTO requests(%s) VALUES (%s)" % (",".join(f), ",".join("?" * len(f))), tuple(f.values()))

    def request(self, request_id):
        return self._one("SELECT * FROM requests WHERE id=?", (request_id,))

    def set_state(self, request_id, state, code="", expect=None, **extra):
        """Move a request to `state`. With `expect` (a state or tuple of states) the update happens only from those states;
        returns whether it happened, so two racing transitions cannot both win."""
        sets = {"state": state, "code": code, **extra}
        sql = "UPDATE requests SET %s WHERE id=?" % ",".join(k + "=?" for k in sets)
        args = list(sets.values()) + [request_id]
        if expect is not None:
            expect = (expect,) if isinstance(expect, str) else tuple(expect)
            sql += " AND state IN (%s)" % ",".join("?" * len(expect))
            args += list(expect)
        return self._run(sql, args) == 1

    def list_requests(self, state=None, limit=50):
        if state:
            return self._all("SELECT * FROM requests WHERE state=? ORDER BY created DESC LIMIT ?", (state, limit))
        return self._all("SELECT * FROM requests ORDER BY created DESC LIMIT ?", (limit,))

    def open_count(self, agent_id):
        return self._one("SELECT COUNT(*) AS n FROM requests WHERE agent_id=? AND state IN (%s)" % ",".join("?" * len(OPEN_STATES)),
                         (agent_id,) + OPEN_STATES)["n"]

    def blocking_request(self, run_id, target):
        return self._one("SELECT id FROM requests WHERE run_id=? AND target=? AND state IN (%s) LIMIT 1"
                         % ",".join("?" * len(BLOCKING_STATES)), (run_id, target) + BLOCKING_STATES)

    def recent(self, agent_id, target, since):
        """(requests, denied) by this agent for this target since `since`."""
        r = self._one("SELECT COUNT(*) AS n, COALESCE(SUM(state='denied'),0) AS d FROM requests WHERE agent_id=? AND target=? AND created>=?",
                      (agent_id, target, since))
        return r["n"], int(r["d"])

    def denials_since_last_success(self, agent_id, target, issue_id, codes):
        """(count, time of the last one): consecutive guard-relevant denials for (agent, target, issue) since the last request
        that was not denied. `codes` are the denial codes that count (the agent's own doing, not infrastructure)."""
        rows = self._all("SELECT state, code, decided FROM requests WHERE agent_id=? AND target=? AND issue_id=? ORDER BY created DESC",
                         (agent_id, target, issue_id))
        n, last = 0, 0.0
        for r in rows:
            if r["state"] != "denied":
                break
            if r["code"] in codes:
                n += 1
                last = max(last, r["decided"] or 0.0)
        return n, last

    def denial_times(self, agent_id, target, since, codes):
        return [r["decided"] for r in self._all(
            "SELECT decided FROM requests WHERE agent_id=? AND target=? AND state='denied' AND decided>=? AND code IN (%s) ORDER BY decided"
            % ",".join("?" * len(codes)), (agent_id, target, since) + tuple(codes))]

    # ---- leases ---------------------------------------------------------------------
    def add_lease(self, **f):
        with self.lock:
            self.db.execute("INSERT INTO leases(%s) VALUES (%s)" % (",".join(f), ",".join("?" * len(f))), tuple(f.values()))

    def lease(self, lease_id=None, request_id=None):
        if lease_id is not None:
            return self._one("SELECT * FROM leases WHERE id=?", (lease_id,))
        return self._one("SELECT * FROM leases WHERE request_id=?", (request_id,))

    def end_lease(self, lease_id, now, reason, logout):
        return self._run("UPDATE leases SET ended=?, end_reason=?, logout=? WHERE id=? AND ended IS NULL", (now, reason, logout, lease_id)) == 1

    def open_leases(self):
        """Leases not ended yet, with their request's state."""
        return self._all("SELECT l.*, r.state AS state, r.minutes AS minutes, r.role AS role FROM leases l JOIN requests r ON r.id=l.request_id "
                         "WHERE l.ended IS NULL ORDER BY l.starts")

    # ---- judge records --------------------------------------------------------------
    def add_judge_record(self, model, provider, k, prompt_sha, scenarios_sha, metrics, clean, now):
        with self.lock:
            self.db.execute("INSERT INTO judge_records(model, provider, k, prompt_sha, scenarios_sha, metrics, clean, recorded) VALUES (?,?,?,?,?,?,?,?)",
                            (model, provider, k, prompt_sha, scenarios_sha, json.dumps(metrics, sort_keys=True), int(clean), now))

    def has_clean_record(self, model, provider, prompt_sha, scenarios_sha):
        """Latest record for the key decides: a later failing run withdraws an earlier clean one."""
        r = self._one("SELECT clean FROM judge_records WHERE model=? AND provider=? AND prompt_sha=? AND scenarios_sha=? ORDER BY id DESC LIMIT 1",
                      (model, provider, prompt_sha, scenarios_sha))
        return bool(r and r["clean"])

    # ---- nonces ---------------------------------------------------------------------
    def use_nonce(self, nonce, now):
        """False when the nonce was seen before."""
        try:
            with self.lock:
                self.db.execute("INSERT INTO nonces(nonce, seen) VALUES (?,?)", (nonce, now))
            return True
        except sqlite3.IntegrityError:
            return False

    # ---- locks and companies ----------------------------------------------------------
    def lock_agent(self, agent_id, now, request_id=None):
        self._run("INSERT OR IGNORE INTO locks(agent_id, locked, request_id) VALUES (?,?,?)", (agent_id, now, request_id))

    def unlock_agent(self, agent_id):
        return self._run("DELETE FROM locks WHERE agent_id=?", (agent_id,)) == 1

    def is_locked(self, agent_id):
        return self._one("SELECT 1 FROM locks WHERE agent_id=?", (agent_id,)) is not None

    def locked_agents(self):
        return [r["agent_id"] for r in self._all("SELECT agent_id FROM locks ORDER BY agent_id")]

    def add_company(self, company_id, now):
        self._run("INSERT OR IGNORE INTO companies(id, added) VALUES (?,?)", (company_id, now))

    def remove_company(self, company_id):
        return self._run("DELETE FROM companies WHERE id=?", (company_id,)) == 1

    def companies(self):
        return [r["id"] for r in self._all("SELECT id FROM companies ORDER BY id")]

    # ---- housekeeping -----------------------------------------------------------------
    def prune(self, now, nonce_ttl):
        self._run("DELETE FROM nonces WHERE seen<?", (now - nonce_ttl,))
        self._run("DELETE FROM requests WHERE state NOT IN (%s) AND created<? AND id NOT IN (SELECT request_id FROM leases WHERE ended IS NULL)"
                  % ",".join("?" * len(OPEN_STATES + ("delivered",))), OPEN_STATES + ("delivered", now - RETAIN_SECONDS))
        self._run("DELETE FROM leases WHERE ended IS NOT NULL AND ended<?", (now - RETAIN_SECONDS,))
