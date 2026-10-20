"""Lease life cycle against a fake helper socket: issuing, delivery, end, revoke, failures, restart."""
import json
import os
import threading
import unittest

import support
from support import AGENT_ENG, AGENT_QA, Env, approve, oauth_site_json, site_json
from vaultd.helperclient import HelperError


class Base(unittest.TestCase):
    sites = None

    def setUp(self):
        self.env = Env(sites=self.sites)
        self.addCleanup(self.env.close)
        self.env.record_clean()

    def audit(self, event):
        with open(self.env.cfg["audit_path"]) as f:
            return [e for e in map(json.loads, f) if e["event"] == event]

    def lease(self, minutes=30, **kw):
        c = self.env.create(minutes=minutes, **kw)
        r = self.env.verdict(c, [approve(minutes), approve(minutes)])
        return c, r

    def state(self, c):
        return self.env.ok("request.status", {"requestId": c["requestId"]})


class LoginLease(Base):
    def test_full_cycle_login_fetch_ack_expire(self):
        c, r = self.lease(30)
        self.assertEqual(r["state"], "issuing")
        st = self.state(c)
        self.assertEqual((st["state"], st["minutes"], st["expiresAt"]), ("ready", 30, "2027-01-15T08:30:00Z"))
        op, params = self.env.helper.ops("session.open")[0]
        self.assertEqual((params["siteId"], params["minutes"], params["endsAt"]), ("todo-staging", 30, "2027-01-15T08:30:00Z"))
        self.assertRegex(params["leaseId"], r"^lse_[0-9a-f]{16}$")
        leases = self.env.ok("leases.list")["leases"]
        self.assertEqual([(l["leaseId"], l["agentId"], l["state"], l["target"]) for l in leases], [(params["leaseId"], AGENT_QA, "ready", "web-todo-staging")])

        got = self.env.ok("lease.fetch", {"requestId": c["requestId"]})
        self.assertEqual(set(got), {"leaseId", "kind", "name", "expiresAt", "minutes", "payload"})
        self.assertEqual((got["leaseId"], got["kind"], got["name"], got["minutes"]), (params["leaseId"], "login", "todo-staging", 30))
        self.assertEqual(got["payload"]["cookies"][0]["value"], "FAKE-cookie")                          # the Playwright storageState itself
        self.assertEqual(got["expiresAt"], "2027-01-15T08:30:00Z")
        self.assertEqual(self.env.err("lease.fetch", {"requestId": c["requestId"]}), "conflict")       # single use
        self.assertEqual(self.state(c)["state"], "delivered")
        self.assertEqual(self.env.err("lease.ack", {"requestId": c["requestId"]}), "bad_request")
        self.env.ok("lease.ack", {"requestId": c["requestId"], "relPath": ".vault/todo-staging-abc.session.json"})
        self.assertEqual(self.audit("lease_ack")[0]["relPath"], ".vault/todo-staging-abc.session.json")

        self.env.clock.advance(29 * 60)
        self.env.broker.sweep()
        self.assertEqual(self.state(c)["state"], "delivered")                                           # not yet
        self.env.clock.advance(60)
        self.env.broker.sweep()
        self.assertEqual(self.state(c)["state"], "ended")
        self.assertEqual(self.env.helper.ops("session.close")[0][1], {"leaseId": params["leaseId"]})
        end = self.audit("lease_end")[0]
        self.assertEqual((end["reason"], end["logout"], end["leaseId"]), ("expired", "ok", params["leaseId"]))
        self.assertEqual(self.env.ok("leases.list")["leases"], [])
        self.env.broker.sweep()
        self.assertEqual(len(self.env.helper.ops("session.close")), 1)                                  # ended once

    def test_the_session_exists_only_in_memory(self):
        c, _ = self.lease()
        self.assertIn(c["requestId"], self.env.broker.payloads)
        self.env.ok("lease.fetch", {"requestId": c["requestId"]})
        self.assertNotIn(c["requestId"], self.env.broker.payloads)                                      # dropped on fetch
        for path in (self.env.cfg["audit_path"], self.env.cfg["db_path"], self.env.cfg["db_path"] + "-wal"):
            if os.path.exists(path):
                with open(path, "rb") as f:
                    self.assertNotIn(b"FAKE-cookie", f.read(), path)

    def test_undelivered_lease_expires_and_is_closed(self):
        c, _ = self.lease(10)
        self.env.clock.advance(601)
        self.env.broker.sweep()
        self.assertEqual(self.state(c)["state"], "expired")
        self.assertEqual(len(self.env.helper.ops("session.close")), 1)
        self.assertNotIn(c["requestId"], self.env.broker.payloads)
        self.assertEqual(self.env.err("lease.fetch", {"requestId": c["requestId"]}), "conflict")

    def test_revoke_in_every_state(self):
        c, _ = self.lease()
        r = self.env.ok("lease.revoke", {"requestId": c["requestId"], "by": "board-user-1"})
        self.assertEqual(r["state"], "revoked")
        self.assertEqual(len(self.env.helper.ops("session.close")), 1)
        self.assertEqual(self.audit("lease_end")[0]["reason"], "revoked")
        self.assertEqual(self.audit("revoke")[0]["by"], "board-user-1")
        self.assertEqual(self.env.err("lease.revoke", {"requestId": c["requestId"], "by": "x"}), "conflict")   # already over
        self.assertEqual(self.env.err("lease.fetch", {"requestId": c["requestId"]}), "conflict")
        # delivered lease, by leaseId
        c2, _ = self.lease(agent=AGENT_ENG)
        self.env.ok("lease.fetch", {"requestId": c2["requestId"]})
        lid = self.state(c2)["leaseId"]
        self.assertEqual(self.env.ok("lease.revoke", {"leaseId": lid, "by": "u"})["state"], "revoked")
        # still waiting for a verdict
        c3 = self.env.create(agent=AGENT_ENG)
        self.assertEqual(self.env.ok("lease.revoke", {"requestId": c3["requestId"], "by": "u"})["state"], "revoked")
        self.assertEqual(self.env.err("verdict.submit", self.env.verdict_data(c3, [approve(30), approve(30)])), "conflict")
        self.assertEqual(self.env.err("lease.revoke", {"leaseId": "lse_" + "0" * 16, "by": "u"}), "not_found")
        self.assertEqual(self.env.err("lease.revoke", {"requestId": c3["requestId"]}), "bad_request")          # by is required

    def test_failed_delivery_reported_by_the_plugin_ends_the_lease_as_failed(self):
        c, _ = self.lease()
        self.env.ok("lease.fetch", {"requestId": c["requestId"]})
        r = self.env.ok("lease.revoke", {"requestId": c["requestId"], "by": "plugin", "reason": "no_workspace"})
        self.assertEqual(r["state"], "failed")
        st = self.state(c)
        self.assertEqual((st["state"], st["code"]), ("failed", "no_workspace"))
        self.assertEqual(len(self.env.helper.ops("session.close")), 1)
        self.assertEqual(self.audit("lease_end")[0]["reason"], "delivery_failed")
        c2, _ = self.lease(agent=AGENT_ENG)
        self.env.ok("lease.revoke", {"leaseId": self.state(c2)["leaseId"], "by": "plugin"})                  # undelivered, no reason
        self.assertEqual((self.state(c2)["state"], self.state(c2)["code"]), ("failed", "delivery_failed"))
        self.assertEqual(self.env.err("lease.revoke", {"requestId": c2["requestId"], "by": "plugin", "reason": "Bad Reason!"}), "bad_request")

    def test_admin_revoke(self):
        c, _ = self.lease()
        lid = self.state(c)["leaseId"]
        self.assertTrue(self.env.broker.admin({"cmd": "revoke", "lease": lid})["ok"])
        self.assertEqual(self.state(c)["state"], "revoked")
        self.assertFalse(self.env.broker.admin({"cmd": "revoke", "lease": lid})["ok"])

    def test_helper_failing_at_close_is_recorded_not_hidden(self):
        c, _ = self.lease()
        self.env.helper.reply["session.close"] = HelperError("helper_down", "x")
        self.env.ok("lease.revoke", {"requestId": c["requestId"], "by": "u"})
        end = self.audit("lease_end")[0]
        self.assertEqual((end["reason"], end["logout"]), ("helper_error", "failed"))
        self.assertEqual(self.state(c)["state"], "revoked")

    def test_logout_unsupported_is_reported(self):
        c, _ = self.lease()
        self.env.helper.reply["session.close"] = {"loggedOut": "unsupported"}
        self.env.broker.admin({"cmd": "revoke", "lease": self.state(c)["leaseId"]})
        self.assertEqual(self.audit("lease_end")[0]["logout"], "unsupported")

    def test_lease_start_is_audited_without_the_session(self):
        self.lease()
        e = self.audit("lease_start")[0]
        self.assertEqual((e["agentId"], e["target"], e["kind"]), (AGENT_QA, "web-todo-staging", "login"))
        with open(self.env.cfg["audit_path"]) as f:
            self.assertNotIn("FAKE-cookie", f.read())

    def test_helper_expiry_later_than_the_lease_is_clamped(self):
        self.env.helper.reply["session.open"] = lambda p: {"storageState": {"cookies": [], "origins": []}, "expiresAt": "2099-01-01T00:00:00Z"}
        c, _ = self.lease(15)
        self.assertEqual(self.env.ok("lease.fetch", {"requestId": c["requestId"]})["expiresAt"], "2027-01-15T08:15:00Z")


class Failures(Base):
    def test_helper_codes_become_failed_with_that_code(self):
        for code in ("login_failed", "totp_failed", "challenge_required", "needs_interactive", "captcha", "site_unreachable", "recipe_error", "timeout"):
            self.env.helper.reply["session.open"] = HelperError(code, "x")
            c, r = self.lease()
            st = self.state(c)
            self.assertEqual((st["state"], st["code"]), ("failed", code), code)
            self.assertEqual(self.env.ok("leases.list")["leases"], [])
            self.env.clock.advance(7200)
            self.env.broker.site_notes.clear()
        self.assertEqual(len(self.env.helper.ops("session.close")), 0)                                   # nothing was opened

    def test_unknown_helper_code_is_helper_error(self):
        self.env.helper.reply["session.open"] = HelperError("browser_unavailable", "x")
        c, _ = self.lease()
        self.assertEqual(self.state(c)["code"], "helper_error")

    def test_helper_down(self):
        self.env.helper.close()
        c, _ = self.lease()
        st = self.state(c)
        self.assertEqual((st["state"], st["code"]), ("failed", "helper_down"))
        self.assertEqual(self.env.ok("hello")["helper"], "down")
        self.env.helper = type("Gone", (), {"close": lambda s: None, "ops": lambda s, n=None: []})()      # for cleanup

    def test_session_larger_than_2_mib_or_missing_fails_closed(self):
        self.env.helper.reply["session.open"] = lambda p: {"storageState": {"cookies": [{"v": "x" * 2_100_000}], "origins": []}, "expiresAt": p["endsAt"]}
        c, _ = self.lease()
        self.assertEqual((self.state(c)["state"], self.state(c)["code"]), ("failed", "recipe_error"))
        self.env.clock.advance(7200)
        self.env.helper.reply["session.open"] = {"expiresAt": "2099-01-01T00:00:00Z"}
        c, _ = self.lease()
        self.assertEqual(self.state(c)["code"], "recipe_error")

    def test_needs_owner_ack_is_denied_as_site_not_ready(self):
        self.env.helper.reply["session.open"] = HelperError("needs_owner_ack", "no logout recipe")
        c, _ = self.lease()
        st = self.state(c)
        self.assertEqual((st["state"], st["code"]), ("denied", "site_not_ready"))

    def test_a_site_that_reported_itself_unusable_is_not_ready_until_the_note_expires(self):
        self.env.helper.reply["session.open"] = HelperError("needs_interactive", "captcha wall")
        self.lease()
        self.assertEqual(self.env.ok("sites.list")["sites"][0]["state"], "needs_interactive")
        self.env.clock.advance(40)
        r = self.env.create()
        self.assertEqual((r["state"], r["code"], r["siteState"]), ("denied", "site_not_ready", "needs_interactive"))
        self.assertEqual(self.env.ok("sites.list", {"agentId": AGENT_QA})["sites"], [])                  # hidden from the agent's list
        self.env.clock.advance(200)
        self.assertEqual(self.env.ok("sites.list")["sites"][0]["state"], "ready")
        self.env.helper.reply.pop("session.open")
        self.assertEqual(self.env.create()["state"], "awaiting_verdict")

    def test_missing_credential_marks_the_site(self):
        self.env.helper.reply["session.open"] = HelperError("missing_credential", "password not provisioned")
        c, _ = self.lease()
        self.assertEqual(self.state(c)["code"], "helper_error")                                          # the request failed generically ...
        self.assertEqual(self.env.ok("sites.list")["sites"][0]["state"], "missing_credential")           # ... the site says why

    def test_revoked_while_the_helper_is_still_logging_in(self):
        env = Env(spawn="thread")
        self.addCleanup(env.close)
        env.record_clean()
        started, release = threading.Event(), threading.Event()

        def slow(params):
            started.set()
            release.wait(5)
            return {"storageState": {"cookies": [], "origins": []}, "expiresAt": params["endsAt"]}
        env.helper.reply["session.open"] = slow
        c = env.create()
        env.verdict(c, [approve(30), approve(30)])
        self.assertTrue(started.wait(5))
        self.assertEqual(env.ok("request.status", {"requestId": c["requestId"]})["state"], "issuing")
        self.assertEqual(env.err("lease.fetch", {"requestId": c["requestId"]}), "conflict")             # not ready yet
        env.ok("lease.revoke", {"requestId": c["requestId"], "by": "u"})
        release.set()
        for _ in range(100):
            if len(env.helper.ops("session.close")) == 2:
                break
            threading.Event().wait(0.05)
        self.assertEqual(len(env.helper.ops("session.close")), 2)                                       # revoke, and the late login closed again
        self.assertEqual(env.ok("request.status", {"requestId": c["requestId"]})["state"], "revoked")
        self.assertNotIn(c["requestId"], env.broker.payloads)


class SiteStates(Base):
    """sites.list and the ceilings use the per-site state the helper reports in its ping."""
    sites = [site_json(), oauth_site_json(allowedAgents=[AGENT_ENG])]

    def states(self, **kw):
        return {s["id"]: s["state"] for s in self.env.ok("sites.list", kw or None)["sites"]}

    def test_states_come_from_the_helper_ping(self):
        self.env.helper.site_states = {"todo-staging": "missing_credential", "drive": "needs_authorize"}
        self.assertEqual(self.states(), {"todo-staging": "missing_credential", "drive": "needs_authorize"})
        self.assertEqual(self.env.ok("sites.list", {"agentId": AGENT_QA})["sites"], [])                  # not ready: hidden from agents
        r = self.env.create()
        self.assertEqual((r["state"], r["code"], r["siteState"]), ("denied", "site_not_ready", "missing_credential"))
        self.env.clock.advance(6)
        self.env.helper.site_states = {"todo-staging": "ready", "drive": "ready"}
        self.assertEqual(self.states(), {"todo-staging": "ready", "drive": "ready"})
        self.assertEqual([s["id"] for s in self.env.ok("sites.list", {"agentId": AGENT_QA})["sites"]], ["todo-staging"])
        self.assertEqual(self.env.create()["state"], "awaiting_verdict")

    def test_every_helper_state_is_shown_as_is(self):
        for state in ("needs_interactive", "needs_owner_ack", "needs_authorize", "missing_credential"):
            self.env.clock.advance(6)
            self.env.helper.site_states = {"todo-staging": state}
            self.assertEqual(self.states()["todo-staging"], state)

    def test_the_ping_is_reused_for_a_few_seconds(self):
        self.env.helper.site_states = {"todo-staging": "needs_interactive"}
        self.states()
        self.env.helper.site_states = {"todo-staging": "ready"}
        self.env.clock.advance(3)
        self.assertEqual(self.states()["todo-staging"], "needs_interactive")                            # cached
        self.env.clock.advance(3)
        self.assertEqual(self.states()["todo-staging"], "ready")
        self.assertEqual(len(self.env.helper.ops("ping")), 2)

    def test_a_helper_that_does_not_know_a_site_or_reports_nothing_is_not_blocking(self):
        self.assertEqual(self.states(), {"todo-staging": "ready", "drive": "ready"})                     # no "sites" key at all
        self.env.clock.advance(6)
        self.env.helper.site_states = {"other": "missing_credential"}
        self.assertEqual(self.states(), {"todo-staging": "ready", "drive": "ready"})

    def test_helper_down(self):
        self.assertEqual(set(self.states().values()), {"ready"})
        self.env.helper.close()
        self.env.helper = type("Gone", (), {"close": lambda s: None, "path": self.env.helper.path, "calls": []})()
        self.env.clock.advance(6)
        listed = self.env.ok("sites.list")
        self.assertEqual({s["state"] for s in listed["sites"]}, {"helper_down"})
        self.assertEqual(listed["helper"], "down")
        self.assertEqual(self.env.ok("sites.list", {"agentId": AGENT_QA})["sites"], [])
        r = self.env.create()                                                                           # requests still reach the gatekeeper
        self.assertEqual(r["state"], "awaiting_verdict")

    def test_a_recent_issuing_failure_still_marks_a_site_the_helper_calls_ready(self):
        self.env.helper.site_states = {"todo-staging": "ready"}
        self.env.helper.reply["session.open"] = HelperError("needs_interactive", "captcha wall")
        self.lease()
        self.assertEqual(self.states()["todo-staging"], "needs_interactive")
        self.env.clock.advance(200)
        self.assertEqual(self.states()["todo-staging"], "ready")


class OauthLease(Base):
    sites = [site_json(), oauth_site_json(allowedAgents=[AGENT_ENG])]

    def test_token_mint_fetch_and_revoke(self):
        c = self.env.create(agent=AGENT_ENG, credential="oauth-drive", minutes=30)
        self.assertEqual(c["ceiling"], {"class": "oauth-token", "maxMinutes": 45, "narrowMinutes": 30})
        self.assertIn("requested_scope: drive.read", c["prompt"])
        self.assertIn("OAuth access token", c["prompt"])
        self.env.verdict(c, [approve(30), approve(30)])
        _, params = self.env.helper.ops("token.mint")[0]
        self.assertEqual((params["siteId"], params["minutes"], params["scopes"]), ("drive", 30, ["drive.read"]))
        fetched = self.env.ok("lease.fetch", {"requestId": c["requestId"]})
        got = fetched["payload"]
        self.assertEqual((fetched["kind"], fetched["name"]), ("token", "oauth-drive"))
        self.assertEqual((got["accessToken"], got["tokenType"], got["scopes"]), ("FAKE-oauth-token", "Bearer", ["drive.read"]))
        self.assertEqual((got["expiresAt"], fetched["expiresAt"]), ("2027-01-15T08:30:00Z",) * 2)       # the helper said 2099: clamped
        self.env.broker.admin({"cmd": "revoke", "lease": self.state(c)["leaseId"]})
        self.assertEqual(self.env.helper.ops("token.revoke")[0][1]["leaseId"], params["leaseId"])
        self.assertEqual(self.env.helper.ops("session.close"), [])

    def test_oauth_site_not_authorized_yet(self):
        self.env.helper.reply["token.mint"] = HelperError("needs_authorize", "run vault-site authorize")
        c = self.env.create(agent=AGENT_ENG, credential="oauth-drive", minutes=30)
        self.env.verdict(c, [approve(30), approve(30)])
        self.assertEqual((self.state(c)["state"], self.state(c)["code"]), ("failed", "needs_authorize"))
        states = {s["id"]: s["state"] for s in self.env.ok("sites.list")["sites"]}
        self.assertEqual(states, {"drive": "needs_authorize", "todo-staging": "ready"})

    def test_over_the_oauth_maximum_is_denied(self):
        r = self.env.create(agent=AGENT_ENG, credential="oauth-drive", minutes=46)
        self.assertEqual((r["code"], r["maxMinutes"]), ("minutes_over_max", 45))


class StaticTokenLease(Base):
    def test_token_is_read_from_the_credential_directory_and_never_logged(self):
        c = self.env.create(agent=AGENT_ENG, credential="github-repo1", minutes=60)
        self.assertIn("requested_scope: contents:read+contents:write", c["prompt"])
        self.env.verdict(c, [approve(60), approve(60)])
        self.assertEqual(self.env.helper.ops("session.open"), [])
        fetched = self.env.ok("lease.fetch", {"requestId": c["requestId"]})
        got = fetched["payload"]
        self.assertEqual((fetched["kind"], fetched["name"]), ("token", "github-repo1"))
        self.assertEqual((got["accessToken"], got["tokenType"]), ("FAKE-gh-secret-111", "static"))
        self.assertEqual(got["scopes"], ["contents:read", "contents:write"])
        self.env.clock.advance(3601)
        self.env.broker.sweep()
        self.assertEqual(self.state(c)["state"], "ended")
        self.assertEqual(self.audit("lease_end")[0]["logout"], "unsupported")
        self.assertEqual([c for c in self.env.helper.calls if c[0] != "ping"], [])
        with open(self.env.cfg["audit_path"]) as f:
            self.assertNotIn("FAKE-gh-secret", f.read())

    def test_secret_removed_between_request_and_issue_fails(self):
        c = self.env.create(agent=AGENT_ENG, credential="api-weather", minutes=30)
        os.unlink(os.path.join(self.env.creds, "vault.api-weather"))
        self.assertEqual(self.env.verdict(c, [approve(30), approve(30)])["code"], "bad_target")


class Restart(Base):
    def restart(self):
        self.env.store.close()
        self.env.build()

    def test_undelivered_leases_are_closed_and_delivered_ones_kept(self):
        a, _ = self.lease(30)
        b, _ = self.lease(30, agent=AGENT_ENG)
        self.env.ok("lease.fetch", {"requestId": b["requestId"]})
        self.restart()
        self.env.broker.reconcile()
        sa, sb = self.state(a), self.state(b)
        self.assertEqual((sa["state"], sa["code"]), ("failed", "vaultd_restart"))
        self.assertEqual(sb["state"], "delivered")
        self.assertEqual(len(self.env.helper.ops("session.close")), 1)
        self.assertEqual(self.audit("lease_end")[-1]["reason"], "restart")
        self.env.clock.advance(31 * 60)
        self.env.broker.sweep()                                                                        # the delivered one still ends on time
        self.assertEqual(self.state(b)["state"], "ended")
        self.assertEqual(len(self.env.helper.ops("session.close")), 2)

    def test_helper_leases_vaultd_does_not_know_are_closed(self):
        self.env.helper.leases = [{"leaseId": "lse_" + "9" * 16, "siteId": "todo-staging", "endsAt": "2099-01-01T00:00:00Z"},
                                  {"leaseId": "lse_" + "8" * 16, "siteId": "drive", "endsAt": "2099-01-01T00:00:00Z"}]
        self.env.write_site(oauth_site_json())
        self.env.broker.reconcile()
        self.assertEqual([p["leaseId"] for _, p in self.env.helper.ops("session.close")], ["lse_" + "9" * 16])
        self.assertEqual([p["leaseId"] for _, p in self.env.helper.ops("token.revoke")], ["lse_" + "8" * 16])
        self.assertEqual({e["reason"] for e in self.audit("lease_end")}, {"orphan"})

    def test_a_running_helper_lease_vaultd_knows_is_left_alone(self):
        c, _ = self.lease()
        self.env.ok("lease.fetch", {"requestId": c["requestId"]})
        lid = self.state(c)["leaseId"]
        self.env.helper.leases = [{"leaseId": lid, "siteId": "todo-staging", "endsAt": "2027-01-15T08:30:00Z"}]
        self.restart()
        self.env.broker.reconcile()
        self.assertEqual(self.env.helper.ops("session.close"), [])

    def test_reconcile_with_the_helper_down_does_not_crash(self):
        self.env.helper.close()
        self.env.broker.reconcile()
        self.env.helper = type("Gone", (), {"close": lambda s: None})()


if __name__ == "__main__":
    unittest.main()
