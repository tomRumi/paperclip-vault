"""Ceilings (policy.py) and site files (sites.py)."""
import copy
import json
import os
import tempfile
import unittest

import support
from support import AGENT_ENG, AGENT_QA, POLICY, oauth_site_json, site_json
from vaultd import sites
from vaultd.policy import Policy


class Ceilings(unittest.TestCase):
    pol = Policy(POLICY)
    site = {"allowedAgents": [AGENT_QA], "maxMinutes": 60}

    def check(self, role="Engineer", cred="github-repo1", minutes=10, agent=AGENT_ENG, site=None):
        return self.pol.check(role, cred, minutes, agent, site)

    def test_ok_returns_class_limits(self):
        c = self.check()
        self.assertEqual((c.ok, c.cls, c.max_minutes, c.narrow_minutes, c.scopes), (True, "github", 480, 20, ("contents:read", "contents:write")))

    def test_codes_in_the_documented_order(self):
        self.assertEqual(self.check(cred="paperclip-secret").code, "bad_target")                   # no class
        self.assertEqual(self.check(cred="openrouter-key", minutes=None).code, "bad_target")       # no class beats everything below
        catch_all = Policy(dict(POLICY, classes=dict(POLICY["classes"], x={"match": "*", "scopes": ["use"]}), roles={"Engineer": ["x"], "QA": []}))
        self.assertEqual(catch_all.check("Engineer", "openrouter-key", None).code, "never_list")   # never beats role and minutes
        self.assertEqual(self.check(role="QA", cred="github-repo1", minutes=None).code, "role_class")
        self.assertEqual(self.check(cred="web-x", agent=AGENT_ENG, site=self.site, minutes=None).code, "site_agent_not_allowed")
        self.assertEqual(self.check(cred="web-x", agent=AGENT_QA, role="QA", site=self.site, minutes=None).code, "minutes_missing")
        self.assertEqual(self.check(cred="web-x", agent=AGENT_QA, role="QA", site=self.site, minutes=61).code, "minutes_over_max")

    def test_vault_prefix_is_never_grantable_even_without_a_never_list(self):
        pol = Policy({"roles": {"Engineer": ["any"]}, "classes": {"any": {"match": "*", "scopes": ["use"]}}})
        for name in ("vault-master", "vault.x", "vaultish"):
            self.assertEqual(pol.check("Engineer", name, 5).code, "never_list", name)
        self.assertTrue(pol.check("Engineer", "api-x", 5).ok)

    def test_minutes_rules(self):
        for bad in (None, 0, -5, 1.5, "30", True, [30]):
            self.assertEqual(self.check(minutes=bad).code, "minutes_missing", bad)
        self.assertTrue(self.check(minutes=1).ok)
        self.assertTrue(self.check(minutes=480).ok)
        c = self.check(minutes=481)
        self.assertEqual((c.code, c.max_minutes), ("minutes_over_max", 480))                       # the answer carries the maximum

    def test_maximum_is_the_smallest_of_class_site_oauth_and_480(self):
        api = self.check(cred="api-weather", minutes=60)                                           # class without max_minutes: 60
        self.assertEqual((api.ok, api.max_minutes), (True, 60))
        self.assertEqual(self.check(cred="api-weather", minutes=61).code, "minutes_over_max")
        site = {"allowedAgents": [AGENT_ENG], "maxMinutes": 45}
        self.assertEqual(self.check(cred="web-x", site=site, minutes=45).max_minutes, 45)          # site lower than class (120)
        self.assertEqual(self.check(cred="web-x", site=dict(site, maxMinutes=480), minutes=120).max_minutes, 120)
        oauth = dict(oauth_site_json(), allowedAgents=[AGENT_ENG])
        self.assertEqual(self.check(cred="oauth-drive", site=oauth, minutes=45).max_minutes, 45)   # accessTtlMaxMinutes
        big = Policy(dict(POLICY, classes=dict(POLICY["classes"], github=dict(POLICY["classes"]["github"], max_minutes=480))))
        self.assertEqual(big.check("Engineer", "github-x", 480).max_minutes, 480)
        with self.assertRaises(ValueError):
            Policy(dict(POLICY, classes={"g": {"match": "g-*", "scopes": ["use"], "max_minutes": 481}}, roles={}, agents={}))

    def test_narrow_minutes_never_exceed_the_maximum(self):
        c = self.check(cred="web-x", site={"allowedAgents": [AGENT_ENG], "maxMinutes": 10}, minutes=5)
        self.assertEqual((c.max_minutes, c.narrow_minutes), (10, 10))
        self.assertEqual(self.check(cred="api-weather").narrow_minutes, 30)                        # default narrow_minutes

    def test_match_accepts_a_glob_or_a_list(self):
        self.assertEqual(self.pol.classify("svc-main")[0], "api-key")
        self.assertEqual(self.pol.classify("api-x")[0], "api-key")
        self.assertEqual(self.pol.classify("zzz"), (None, None))

    def test_role_comes_only_from_the_pin(self):
        self.assertEqual(self.pol.role_of(AGENT_ENG), "Engineer")
        self.assertIsNone(self.pol.role_of("nobody"))

    def test_policy_validation(self):
        base = copy.deepcopy(POLICY)
        bad = [dict(base, agents={"a": "Nope"}), dict(base, roles={"Engineer": ["ghost"]}),
               dict(base, classes={"c": {"match": "c-*", "scopes": ["use"], "standing": True}}, roles={}, agents={}),
               dict(base, classes={"c": {"match": "c-*", "scopes": []}}, roles={}, agents={}),
               dict(base, classes={"c": {"match": "c-*", "scopes": ["use"], "narrow_minutes": 0}}, roles={}, agents={})]
        for p in bad:
            with self.assertRaises(ValueError):
                Policy(p)

    def test_view_for_the_read_only_tab(self):
        v = self.pol.view()
        self.assertEqual(v["classes"]["web-login"]["maxMinutes"], 120)
        self.assertEqual(v["agents"][AGENT_QA], "QA")
        json.dumps(v)

    def test_example_policy_loads(self):
        p = Policy.load(os.path.join(support.HOST, "policy.example.json"))
        self.assertEqual(p.check("QA", "web-x", 60, next(a for a, r in p.agents.items() if r == "QA"),
                                 {"allowedAgents": [next(a for a, r in p.agents.items() if r == "QA")], "maxMinutes": 60}).ok, True)
        self.assertEqual(p.check("Security", "github-ro-x", 5).code, "role_class")


class SiteFiles(unittest.TestCase):
    def bad(self, site, needle):
        with self.assertRaises(sites.SiteError) as cm:
            sites.validate(site)
        self.assertIn(needle, str(cm.exception))

    def test_valid_files(self):
        for s in (site_json(), oauth_site_json(), site_json("g", type="interactive", recipe={"successCheck": {"selector": "#me"}}, acceptNoLogout=True)):
            self.assertEqual(sites.validate(copy.deepcopy(s))["id"], s["id"])

    def test_max_minutes_default(self):
        s = site_json()
        del s["maxMinutes"]
        self.assertEqual(sites.validate(s)["maxMinutes"], 60)

    def test_unknown_keys_are_rejected_at_every_level(self):
        for path, needle in ((("extra",), "site"), (("recipe", "extra"), "recipe"), (("recipe", "successCheck", "extra"), "successCheck"),
                             (("recipe", "logout", "extra"), "logout"), (("recipe", "steps", 0, "extra"), "steps[0]")):
            s = site_json()
            node = s
            for k in path[:-1]:
                node = node[k]
            node[path[-1]] = 1
            self.bad(s, needle)
        o = oauth_site_json()
        o["oauth"]["extra"] = 1
        self.bad(o, "oauth")

    def test_field_rules(self):
        self.bad(site_json(id="Bad_Id"), "id")
        self.bad(site_json(id="-x"), "id")
        self.bad(site_json(schema=2), "schema")
        self.bad(site_json(type="ssh"), "type")
        self.bad(site_json(kind="prod"), "kind")
        self.bad(site_json(purpose="x" * 201), "purpose")
        self.bad(site_json(allowedHosts=[]), "allowedHosts")
        self.bad(site_json(allowedHosts=["UPPER.example.org"]), "allowedHosts")
        self.bad(site_json(allowedAgents=["not-a-uuid"]), "allowedAgents")
        self.bad(site_json(maxMinutes=481), "maxMinutes")
        self.bad(site_json(maxMinutes=0), "maxMinutes")
        self.bad(site_json(roles=["r"] * 11), "roles")
        self.bad(site_json(loginUrl="ftp://x"), "loginUrl")
        self.bad(site_json(acceptNoLogout="yes"), "acceptNoLogout")
        self.bad(site_json(oauth={"flow": "device"}), "only oauth")

    def test_recipe_rules(self):
        def with_step(step):
            s = site_json()
            s["recipe"]["steps"] = [step]
            return s
        self.bad(with_step({"eval": "alert(1)"}), "exactly one")
        self.bad(with_step({"fill": "#a"}), "fill needs it")
        self.bad(with_step({"fill": "#a", "from": "secret"}), "from")
        self.bad(with_step({"click": "#a", "from": "username"}), "fill steps only")
        self.bad(with_step({"click": "#a", "optional": "yes"}), "optional")
        s = site_json()
        s["recipe"]["trustCookies"] = ["(unclosed"]
        self.bad(s, "regular expression")
        s = site_json()
        del s["recipe"]["successCheck"]
        self.bad(s, "successCheck")
        s = site_json()
        s["recipe"]["steps"] = []
        self.bad(s, "steps")
        self.bad(site_json(recipe=None), "recipe")

    def test_challenge_remember_trust_storage_keys_and_press_selector(self):
        s = site_json()
        s["recipe"]["challenge"] = {"codeSelector": "#code", "submit": "#go", "remember": "#remember"}
        s["recipe"]["trustStorageKeys"] = ["^device_"]
        s["recipe"]["steps"].append({"press": "Enter", "selector": "#otp", "optional": True})
        sites.validate(s)
        for mutate, needle in ((lambda r: r["challenge"].update(remember=""), "remember"),
                               (lambda r: r["challenge"].update(extra="#x"), "challenge"),
                               (lambda r: r["challenge"].pop("submit"), "codeSelector and submit"),
                               (lambda r: r.update(trustStorageKeys=["(unclosed"]), "regular expression"),
                               (lambda r: r.update(trustStorageKeys="x"), "trustStorageKeys"),
                               (lambda r: r["steps"].append({"click": "#a", "selector": "#b"}), "press steps only")):
            bad = copy.deepcopy(s)
            mutate(bad["recipe"])
            self.bad(bad, needle)

    def test_oauth_rules(self):
        self.bad(oauth_site_json(recipe=site_json()["recipe"]), "no 'recipe'")
        o = oauth_site_json()
        o["oauth"]["flow"] = "implicit"
        self.bad(o, "flow")
        o = oauth_site_json()
        o["oauth"]["scopes"] = []
        self.bad(o, "scopes")
        o = oauth_site_json()
        o["oauth"]["tokenUrl"] = "nope"
        self.bad(o, "tokenUrl")
        self.bad(oauth_site_json(loginUrl="https://x.example.org/"), "no loginUrl")
        # the device flow needs deviceUrl but no authUrl; the redirect flow the other way round
        o = oauth_site_json()
        del o["oauth"]["authUrl"]
        sites.validate(o)
        o["oauth"]["deviceUrl"] = None
        self.bad(o, "deviceUrl")
        o = oauth_site_json()
        o["oauth"].update(flow="redirect", deviceUrl=None)
        sites.validate(o)
        del o["oauth"]["authUrl"]
        self.bad(o, "authUrl")

    def test_names_and_description(self):
        s = sites.validate(site_json())
        self.assertEqual(sites.credential_name(s), "web-todo-staging")
        self.assertEqual(sites.credential_name(oauth_site_json()), "oauth-drive")
        self.assertEqual(sites.description(s), "Login for site todo-staging (kind: test; purpose: UI and flow testing of the todo-api staging app; "
                                               "roles: QA, UI Tester). Browser session only, no password.")
        self.assertIn("OAuth access token", sites.description(oauth_site_json()))

    def test_load_all_and_find(self):
        with tempfile.TemporaryDirectory() as d:
            for s in (site_json(), oauth_site_json()):
                with open(os.path.join(d, s["id"] + ".json"), "w") as f:
                    json.dump(s, f)
            with open(os.path.join(d, "broken.json"), "w") as f:
                f.write("{")
            with open(os.path.join(d, "wrongname.json"), "w") as f:
                json.dump(site_json("other"), f)
            with open(os.path.join(d, "notes.txt"), "w") as f:
                f.write("ignored")
            found, errors = sites.load_all(d)
            self.assertEqual(sorted(found), ["drive", "todo-staging"])
            self.assertEqual(sorted(errors), ["broken.json", "wrongname.json"])
            self.assertEqual(sites.find(found, "web-todo-staging")["id"], "todo-staging")
            self.assertIsNone(sites.find(found, "web-drive"))              # an oauth site is not a web login
            self.assertIsNone(sites.find(found, "oauth-todo-staging"))
            self.assertIsNone(sites.find(found, "github-x"))
            self.assertEqual(sites.load_all(os.path.join(d, "missing")), ({}, {}))


if __name__ == "__main__":
    unittest.main()
