"""Site files (/etc/vault/sites/<id>.json): non-secret descriptions of the web logins and OAuth sources the helper can use.

Validated here and by the helper with the same rules: unknown keys are rejected at every level. vaultd uses only the policy
side (allowedAgents, roles, maxMinutes, kind, purpose, type); the recipe belongs to the helper but is checked for shape too.
"""
import json
import os
import re

ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,40}$")
UUID_RE = re.compile(r"^[0-9a-f-]{36}$")
TYPES = ("password-totp", "interactive", "oauth")
KINDS = ("test", "owner", "research")
STEP_OPS = ("fill", "click", "press", "waitFor")
STEP_FROM = ("username", "password", "totp")
TOP_KEYS = {"schema", "id", "displayName", "type", "kind", "purpose", "loginUrl", "logoutUrl", "allowedHosts",
            "allowedAgents", "roles", "maxMinutes", "recipe", "oauth", "acceptNoLogout"}
RECIPE_KEYS = {"steps", "successCheck", "logout", "challenge", "trustCookies", "trustStorageKeys", "timeoutSeconds"}
OAUTH_KEYS = {"flow", "authUrl", "tokenUrl", "deviceUrl", "revokeUrl", "clientId", "scopes", "accessTtlMaxMinutes"}
HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?(:[0-9]{1,5})?$")
DEFAULT_MAX_MINUTES = 60
ABSOLUTE_MAX_MINUTES = 480


class SiteError(ValueError):
    pass


def _need(cond, msg):
    if not cond:
        raise SiteError(msg)


def _str(v, field, cap):
    _need(isinstance(v, str) and 0 < len(v) <= cap, f"{field}: need a non-empty string of at most {cap} characters")
    return v


def _url(v, field, nullable=False):
    if v is None and nullable:
        return
    _str(v, field, 2000)
    _need(re.match(r"^https?://[^\s/]+", v) is not None, f"{field}: need an http(s) URL")


def _keys(d, allowed, field):
    _need(isinstance(d, dict), f"{field}: need an object")
    _need(not (set(d) - allowed), f"{field}: unknown keys {sorted(set(d) - allowed)}")


def _list(v, field, cap=64):
    _need(isinstance(v, list) and len(v) <= cap, f"{field}: need a list of at most {cap} entries")
    return v


def _step(s, field):
    _need(isinstance(s, dict), f"{field}: need an object")
    ops = [k for k in s if k in STEP_OPS]
    _need(len(ops) == 1, f"{field}: exactly one of {STEP_OPS}")
    _keys(s, {ops[0], "from", "optional", "selector"}, field)
    _str(s[ops[0]], f"{field}.{ops[0]}", 500)
    _need("selector" not in s or ops[0] == "press", f"{field}: 'selector' belongs to press steps only")
    if "selector" in s:
        _str(s["selector"], f"{field}.selector", 500)
    _need(("from" in s) == (ops[0] == "fill"), f"{field}: 'from' belongs to fill steps only, and fill needs it")
    _need("from" not in s or s["from"] in STEP_FROM, f"{field}.from: one of {STEP_FROM}")
    _need(isinstance(s.get("optional", False), bool), f"{field}.optional: need a boolean")


def _recipe(r, field):
    _keys(r, RECIPE_KEYS, field)
    for i, s in enumerate(_list(r.get("steps", []), f"{field}.steps", 40)):
        _step(s, f"{field}.steps[{i}]")
    if "successCheck" in r:
        _keys(r["successCheck"], {"urlMatches", "selector"}, f"{field}.successCheck")
        _need(r["successCheck"], f"{field}.successCheck: need urlMatches or selector")
        for k, v in r["successCheck"].items():
            _str(v, f"{field}.successCheck.{k}", 500)
    if "logout" in r:
        _keys(r["logout"], {"steps"}, f"{field}.logout")
        for i, s in enumerate(_list(r["logout"].get("steps", []), f"{field}.logout.steps", 20)):
            _step(s, f"{field}.logout.steps[{i}]")
    if "challenge" in r:
        _keys(r["challenge"], {"codeSelector", "submit", "remember"}, f"{field}.challenge")
        _need("codeSelector" in r["challenge"] and "submit" in r["challenge"], f"{field}.challenge: need codeSelector and submit")
        for k, v in r["challenge"].items():
            _str(v, f"{field}.challenge.{k}", 500)
    for key in ("trustCookies", "trustStorageKeys"):
        for i, p in enumerate(_list(r.get(key, []), f"{field}.{key}", 20)):
            try:
                re.compile(_str(p, f"{field}.{key}[{i}]", 200))
            except re.error as e:
                raise SiteError(f"{field}.{key}[{i}]: bad regular expression ({e})")
    t = r.get("timeoutSeconds", 45)
    _need(isinstance(t, int) and not isinstance(t, bool) and 1 <= t <= 300, f"{field}.timeoutSeconds: 1..300")


def _oauth(o, field):
    _keys(o, OAUTH_KEYS, field)
    _need(o.get("flow") in ("device", "redirect"), f"{field}.flow: device or redirect")
    _url(o.get("tokenUrl"), f"{field}.tokenUrl")
    for k in ("authUrl", "deviceUrl", "revokeUrl"):
        _url(o.get(k), f"{field}.{k}", nullable=True)
    _need(o.get("flow") != "redirect" or o.get("authUrl"), f"{field}.authUrl: needed for the redirect flow")
    _need(o.get("flow") != "device" or o.get("deviceUrl"), f"{field}.deviceUrl: needed for the device flow")
    _str(o.get("clientId"), f"{field}.clientId", 300)
    sc = _list(o.get("scopes"), f"{field}.scopes", 40)
    _need(sc and all(isinstance(s, str) and 0 < len(s) <= 200 and " " not in s for s in sc), f"{field}.scopes: need non-empty scope names")
    t = o.get("accessTtlMaxMinutes", ABSOLUTE_MAX_MINUTES)
    _need(isinstance(t, int) and not isinstance(t, bool) and 1 <= t <= ABSOLUTE_MAX_MINUTES, f"{field}.accessTtlMaxMinutes: 1..{ABSOLUTE_MAX_MINUTES}")


def validate(site):
    """Return the site (with maxMinutes filled in) or raise SiteError naming the first problem."""
    _keys(site, TOP_KEYS, "site")
    _need(site.get("schema") == 1, "schema: must be 1")
    _need(isinstance(site.get("id"), str) and ID_RE.match(site["id"]) is not None, "id: ^[a-z0-9][a-z0-9-]{0,40}$")
    _str(site.get("displayName"), "displayName", 80)
    _need(site.get("type") in TYPES, f"type: one of {TYPES}")
    _need(site.get("kind") in KINDS, f"kind: one of {KINDS}")
    _str(site.get("purpose"), "purpose", 200)
    for h in _list(site.get("allowedHosts"), "allowedHosts", 20):
        _need(isinstance(h, str) and HOST_RE.match(h) is not None, "allowedHosts: need host names in lower case")
    _need(site["allowedHosts"], "allowedHosts: at least one host")
    for a in _list(site.get("allowedAgents"), "allowedAgents", 200):
        _need(isinstance(a, str) and UUID_RE.match(a) is not None, "allowedAgents: need agent UUIDs")
    for r in _list(site.get("roles"), "roles", 10):
        _str(r, "roles[]", 30)
    m = site.get("maxMinutes", DEFAULT_MAX_MINUTES)
    _need(isinstance(m, int) and not isinstance(m, bool) and 1 <= m <= ABSOLUTE_MAX_MINUTES, f"maxMinutes: 1..{ABSOLUTE_MAX_MINUTES}")
    site["maxMinutes"] = m
    if site["type"] == "oauth":
        _need(site.get("oauth") is not None and site.get("recipe") is None, "oauth sites need 'oauth' and no 'recipe'")
        _oauth(site["oauth"], "oauth")
        _need(site.get("loginUrl") is None and site.get("logoutUrl") is None, "oauth sites have no loginUrl or logoutUrl")
    else:
        _need(site.get("oauth") is None, "only oauth sites carry 'oauth'")
        _url(site.get("loginUrl"), "loginUrl")
        _url(site.get("logoutUrl"), "logoutUrl", nullable=True)
        _need(isinstance(site.get("recipe"), dict), "recipe: need an object")
        _recipe(site["recipe"], "recipe")
        _need("successCheck" in site["recipe"], "recipe.successCheck is mandatory")
        _need(site["type"] != "password-totp" or site["recipe"].get("steps"), "password-totp sites need recipe.steps")
    _need(isinstance(site.get("acceptNoLogout", False), bool), "acceptNoLogout: need a boolean")
    return site


def credential_name(site):
    return ("oauth-" if site["type"] == "oauth" else "web-") + site["id"]


def description(site):
    """The credential_description the gatekeeper sees (TRUSTED: written by the owner in the site file)."""
    roles = ", ".join(site["roles"]) or "none listed"
    if site["type"] == "oauth":
        return "OAuth access token for %s (kind: %s; purpose: %s; roles: %s). Access token only, no refresh token." % (
            site["id"], site["kind"], site["purpose"], roles)
    return "Login for site %s (kind: %s; purpose: %s; roles: %s). Browser session only, no password." % (
        site["id"], site["kind"], site["purpose"], roles)


def load_all(directory):
    """({id: site}, {file: error}) for every *.json in the directory. A broken file is reported, never half-used."""
    sites, errors = {}, {}
    try:
        names = sorted(n for n in os.listdir(directory) if n.endswith(".json"))
    except FileNotFoundError:
        return sites, errors
    for n in names:
        try:
            with open(os.path.join(directory, n)) as f:
                site = validate(json.load(f))
            _need(n == site["id"] + ".json", "file name must be <id>.json")
            sites[site["id"]] = site
        except (OSError, ValueError) as e:
            errors[n] = str(e)
    return sites, errors


def find(sites, credential):
    """The site a credential name points at (web-<id> or oauth-<id>), or None."""
    for prefix, oauth in (("web-", False), ("oauth-", True)):
        if credential.startswith(prefix):
            s = sites.get(credential[len(prefix):])
            return s if s is not None and (s["type"] == "oauth") == oauth else None
    return None
