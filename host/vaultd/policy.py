"""Hard ceilings, loaded from the root-owned policy.json. Pure code, no I/O except load().

The ceilings run before the judge and again when its verdict arrives; the judge can only deny or shorten,
never widen. The requester states the lease length in whole minutes; there is no default.
Schema: agents{uuid: role}, never[globs], roles{role: [class]}, classes{name: {match, description, max_minutes, scopes, narrow_minutes}}.
"""
import fnmatch
import json
import re
from dataclasses import dataclass

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
ABSOLUTE_MAX_MINUTES = 480   # no lease is longer, whatever the policy or a site file says
DEFAULT_MAX_MINUTES = 60     # class without max_minutes (and a site file without maxMinutes)
DEFAULT_NARROW_MINUTES = 30  # judge option a
CLASS_KEYS = {"match", "description", "max_minutes", "scopes", "narrow_minutes"}


@dataclass(frozen=True)
class Ceiling:
    ok: bool
    code: str = ""         # first failing ceiling (see Policy.check), "" when ok
    cls: str = ""          # credential class name
    max_minutes: int = 0   # longest lease allowed for this request
    narrow_minutes: int = 0
    scopes: tuple = ()


def _patterns(value):
    return [value] if isinstance(value, str) else list(value)


class Policy:
    def __init__(self, data):
        self.never = list(data.get("never", []))
        self.roles = {r: list(c) for r, c in data.get("roles", {}).items()}
        self.classes = data.get("classes", {})
        # agent uuid -> role. The ceilings use THIS role, never one reported by Paperclip or the plugin.
        self.agents = {str(a): str(r) for a, r in data.get("agents", {}).items()}
        for name, c in self.classes.items():
            if unknown := set(c) - CLASS_KEYS:
                raise ValueError(f"class {name}: unknown keys {sorted(unknown)}")
            if not _patterns(c.get("match", [])) or not c.get("scopes"):
                raise ValueError(f"class {name}: need match and scopes")
            if not 0 < self.max_minutes(c) <= ABSOLUTE_MAX_MINUTES or self.narrow_minutes(c) <= 0:
                raise ValueError(f"class {name}: max_minutes must be 1..{ABSOLUTE_MAX_MINUTES} and narrow_minutes > 0")
        for r, names in self.roles.items():
            for n in names:
                if n not in self.classes:
                    raise ValueError(f"role {r}: class {n!r} is not defined")
        for a, r in self.agents.items():
            if r not in self.roles:
                raise ValueError(f"agent {a}: pinned role {r!r} is not in 'roles'")

    @classmethod
    def load(cls, path):
        with open(path) as f:
            return cls(json.load(f))

    def role_of(self, agent_id):
        """The policy-pinned role of an agent, or None (the request is denied: agent_unpinned)."""
        return self.agents.get(agent_id)

    def classify(self, credential):
        for name, c in self.classes.items():
            if any(fnmatch.fnmatchcase(credential, p) for p in _patterns(c["match"])):
                return name, c
        return None, None

    @staticmethod
    def max_minutes(c):
        return int(c.get("max_minutes", DEFAULT_MAX_MINUTES))

    @staticmethod
    def narrow_minutes(c):
        return int(c.get("narrow_minutes", DEFAULT_NARROW_MINUTES))

    def is_never(self, credential):
        return credential.startswith("vault") or any(fnmatch.fnmatchcase(credential, p) for p in self.never)

    def check(self, role, credential, minutes, agent_id=None, site=None):
        """The Ceiling for a request; the first failing ceiling wins. Codes: bad_target (no class), never_list, role_class,
        site_agent_not_allowed (a site file lists allowedAgents), minutes_missing (absent, non-integer or < 1),
        minutes_over_max (above the class maximum, the site's maxMinutes and 480; nothing is clamped here)."""
        name, c = self.classify(credential)
        if c is None:
            return Ceiling(False, "bad_target")
        if self.is_never(credential):
            return Ceiling(False, "never_list", name)
        if name not in self.roles.get(role, []):
            return Ceiling(False, "role_class", name)
        if site is not None and agent_id not in site["allowedAgents"]:
            return Ceiling(False, "site_agent_not_allowed", name)
        top = min(self.max_minutes(c), ABSOLUTE_MAX_MINUTES)
        if site is not None:
            top = min(top, site["maxMinutes"], (site.get("oauth") or {}).get("accessTtlMaxMinutes", ABSOLUTE_MAX_MINUTES))
        narrow = min(self.narrow_minutes(c), top)
        scopes = tuple(c["scopes"])
        if isinstance(minutes, bool) or not isinstance(minutes, int) or minutes < 1:
            return Ceiling(False, "minutes_missing", name, top, narrow, scopes)
        if minutes > top:
            return Ceiling(False, "minutes_over_max", name, top, narrow, scopes)
        return Ceiling(True, "", name, top, narrow, scopes)

    def description(self, cls):
        return self.classes[cls].get("description", "Credential of class " + cls)

    def view(self):
        """The policy as shown to the plugin's read-only Ceilings tab."""
        return {"agents": dict(self.agents), "never": list(self.never), "roles": {r: list(c) for r, c in self.roles.items()},
                "classes": {n: {"match": _patterns(c["match"]), "description": self.description(n),
                                "maxMinutes": min(self.max_minutes(c), ABSOLUTE_MAX_MINUTES),
                                "narrowMinutes": self.narrow_minutes(c), "scopes": list(c["scopes"])}
                            for n, c in self.classes.items()}}
