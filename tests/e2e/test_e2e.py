"""End to end, with nothing between the components faked: the real vaultd, the real helper with real headless Chromium, the plugin's
real worker logic (tests/e2e/plugin_driver.mjs: tools, actions, jobs, signed client, verdict provider, delivery) over a mocked
Paperclip context, a fake login site (tests/fakes/fake_site.py), a fake OAuth provider (tests/fakes/fake_oauth.py) and a local
chat-completions server standing in for the verdict model.

Everything lives in one scratch directory (config, state, sockets, credentials, workspaces); vaultd runs without systemd
(plugin_uid = the current uid), the helper reads its credentials from a scratch directory. Every process this test starts is
stopped in teardown by pid, and so are the browsers the helper left behind.

The tests are ordered (test_01 ... test_11) and share the running stack: enrolment, the judge-test gate, the login lease from
request to logout, ceilings, verdict and signature negatives, an OAuth token lease, lease expiry, and a leak check.

Heavy (Chromium): run it under the host's job lock. SKIP_BROWSER=1 skips it loudly.
Run: python3 -I -B -m unittest discover -s tests/e2e"""
import base64
import json
import os
import queue
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
HOST = os.path.join(REPO, "host")
HELPER = os.path.join(HOST, "helper")
DRIVER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "plugin_driver.mjs")
FAKE_SITE = os.path.join(REPO, "tests", "fakes", "fake_site.py")
FAKE_OAUTH = os.path.join(REPO, "tests", "fakes", "fake_oauth.py")
VAULTCTL = os.path.join(HOST, "bin", "vaultctl")
SCENARIOS = os.path.join(HOST, "judge-tests", "scenarios.jsonl")
sys.path.insert(0, HOST)

from vaultd import audit, judge  # noqa: E402
from vaultd.helperclient import HelperClient  # noqa: E402
from vaultd.server import Enrolment  # noqa: E402

SKIP = os.environ.get("SKIP_BROWSER") == "1"
NODE = shutil.which("node")


def placeholder_id(char, n):
    """A UUID-shaped placeholder id: eight copies of `char`, then 0000-4000-8000 and the number."""
    return "%s-0000-4000-8000-%012d" % (char * 8, n)


COMPANY = placeholder_id("c", 1)
PROJECT = placeholder_id("b", 1)
ADMIN, PLAIN_USER = "user-admin", "user-plain"
MODEL = "e2e-model"
USER, PASSWORD, TOTP_SECRET = "tester@example.test", "correct horse battery", "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
REASON = "Click through the staging forms to verify the due-date field."
SITE_MAX = 30           # the site file's maxMinutes; the web-login class allows 120, so 45 minutes is over the SITE's maximum

# agent key -> number in its placeholder ids
AGENT_KEYS = {"main": 1, "ceil": 2, "split": 3, "lock": 4, "notallowed": 5, "expiry": 6}


def wait_for(cond, seconds, what, step=0.1):
    end = time.time() + seconds
    while time.time() < end:
        got = cond()
        if got:
            return got
        time.sleep(step)
    raise AssertionError("timed out after %ds waiting for %s" % (seconds, what))


def read_text(path):
    with open(path) as f:
        return f.read()


def http_json(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"null")
        finally:
            e.close()


def cookie_header(cookies):
    return "; ".join("%s=%s" % (c["name"], c["value"]) for c in cookies)


def iso_in(seconds):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + seconds))


def descendants(pid):
    """Live (non-zombie) descendants of pid, read from /proc: [(pid, cmdline)]. No pattern matching on names."""
    children = {}
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        try:
            with open("/proc/%s/stat" % name) as f:
                stat_line = f.read()
            state, ppid = stat_line[stat_line.rindex(")") + 2:].split(" ")[:2]
            if state == "Z":
                continue
            with open("/proc/%s/cmdline" % name, "rb") as f:
                cmd = f.read().replace(b"\0", b" ").decode(errors="replace").strip()
        except OSError:
            continue
        children.setdefault(int(ppid), []).append((int(name), cmd))
    found, todo = [], [pid]
    while todo:
        for child in children.get(todo.pop(), []):
            found.append(child)
            todo.append(child[0])
    return found


class FakeProvider:
    """A local OpenAI-compatible chat-completions server for the verdict model.

    Prompts of the judge-test scenarios get the scenario's expected verdict (the oracle of host/judge-tests/score.py). Every other
    prompt (a real request) takes its answer from `flow`, one entry per call (the plugin asks k=2 times); an empty queue answers
    a deny so a forgotten setup cannot approve anything."""

    def __init__(self):
        sec = judge.load_prompt(judge.DEFAULT_PROMPT)
        self.scenarios = {}
        with open(SCENARIOS, encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    s = json.loads(line)
                    self.scenarios[judge.render_prompt(sec, s["request"])] = s
        self.flow = []
        self.lock = threading.Lock()
        self.calls = {"scenario": 0, "flow": 0}
        self.bad_requests = []          # what the plugin sent that is not the documented shape
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_):
                pass

            def _send(self, status, obj):
                data = json.dumps(obj).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                if self.path == "/v1/models":
                    return self._send(200, {"data": [{"id": MODEL}, {"id": "other-model"}]})
                self._send(404, {"error": "not found"})

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"{}")
                if self.path != "/v1/chat/completions" or body.get("model") != MODEL:
                    return self._send(404, {"error": "unknown model or path"})
                rf = body.get("response_format") or {}
                schema = (rf.get("json_schema") or {})
                if rf.get("type") != "json_schema" or schema.get("strict") is not True or "decision" not in json.dumps(schema):
                    outer.bad_requests.append("response_format")
                msgs = body.get("messages") or []
                prompt = msgs[0].get("content") if len(msgs) == 1 else None
                if not isinstance(prompt, str):
                    outer.bad_requests.append("messages")
                    return self._send(400, {"error": "bad messages"})
                self._send(200, {"choices": [{"message": {"content": json.dumps(outer.answer(prompt))}}]})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()

    def answer(self, prompt):
        scn = self.scenarios.get(prompt)
        with self.lock:
            if scn is not None:
                self.calls["scenario"] += 1
                d, minutes = scn["expected"], scn["request"]["duration_min"]
                return {"decision": d, "max_minutes": (min(minutes, 30) if d == "a" else minutes) if d in "ab" else 0, "reason": "oracle"}
            self.calls["flow"] += 1
            return self.flow.pop(0) if self.flow else {"decision": "c", "max_minutes": 0, "reason": "no answer queued"}

    def queue(self, *answers):
        with self.lock:
            self.flow = list(answers)

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)


def approve(minutes, d="b"):
    return {"decision": d, "max_minutes": minutes, "reason": "fits the ticket"}


DENY = {"decision": "c", "max_minutes": 0, "reason": "not justified"}
LOCK = {"decision": "d", "max_minutes": 0, "reason": "hostile request"}


class DriverError(Exception):
    def __init__(self, code, message):
        super().__init__("%s: %s" % (code, message))
        self.code, self.message = code, message


class PluginDriver:
    """The Node process that runs the plugin worker logic. One JSON line per command and per reply."""

    def __init__(self, cfg_path, err_file):
        self.proc = subprocess.Popen([NODE, DRIVER, cfg_path], cwd=REPO, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=err_file,
                                     env={"PATH": os.environ["PATH"], "HOME": os.environ.get("HOME", "/nonexistent")}, text=True, bufsize=1)
        self.waiting, self.lock, self.n = {}, threading.Lock(), 0
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        for line in self.proc.stdout:
            msg = json.loads(line)
            with self.lock:
                q = self.waiting.pop(msg["id"], None)
            if q:
                q.put(msg)

    def call(self, cmd, timeout=120, **kw):
        q = queue.Queue()
        with self.lock:
            self.n += 1
            n = self.n
            self.waiting[n] = q
        self.proc.stdin.write(json.dumps(dict(kw, id=n, cmd=cmd)) + "\n")
        self.proc.stdin.flush()
        try:
            msg = q.get(timeout=timeout)
        except queue.Empty:
            raise AssertionError("plugin driver gave no answer to %s within %ds (alive: %s)" % (cmd, timeout, self.proc.poll() is None))
        if not msg["ok"]:
            raise DriverError(msg["error"]["code"], msg["error"]["message"])
        return msg["result"]

    def stop(self):
        try:
            self.proc.stdin.close()
        except OSError:
            pass
        try:
            self.proc.wait(15)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.proc.stdout.close()


def wire(sock_path, line):
    """One raw request line to vaultd's plugin socket, the one response line parsed."""
    with socket.socket(socket.AF_UNIX) as s:
        s.settimeout(15)
        s.connect(sock_path)
        s.sendall(line if isinstance(line, bytes) else line.encode())
        s.sendall(b"\n")
        return json.loads(s.makefile("rb").readline())


@unittest.skipIf(SKIP, "SKIP_BROWSER=1: the end-to-end suite needs Chromium and is SKIPPED (not run)")
class EndToEnd(unittest.TestCase):
    # ---- the stack --------------------------------------------------------------------------------------------------
    @classmethod
    def setUpClass(cls):
        cls.procs = []                       # (name, Popen), stopped in reverse order
        cls.browser_pids = set()
        cls.outputs = []
        cls.root = None
        cls.provider = None
        cls.access_token, cls.main_cookies = "", []
        cls.tool_results = []                # every tool answer: nothing secret may be in them
        cls.addClassCleanup(cls.stop_all)           # registered first = runs last: after the log files were closed, it stops everything
        if NODE is None:
            raise AssertionError("node is not on PATH")
        for need in (os.path.join(HELPER, "node_modules", "playwright-core"), os.path.join(REPO, "plugin", "node_modules", "@paperclipai")):
            if not os.path.isdir(need):
                raise AssertionError("missing %s: run `npm ci --ignore-scripts` in that package first (scripts/test-all.sh does)" % need)
        cls.root = tempfile.mkdtemp(prefix="pce-")
        for d in ("sites", "creds", "vaultd-creds", "state", "log", "roots", "logs"):
            os.mkdir(cls.p(d), 0o700)
        os.mkdir(cls.p("pdata"), 0o700)
        cls.agent = {k: {"agentId": placeholder_id("a", n), "runId": placeholder_id("e", n), "issueId": placeholder_id("d", n),
                         "execWorkspaceId": placeholder_id("6", n), "issueTitle": "[Test] Verify the due-date field", "workspace": cls.p("roots", "ws-" + k)}
                     for k, n in AGENT_KEYS.items()}
        for a in cls.agent.values():
            os.mkdir(a["workspace"])
        cls.provider = FakeProvider()

        cls.site = cls.start_fake("site", FAKE_SITE, ["--no-challenge"])
        cls.oauth = cls.start_fake("oauth", FAKE_OAUTH, ["--interval", "1", "--pending", "1"])
        cls.write_site_files()
        cls.write_policy()
        cls.write_helper_files()
        cls.sock = cls.p("plugin.sock")
        cls.admin_sock = cls.p("admin.sock")
        cls.audit_path = cls.p("log", "audit.jsonl")

        # the plugin side starts first: its installCommand action creates the signing key and the one-time code
        cls.plugin_config = {
            "adminUserIds": [ADMIN], "workspaceRoots": [cls.p("roots")], "agentHomeRoot": cls.p("roots", "homes"), "dataDir": cls.p("pdata"),
            "socketPath": cls.sock, "toolWaitMs": 1500,
            "judge": {"baseUrl": "http://127.0.0.1:%d/v1" % cls.provider.port, "k": 2, "temperature": 0.2, "perCallTimeoutMs": 20000}}
        with open(cls.p("driver.json"), "w") as f:
            json.dump({"companyId": COMPANY, "projectId": PROJECT, "adminUserId": ADMIN, "plainUserId": PLAIN_USER, "agents": cls.agent,
                       "pluginConfig": cls.plugin_config,
                       "pins": {"version": "0.1.0", "baseUrl": "https://example.org/vault/", "installVaultSha256": "0" * 64}}, f)
        err = cls.open_log("driver.err")
        cls.plugin = PluginDriver(cls.p("driver.json"), err)
        cls.procs.append(("plugin driver", cls.plugin))

    @classmethod
    def p(cls, *parts):
        return os.path.join(cls.root, *parts)

    @classmethod
    def open_log(cls, name):
        f = open(cls.p("logs", name), "w+")
        cls.addClassCleanup(f.close)
        cls.outputs.append(cls.p("logs", name))
        return f

    @classmethod
    def start_fake(cls, name, script, args):
        proc = subprocess.Popen([sys.executable, "-I", "-B", script] + args, stdout=subprocess.PIPE, stderr=cls.open_log(name + ".err"), text=True)
        cls.procs.append((name, proc))
        port = json.loads(proc.stdout.readline())["port"]
        cls.addClassCleanup(proc.stdout.close)
        return {"port": port, "origin": "http://127.0.0.1:%d" % port, "host": "127.0.0.1:%d" % port}

    @classmethod
    def write_site_files(cls):
        origin = cls.site["origin"]
        agents = [cls.agent[k]["agentId"] for k in ("main", "ceil", "split", "lock", "expiry")]      # not "notallowed"
        login = {"schema": 1, "id": "fake-todo", "displayName": "Fake todo staging", "type": "password-totp", "kind": "test",
                 "purpose": "UI and flow testing of the todo-api staging app", "loginUrl": origin + "/login", "logoutUrl": None,
                 "allowedHosts": [cls.site["host"]], "allowedAgents": agents, "roles": ["QA"], "maxMinutes": SITE_MAX,
                 "recipe": {"steps": [{"fill": "#email", "from": "username"}, {"click": "#next"}, {"fill": "#password", "from": "password"},
                                      {"click": "#login"}, {"fill": "#otp", "from": "totp", "optional": True}, {"click": "#verify", "optional": True}],
                            "successCheck": {"urlMatches": "^" + re.escape(origin) + "/dashboard", "selector": "#avatar"},
                            "logout": {"steps": [{"click": "#logout"}]}, "trustCookies": ["^device_"], "timeoutSeconds": 30},
                 "oauth": None}
        drive = {"schema": 1, "id": "drive", "displayName": "Shared drive", "type": "oauth", "kind": "owner", "purpose": "read the shared drive",
                 "loginUrl": None, "logoutUrl": None, "allowedHosts": [cls.oauth["host"]], "allowedAgents": [cls.agent["main"]["agentId"]],
                 "roles": ["QA"], "maxMinutes": 60, "recipe": None,
                 "oauth": {"flow": "device", "authUrl": cls.oauth["origin"] + "/authorize", "tokenUrl": cls.oauth["origin"] + "/token",
                           "deviceUrl": cls.oauth["origin"] + "/device", "revokeUrl": cls.oauth["origin"] + "/revoke", "clientId": "client-1",
                           "scopes": ["drive.read"], "accessTtlMaxMinutes": 45}}
        for s in (login, drive):
            with open(cls.p("sites", s["id"] + ".json"), "w") as f:
                json.dump(s, f)

    @classmethod
    def write_policy(cls):
        policy = {"agents": {a["agentId"]: "QA" for a in cls.agent.values()}, "never": ["openrouter*", "*admin*", "*prod-deploy*"],
                  "roles": {"QA": ["web-login", "oauth-token"]},
                  "classes": {"web-login": {"description": "Browser session.", "match": "web-*", "max_minutes": 120, "scopes": ["use"]},
                              "oauth-token": {"description": "OAuth access token.", "match": "oauth-*", "max_minutes": 60, "scopes": ["use"]}}}
        with open(cls.p("policy.json"), "w") as f:
            json.dump(policy, f)

    @classmethod
    def write_helper_files(cls):
        with open(cls.p("creds", "vault-helper.storekey"), "wb") as f:
            f.write(os.urandom(32))
        for part, value in (("username", USER), ("password", PASSWORD), ("totp", TOTP_SECRET)):
            with open(cls.p("creds", "vault-helper.site.fake-todo." + part), "w") as f:
                f.write(value)
        cls.token_file, cls.admin_token_file = cls.p("helper.token"), cls.p("helper-admin.token")
        for path in (cls.token_file, cls.admin_token_file):
            with open(path, "w") as f:
                f.write(os.urandom(32).hex() + "\n")
        cls.helper_sock = cls.p("helper.sock")
        with open(cls.p("helper.json"), "w") as f:
            json.dump({"socketPath": cls.helper_sock, "socketGroup": None, "tokenFile": cls.token_file, "adminTokenFile": cls.admin_token_file,
                       "sitesDir": cls.p("sites"), "stateDir": cls.p("state"), "credentialsDir": cls.p("creds"), "allowNoSandbox": True}, f)

    @classmethod
    def start_helper(cls):
        env = dict(os.environ, PLAYWRIGHT_BROWSERS_PATH=os.environ.get("PLAYWRIGHT_BROWSERS_PATH") or os.path.expanduser("~/.cache/ms-playwright"))
        env.pop("CREDENTIALS_DIRECTORY", None)
        proc = subprocess.Popen([NODE, os.path.join(HELPER, "main.js"), "--config", cls.p("helper.json")], cwd=HELPER, env=env,
                                stdout=cls.open_log("helper.out"), stderr=cls.open_log("helper.err"))
        cls.procs.append(("helper", proc))
        cls.wait_socket(cls.helper_sock, proc, "helper.err")
        cls.helper = HelperClient(cls.helper_sock, cls.token_file)
        cls.helper_admin = HelperClient(cls.helper_sock, cls.admin_token_file)
        ping = wait_for(lambda: cls.try_ping(), 60, "the helper's first ping")
        if not ping.get("browsers"):
            raise AssertionError("the helper cannot start Chromium. Install it with: (cd host/helper && "
                                 "PLAYWRIGHT_BROWSERS_PATH=$HOME/.cache/ms-playwright npx playwright-core install chromium), or set SKIP_BROWSER=1")

    @classmethod
    def try_ping(cls):
        try:
            return cls.helper.ping()
        except Exception:
            return None

    @classmethod
    def start_vaultd(cls):
        cfg = {"plugin_uid": os.getuid(), "allowed_company_ids": [COMPANY], "policy_path": cls.p("policy.json"), "sites_dir": cls.p("sites"),
               "enrol_path": cls.p("enrol.json"), "plugin_socket": cls.sock, "admin_socket": cls.admin_sock, "helper_socket": cls.helper_sock,
               "helper_token_path": cls.token_file, "audit_path": cls.audit_path, "db_path": cls.p("state", "vault.db"),
               "key_path": cls.p("state", "plugin-key.json"), "verdict_timeout_s": 120}
        with open(cls.p("config.json"), "w") as f:
            json.dump(cfg, f)
        # this test is the plugin user AND vaultd's user, which a real config refuses: only the own-uid lookup is stubbed
        stub = "import sys, vaultd.__main__ as m; m.own_uid = lambda: -1; sys.exit(m.main(['serve', '--config', sys.argv[1]]))"
        proc = subprocess.Popen([sys.executable, "-s", "-B", "-c", stub, cls.p("config.json")], cwd=HOST,
                                env={"PATH": os.environ["PATH"], "PYTHONPATH": HOST, "CREDENTIALS_DIRECTORY": cls.p("vaultd-creds")},
                                stdout=cls.open_log("vaultd.out"), stderr=cls.open_log("vaultd.err"))
        cls.procs.append(("vaultd", proc))
        cls.wait_socket(cls.sock, proc, "vaultd.err")
        cls.wait_socket(cls.admin_sock, proc, "vaultd.err")

    @classmethod
    def wait_socket(cls, path, proc, err_name):
        end = time.time() + 30
        while time.time() < end and not os.path.exists(path):
            if proc.poll() is not None:
                raise AssertionError("process exited (%s) before %s existed:\n%s" % (proc.returncode, path, read_text(cls.p("logs", err_name))[-2000:]))
            time.sleep(0.05)
        if not os.path.exists(path):
            raise AssertionError("%s did not appear" % path)

    @classmethod
    def stop_all(cls):
        """Every process this test started, in reverse order, by pid; then the browsers the helper left behind, by pid."""
        for name, proc in reversed(cls.procs):
            if isinstance(proc, PluginDriver):
                proc.stop()
                continue
            if name == "helper" and proc.poll() is None:
                cls.browser_pids |= {pid for pid, _ in descendants(proc.pid)}
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(15)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
            if proc.stdout:
                proc.stdout.close()
        cls.procs.clear()
        for pid in cls.browser_pids:
            try:
                os.kill(pid, 9)       # only a pid we saw as a descendant of our helper; ESRCH means it is already gone
            except ProcessLookupError:
                pass
        if cls.provider:
            cls.provider.close()
            cls.provider = None
        if cls.root:
            shutil.rmtree(cls.root, ignore_errors=True)

    # ---- small helpers ----------------------------------------------------------------------------------------------
    def tool(self, name, params, agent="main"):
        r = self.plugin.call("tool", name=name, params=params, agent=agent)
        type(self).tool_results.append(json.dumps(r))
        return r["data"] if "data" in r else r

    def action(self, key, params=None, as_="admin"):
        return self.plugin.call("action", key=key, params=params or {}, **{"as": as_})

    def request_login(self, agent, minutes=5, site="fake-todo", flow=None, **over):
        if flow is not None:
            self.provider.queue(*flow)
        params = dict({"site": site, "reason": REASON, "minutes": minutes}, **over)
        return self.tool("vault_request_login", params, agent)

    def poll_ready(self, agent, request_id, seconds=90):
        def done():
            r = self.tool("vault_request_status", {"requestId": request_id}, agent)
            return r if r["status"] not in ("pending", "preparing") else None
        return wait_for(done, seconds, "request %s to leave pending/preparing" % request_id, step=0.3)

    def vault(self, type_, **data):
        return self.plugin.call("call", type=type_, data=data)

    def site_debug(self):
        return http_json(self.site["origin"] + "/_debug")[1]

    def oauth_debug(self):
        return http_json(self.oauth["origin"] + "/_debug")[1]

    def vaultctl(self, *args):
        r = subprocess.run([sys.executable, "-B", VAULTCTL] + list(args), capture_output=True, text=True,
                           env={"PATH": os.environ["PATH"], "VAULT_ADMIN_SOCKET": self.admin_sock})
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout

    def vault_dir(self, agent):
        return os.path.join(self.agent[agent]["workspace"], ".vault")

    def audit_events(self):
        with open(self.audit_path) as f:
            return [json.loads(l) for l in f if l.strip()]

    def decisions(self, agent):
        return [e for e in self.audit_events() if e.get("event") == "decision" and e.get("agentId") == self.agent[agent]["agentId"]]

    # ---- 01 enrolment ------------------------------------------------------------------------------------------------
    def test_01_enrolment_with_a_one_time_code(self):
        cls = type(self)
        cmd = self.action("installCommand")
        self.assertTrue(cmd["ok"])
        code = re.search(r"--enrol (\S+)", cmd["command"]).group(1)
        self.assertRegex(code, r"^[A-Z0-9]{4}(-[A-Z0-9]{4}){3}$")
        self.assertEqual(oct(os.stat(self.p("pdata", "plugin-key.pem")).st_mode & 0o777), "0o600")
        # what the root installer does: only the HASH of the code goes to /etc/vault/enrol.json (here: the scratch directory)
        cls.install_id = "inst-" + os.urandom(12).hex()
        with open(self.p("enrol.json"), "w") as f:
            json.dump({"installId": self.install_id, "codeHash": Enrolment.code_hash(code), "expiresAt": iso_in(3600), "serviceUid": os.getuid()}, f)
        self.assertNotIn(code, read_text(self.p("enrol.json")))
        self.start_helper()
        self.start_vaultd()
        self.plugin.call("job", name="enrol-tick")
        state = self.plugin.call("state")
        self.assertEqual(state["install"]["installId"], self.install_id)
        status = self.action("vaultStatus")
        self.assertTrue(status["enrolled"])
        self.assertEqual((status["vaultd"]["reachable"], status["vaultd"]["helper"]), (True, "up"))
        self.assertEqual(self.vault("hello")["installId"], self.install_id)       # signed calls work from now on
        self.assertEqual(oct(os.stat(self.p("state", "plugin-key.json")).st_mode & 0o777), "0o600")

    # ---- 02 no cleared model = no grant ------------------------------------------------------------------------------
    def test_02_without_a_cleared_model_nothing_is_granted(self):
        self.provider.queue(approve(5), approve(5))
        r = self.request_login("main", 5)
        self.assertEqual(r["status"], "denied")
        self.assertEqual(r["code"], "provider_error")          # the plugin refused to judge: no verdict, vaultd denies
        self.assertEqual(self.provider.calls["flow"], 0, "the model must not even be asked before the judge tests passed")
        self.provider.queue()

    # ---- 03 judge tests and model selection --------------------------------------------------------------------------
    def test_03_judge_tests_clear_the_model(self):
        models = self.action("refreshModels")
        self.assertIn(MODEL, [m["id"] for m in models["models"]])
        with self.assertRaises(DriverError) as cm:             # selection needs a passing record
            self.action("selectModel", {"model": MODEL})
        self.assertEqual(cm.exception.code, "not_cleared")
        started = self.action("runJudgeTests", {"model": MODEL})
        self.assertTrue(started["started"])

        def finished():
            run = self.action("judgeTestStatus", as_="user")["run"]
            return run if run and run["state"] != "running" else None
        run = wait_for(finished, 240, "the judge test run", step=0.5)
        self.assertEqual(run["state"], "done", run)
        self.assertTrue(run["clean"], run)
        self.assertEqual((run["metrics"]["injection_granted"], run["metrics"]["over_grants"]), (0, 0))
        self.assertTrue(run["postedToVaultd"])
        self.assertEqual(self.provider.bad_requests, [])
        self.assertGreater(self.provider.calls["scenario"], 400)
        self.assertEqual(self.action("selectModel", {"model": MODEL})["selected"]["model"], MODEL)
        gate = self.action("judgeStatus", as_="user")["gate"]
        self.assertTrue(gate["cleared"], gate)
        with self.assertRaises(DriverError):                   # a plain user may read, not change
            self.action("selectModel", {"model": MODEL}, as_="user")
        with self.assertRaises(DriverError):                   # an agent may do neither
            self.action("runJudgeTests", {"model": MODEL}, as_="agent")
        type(self).provider_id = gate["provider"]

    # ---- 04 the login lease from request to logout -------------------------------------------------------------------
    def test_04_login_lease_end_to_end(self):
        listed = self.tool("vault_list_sites", {}, "main")
        self.assertEqual([s["id"] for s in listed["sites"]], ["fake-todo"])          # the OAuth site is not authorized yet: not offered
        self.assertEqual(self.tool("vault_list_sites", {}, "notallowed")["sites"], [])
        logins_before = self.site_debug()["logins"]
        first = self.request_login("main", 5, flow=[approve(5), approve(5)])
        self.assertIn(first["status"], ("pending", "preparing", "ready"), first)
        rid = first["requestId"]
        ready = first if first["status"] == "ready" else self.poll_ready("main", rid)
        self.assertEqual(ready["status"], "ready", ready)
        self.assertEqual(ready["minutes"], 5)
        self.assertEqual(set(ready) - {"status", "requestId", "message", "path", "expiresAt", "minutes"}, set())
        self.assertRegex(ready["path"], r"^\.vault/fake-todo-[0-9a-f]{8}\.session\.json$")

        # the file: in the agent's workspace, 0600, in a 0700 .vault with a .gitignore; the session is live at the site
        vdir = self.vault_dir("main")
        path = os.path.join(self.agent["main"]["workspace"], ready["path"])
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(vdir).st_mode), 0o700)
        self.assertEqual(read_text(os.path.join(vdir, ".gitignore")), "*\n")
        self.assertEqual(sorted(os.listdir(vdir)), sorted([".gitignore", os.path.basename(path)]))
        with open(path) as f:
            state = json.load(f)
        self.assertIn("sid", {c["name"] for c in state["cookies"]})
        type(self).main_cookies = state["cookies"]
        header = {"Cookie": cookie_header(state["cookies"])}
        self.assertEqual(http_json(self.site["origin"] + "/api/me", header)[0], 200)
        self.assertEqual(self.site_debug()["logins"], logins_before + 1)
        for c in state["cookies"]:                            # lifetime clamped to the lease end
            self.assertLessEqual(c["expires"], time.time() + 5 * 60 + 5)
        self.assertNotIn(PASSWORD, json.dumps(state))
        self.assertNotIn(TOTP_SECRET, json.dumps(state))

        # the lease at vaultd; the plugin's state and the agent's own poll agree
        leases = self.action("listLeases", as_="user")["leases"]
        mine = [l for l in leases if l["requestId"] == rid]
        self.assertEqual(len(mine), 1)
        self.assertEqual((mine[0]["state"], mine[0]["kind"], mine[0]["agentId"]), ("delivered", "login", self.agent["main"]["agentId"]))
        self.assertEqual([l["leaseId"] for l in self.helper.ping()["leases"]], [mine[0]["leaseId"]])
        again = self.tool("vault_request_status", {"requestId": rid}, "main")
        self.assertEqual((again["status"], again["path"]), ("ready", ready["path"]))
        other = self.tool("vault_request_status", {"requestId": rid}, "ceil")        # somebody else's request is unknown
        self.assertEqual((other["status"], other["code"]), ("failed", "unknown_request"))

        # the decision in the audit log: the model, the k raw samples, the minutes, the prompt hash
        approvals = [e for e in self.decisions("main") if e.get("decision") == "approve"]
        self.assertEqual(len(approvals), 1)
        d = approvals[0]
        self.assertEqual((d["model"], d["provider"], d["k"], d["minutes"], d["verdict"]), (MODEL, self.provider_id, 2, 5, "b"))
        self.assertEqual([s["decision"] for s in d["raw"]], ["b", "b"])
        self.assertRegex(d["promptSha256"], r"^[0-9a-f]{64}$")

        # lease end by an admin: vaultd -> helper logout; the fake site confirms the session is dead; the file is gone
        revoked = self.action("revokeLease", {"requestId": rid})
        self.assertTrue(revoked["ok"] and revoked["fileRemoved"], revoked)
        self.assertFalse(os.path.exists(path))
        wait_for(lambda: self.site_debug()["logouts"] >= 1, 15, "the server-side logout")
        self.assertEqual(self.site_debug()["sessions"], 0)
        self.assertEqual(http_json(self.site["origin"] + "/api/me", header)[0], 401, "the copied session must be dead at the site")
        self.assertEqual(self.helper.ping()["leases"], [])
        ended = [e for e in self.audit_events() if e.get("event") == "lease_end" and e.get("requestId") == rid]
        self.assertEqual([(e["reason"], e["logout"]) for e in ended], [("revoked", "ok")])
        self.assertEqual(self.tool("vault_request_status", {"requestId": rid}, "main")["status"], "ended")
        with self.assertRaises(DriverError):                  # a plain user cannot revoke
            self.action("revokeLease", {"requestId": rid}, as_="user")

    # ---- 05 a short lease is started now and ends by itself in test_10 -----------------------------------------------
    def test_05_start_a_one_minute_lease(self):
        first = self.request_login("expiry", 1, flow=[approve(1), approve(1)])
        rid = first["requestId"]
        ready = first if first["status"] == "ready" else self.poll_ready("expiry", rid)
        self.assertEqual(ready["status"], "ready", ready)
        path = os.path.join(self.agent["expiry"]["workspace"], ready["path"])
        self.assertTrue(os.path.exists(path))
        with open(path) as f:
            cookies = json.load(f)["cookies"]
        self.assertEqual(http_json(self.site["origin"] + "/api/me", {"Cookie": cookie_header(cookies)})[0], 200)
        type(self).expiry = {"requestId": rid, "path": path, "cookies": cookies, "logouts": self.site_debug()["logouts"]}

    # ---- 06 ceilings -------------------------------------------------------------------------------------------------
    def test_06_ceiling_negatives(self):
        asked = self.provider.calls["flow"]
        # minutes missing: the tool refuses before anything is sent, vaultd refuses it when sent anyway
        r = self.tool("vault_request_login", {"site": "fake-todo", "reason": REASON}, "ceil")
        self.assertEqual((r["status"], r["code"]), ("denied", "bad_params"))
        agent = self.agent["ceil"]
        create = {"agent": {"agentId": agent["agentId"], "runId": agent["runId"], "companyId": COMPANY, "issueId": agent["issueId"]},
                  "kind": "login", "target": "fake-todo", "reason": REASON,
                  "context": {"issue_title": agent["issueTitle"], "issue_project": "todo-api", "stage": "Test"}}
        for minutes in ({}, {"minutes": 0}, {"minutes": None}):
            got = self.vault("request.create", **dict(create, **minutes))
            self.assertEqual((got["state"], got["code"]), ("denied", "minutes_missing"), minutes)
            self.assertEqual(got["maxMinutes"], SITE_MAX)
        # over the maximum: the site's 30 minutes (the class allows 120), refused, not shortened
        r = self.request_login("ceil", SITE_MAX + 15)
        self.assertEqual((r["status"], r["code"], r["maxMinutes"]), ("denied", "minutes_over_max", SITE_MAX))
        r = self.request_login("ceil", 481)                    # the tool schema's own cap, still denied
        self.assertEqual(r["status"], "denied")
        # an agent the site does not list
        r = self.request_login("notallowed", 5)
        self.assertEqual((r["status"], r["code"]), ("denied", "site_agent_not_allowed"))
        # an unknown site
        r = self.request_login("ceil", 5, site="no-such-site")
        self.assertEqual((r["status"], r["code"]), ("denied", "bad_target"))
        self.assertEqual(self.provider.calls["flow"], asked, "a request that fails the ceilings never reaches the model")
        codes = [e["code"] for e in self.decisions("ceil") + self.decisions("notallowed") if e.get("decision") == "deny"]
        for want in ("minutes_missing", "minutes_over_max", "site_agent_not_allowed", "bad_target"):
            self.assertIn(want, codes)
        self.assertEqual(os.listdir(self.agent["notallowed"]["workspace"]), [])

    # ---- 07 verdicts -------------------------------------------------------------------------------------------------
    def test_07_verdict_negatives(self):
        # a split verdict (b + c) is a deny, and no lock
        r = self.request_login("split", 5, flow=[approve(5), DENY])
        self.assertEqual((r["status"], r["code"]), ("denied", "judge_deny"))
        self.assertNotIn(self.agent["split"]["agentId"], json.dumps(self.vault("ceilings.get")["lockedAgents"]))
        self.assertEqual(os.listdir(self.agent["split"]["workspace"]), [])
        d = [e for e in self.decisions("split") if e.get("decision") == "deny"][-1]
        self.assertEqual(sorted(s["decision"] for s in d["raw"]), ["b", "c"])
        self.assertEqual(d["aggregate"], "c")

        # a unanimous d locks the agent; the next request is refused at the door
        r = self.request_login("lock", 5, flow=[LOCK, LOCK])
        self.assertEqual((r["status"], r["code"]), ("denied", "judge_lock"))
        self.assertIn(self.agent["lock"]["agentId"], json.dumps(self.vault("ceilings.get")["lockedAgents"]))
        calls = self.provider.calls["flow"]
        r = self.request_login("lock", 5, flow=[approve(5), approve(5)])
        self.assertEqual((r["status"], r["code"]), ("denied", "agent_locked"))
        self.assertEqual(self.provider.calls["flow"], calls, "a locked agent's request never reaches the model")
        self.vaultctl("unlock", self.agent["lock"]["agentId"])
        self.assertNotIn(self.agent["lock"]["agentId"], json.dumps(self.vault("ceilings.get")["lockedAgents"]))
        self.provider.queue()

        # a verdict whose decision does not follow from its own raw samples is refused by vaultd (the plugin is not trusted)
        agent = self.agent["ceil"]
        created = self.vault("request.create", agent={"agentId": agent["agentId"], "runId": agent["runId"], "companyId": COMPANY,
                                                      "issueId": agent["issueId"]}, kind="login", target="fake-todo", reason=REASON, minutes=5,
                             context={"issue_title": agent["issueTitle"], "issue_project": "todo-api", "stage": "Test"})
        self.assertEqual(created["state"], "awaiting_verdict")
        forged = {"requestId": created["requestId"], "decision": "b", "minutes": 5, "k": 2, "raw": [DENY, DENY], "model": MODEL,
                  "provider": self.provider_id, "promptSha256": created["promptSha256"],
                  "renderedSha256": judge.sha256_text(created["prompt"])}
        got = self.vault("verdict.submit", **forged)
        self.assertEqual((got["state"], got["code"]), ("denied", "aggregate_mismatch"))
        # ... and so is one from a model that has no clean judge-test record
        created = self.vault("request.create", agent={"agentId": agent["agentId"], "runId": agent["runId"], "companyId": COMPANY,
                                                      "issueId": agent["issueId"]}, kind="login", target="fake-todo", reason=REASON, minutes=5,
                             context={"issue_title": agent["issueTitle"], "issue_project": "todo-api", "stage": "Test"})
        honest = dict(forged, requestId=created["requestId"], decision="b", raw=[approve(5), approve(5)], model="uncleared-model",
                      promptSha256=created["promptSha256"], renderedSha256=judge.sha256_text(created["prompt"]))
        got = self.vault("verdict.submit", **honest)
        self.assertEqual((got["state"], got["code"]), ("denied", "model_not_cleared"))
        self.assertEqual(os.listdir(agent["workspace"]), [])

    # ---- 08 signatures -----------------------------------------------------------------------------------------------
    def test_08_signature_negatives(self):
        signed = self.plugin.call("sign", type="hello", data={})
        env = json.loads(signed["line"])

        def reencode(**over):
            return json.dumps(dict(env, **over))
        msg = base64.urlsafe_b64decode(env["msg"] + "=" * (-len(env["msg"]) % 4))
        tampered_msg = base64.urlsafe_b64encode(msg + b" ").decode().rstrip("=")      # one byte more than what was signed
        bad_sig = base64.b64encode(bytes([base64.b64decode(env["sig"])[0] ^ 1]) + base64.b64decode(env["sig"])[1:]).decode()
        for what, line in (("message", reencode(msg=tampered_msg)), ("signature", reencode(sig=bad_sig))):
            got = wire(self.sock, line)
            self.assertFalse(got["ok"], what)
            self.assertEqual(got["error"]["code"], "bad_signature", what)
        got = wire(self.sock, reencode(kid="0" * 16))                                     # a key vaultd never enrolled
        self.assertFalse(got["ok"])
        self.assertIn(got["error"]["code"], ("bad_signature", "not_enrolled"))
        self.assertFalse(wire(self.sock, "{}")["ok"])
        # the untouched line is accepted once and refused as a replay the second time
        first = wire(self.sock, signed["line"])
        self.assertTrue(first["ok"], first)
        self.assertEqual(first["nonce"], signed["nonce"])
        again = wire(self.sock, signed["line"])
        self.assertFalse(again["ok"])
        self.assertEqual(again["error"]["code"], "replay")
        # a message for another install id
        other = self.plugin.call("sign", type="hello", data={}, installId="inst-" + "0" * 24)
        self.assertFalse(wire(self.sock, other["line"])["ok"])
        failures = [e for e in self.audit_events() if e.get("event") == "auth_fail"]
        self.assertGreaterEqual(len(failures), 4)

    # ---- 09 an OAuth token lease -------------------------------------------------------------------------------------
    def test_09_oauth_token_lease(self):
        # not authorized yet: the site is not ready
        r = self.tool("vault_request_credential", {"credential": "oauth-drive", "reason": REASON, "minutes": 10}, "main")
        self.assertEqual((r["status"], r["code"]), ("denied", "site_not_ready"))
        started = self.helper_admin.call("oauth.start", siteId="drive", flow="device")        # the owner authorizes (vault-site authorize)
        self.assertTrue(self.helper_admin.call("oauth.finish", handle=started["handle"])["authorized"])
        self.provider.queue(approve(10), approve(10))
        first = None

        def ask():
            nonlocal first
            first = self.tool("vault_request_credential", {"credential": "oauth-drive", "reason": REASON, "minutes": 10}, "main")
            return first if first["status"] != "denied" or first.get("code") not in ("site_not_ready", "rate_limited") else None
        wait_for(ask, 60, "the authorized site to be ready for requests", step=1.0)
        self.assertIn(first["status"], ("pending", "preparing", "ready"), first)
        rid = first["requestId"]
        ready = first if first["status"] == "ready" else self.poll_ready("main", rid)
        self.assertEqual(ready["status"], "ready", ready)
        self.assertRegex(ready["path"], r"^\.vault/oauth-drive-[0-9a-f]{8}\.token\.json$")
        path = os.path.join(self.agent["main"]["workspace"], ready["path"])
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        with open(path) as f:
            token = json.load(f)
        self.assertEqual(set(token), {"accessToken", "tokenType", "expiresAt", "scopes"})
        self.assertEqual((token["tokenType"], token["scopes"]), ("Bearer", ["drive.read"]))
        auth = {"Authorization": "Bearer " + token["accessToken"]}
        type(self).access_token = token["accessToken"]
        self.assertEqual(http_json(self.oauth["origin"] + "/api/me", auth)[0], 200)
        left = time.mktime(time.strptime(token["expiresAt"], "%Y-%m-%dT%H:%M:%SZ")) - time.mktime(time.gmtime())
        self.assertTrue(0 < left <= 10 * 60 + 5, left)          # clamped to the 10 minute lease, not the provider's hour
        self.assertNotIn("refresh", json.dumps(token).lower())  # the refresh token never leaves the helper
        self.assertTrue(self.action("revokeLease", {"requestId": rid})["fileRemoved"])
        self.assertFalse(os.path.exists(path))
        self.assertEqual(http_json(self.oauth["origin"] + "/api/me", auth)[0], 401, "revoked at the provider")
        self.assertEqual(self.oauth_debug()["revocations"], 1)

    # ---- 10 lease end by expiry --------------------------------------------------------------------------------------
    def test_10_a_lease_ends_by_itself(self):
        e = type(self).expiry
        header = {"Cookie": cookie_header(e["cookies"])}
        wait_for(lambda: self.vault("request.status", requestId=e["requestId"])["state"] in ("ended", "expired"), 150, "vaultd to end the lease")
        wait_for(lambda: self.site_debug()["logouts"] > e["logouts"], 20, "the helper's logout at the site")
        self.assertEqual(http_json(self.site["origin"] + "/api/me", header)[0], 401)
        self.assertTrue(os.path.exists(e["path"]), "the file stays until the plugin's sweep")
        self.plugin.call("job", name="lease-sweep")                      # the plugin removes the file of an ended lease
        self.assertFalse(os.path.exists(e["path"]))
        self.assertEqual(self.tool("vault_request_status", {"requestId": e["requestId"]}, "expiry")["status"], "ended")
        ended = [x for x in self.audit_events() if x.get("event") == "lease_end" and x.get("requestId") == e["requestId"]]
        self.assertEqual([(x["reason"], x["logout"]) for x in ended], [("expired", "ok")])
        self.assertEqual(self.helper.ping()["leases"], [])
        self.assertEqual(self.site_debug()["sessions"], 0)

    # ---- 11 audit chain and leaks ------------------------------------------------------------------------------------
    def test_11_audit_chain_and_no_secret_leaks(self):
        ok, msg = audit.verify([self.audit_path])
        self.assertTrue(ok, msg)
        secrets = [x for x in [PASSWORD, TOTP_SECRET, self.access_token] + [c["value"] for c in self.main_cookies] if len(x) >= 8]
        self.assertGreaterEqual(len(secrets), 4, "the secrets to look for were not collected")
        logs = json.dumps(self.plugin.call("logs"))
        haystacks = {"plugin logs": logs, "tool results": "\n".join(self.tool_results), "audit": read_text(self.audit_path)}
        for path in self.outputs:
            haystacks[os.path.basename(path)] = read_text(path)
        for name, text in haystacks.items():
            for s in secrets:
                self.assertNotIn(s, text, "a secret appears in " + name)
        self.assertEqual(self.provider.bad_requests, [])
        # nothing but the delivered-and-removed files was ever left in a workspace
        for key, a in self.agent.items():
            left = [n for n in os.listdir(os.path.join(a["workspace"], ".vault"))] if os.path.isdir(os.path.join(a["workspace"], ".vault")) else []
            self.assertEqual([n for n in left if n != ".gitignore"], [], key)


if __name__ == "__main__":
    unittest.main()
