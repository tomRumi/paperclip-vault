#!/usr/bin/env python3
"""Fake login site for the helper tests: stdlib only, 127.0.0.1:<ephemeral>.

Flow: /login (email) -> /password -> /otp (TOTP, +-1 window) -> /challenge (an
SMS-style code, skipped when a valid device-trust cookie is present) ->
/dashboard.  The session cookie is server-side state; /logout (GET or POST) and
/logout-post (POST only, 405 on GET) kill it.  /out redirects to another host
name (localhost) to exercise the allowedHosts guard; /bounce?to=URL redirects
to any URL (same host name on another port, ...).  The SMS challenge page has a
"remember this device" checkbox (#remember); with --require-remember the
device-trust cookie is only issued when it is ticked.

Start:  fake_site.py [--user U] [--password P] [--totp-secret B32] [--sms-code C]
                     [--password-delay S] [--no-challenge] [--require-remember]
Prints one JSON line {"port": N} on stdout, then serves until killed.
/_debug returns counters as JSON (live sessions, challenges served, ...).
"""
import argparse
import base64
import hashlib
import hmac
import json
import secrets
import struct
import threading
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


def totp(secret_b32, counter, digits=6):
    key = base64.b32decode(secret_b32.upper().replace(" ", ""))
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    value = struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF
    return str(value % 10 ** digits).zfill(digits)


class State:
    def __init__(self, args):
        self.user = args.user
        self.password = args.password
        self.totp_secret = args.totp_secret
        self.sms_code = args.sms_code
        self.password_delay = args.password_delay
        self.challenge = not args.no_challenge
        self.require_remember = args.require_remember
        self.lock = threading.Lock()
        self.pre = {}  # pre-login id -> {"stage": ..., "user": ...}
        self.sessions = {}  # sid -> user
        self.trusted = set()  # device-trust tokens issued by a correct SMS code
        self.foreign = []  # "host/path" of requests that arrived under a host name other than 127.0.0.1
        self.counters = {"challenges_served": 0, "challenges_passed": 0, "logins": 0,
                         "logouts": 0, "in_flight_password": 0, "max_in_flight_password": 0,
                         "bad_totp": 0, "bad_password": 0, "foreign_host_requests": 0}

    def totp_ok(self, code):
        now = int(time.time()) // 30
        return any(hmac.compare_digest(code, totp(self.totp_secret, now + d)) for d in (-1, 0, 1))


PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>{title}</title></head>
<body><h1>{title}</h1>{body}</body></html>"""


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    @property
    def state(self):
        return self.server.state

    @property
    def port(self):
        return self.server.server_address[1]

    def log_message(self, *_):  # keep test output quiet
        pass

    # -- helpers ---------------------------------------------------
    def cookies(self):
        jar = SimpleCookie(self.headers.get("Cookie", ""))
        return {k: m.value for k, m in jar.items()}

    def send(self, status, body="", headers=(), ctype="text/html; charset=utf-8"):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, location, headers=()):
        self.send(302, "", [("Location", location), *headers])

    def page(self, title, body, status=200, headers=()):
        self.send(status, PAGE.format(title=title, body=body), headers)

    def form(self):
        n = int(self.headers.get("Content-Length") or 0)
        return {k: v[0] for k, v in parse_qs(self.rfile.read(n).decode()).items()}

    def pre_id(self):
        return self.cookies().get("pre")

    def session_user(self):
        return self.state.sessions.get(self.cookies().get("sid", ""))

    def start_session(self, user, extra=()):
        sid = secrets.token_urlsafe(24)
        with self.state.lock:
            self.state.sessions[sid] = user
            self.state.counters["logins"] += 1
        return [
            ("Set-Cookie", f"sid={sid}; Path=/; HttpOnly; SameSite=Lax"),
            ("Set-Cookie", "pref=dark; Path=/; Max-Age=31536000; SameSite=Lax"),
            *extra,
        ]

    # -- routes ----------------------------------------------------
    def do_GET(self):
        path = urlsplit(self.path).path
        if not self.headers.get("Host", "").startswith("127.0.0.1:"):
            with self.state.lock:
                self.state.counters["foreign_host_requests"] += 1
                self.state.foreign.append(f'{self.headers.get("Host", "")}{self.path}')
        if path == "/":
            return self.redirect("/dashboard")
        if path == "/login":
            pid = secrets.token_urlsafe(12)
            with self.state.lock:
                self.state.pre[pid] = {"stage": "email"}
            return self.page("Sign in", '<form method="post" action="/login">'
                             '<input id="email" name="email"><button id="next" type="submit">Next</button></form>',
                             headers=[("Set-Cookie", f"pre={pid}; Path=/; HttpOnly")])
        if path == "/login-captcha":
            return self.page("Sign in", '<div class="g-recaptcha" data-sitekey="x" style="width:300px;height:80px">I am not a robot</div>')
        if path == "/password":
            return self.page("Password", self.password_form(""))
        if path == "/otp":
            return self.page("Code", self.otp_form(""))
        if path == "/challenge":
            with self.state.lock:
                self.state.counters["challenges_served"] += 1
            return self.page("Verify this device", self.challenge_form(""))
        if path == "/dashboard":
            user = self.session_user()
            if not user:
                return self.redirect("/login")
            return self.page("Dashboard",
                             f'<span id="avatar">{user}</span>'
                             '<form method="post" action="/logout"><button id="logout" type="submit">Log out</button></form>'
                             '<a id="out" href="/out">elsewhere</a>'
                             f'<img alt="" src="http://localhost:{self.port}/pixel.gif">'
                             '<script>localStorage.setItem("device_token", "LS-TRUST-VALUE");'
                             'localStorage.setItem("theme", "dark");</script>')
        if path == "/api/me":
            user = self.session_user()
            if not user:
                return self.send(401, json.dumps({"error": "no session"}), ctype="application/json")
            return self.send(200, json.dumps({"user": user}), ctype="application/json")
        if path == "/logout":
            return self.logout()
        if path == "/logout-post":
            return self.send(405, "use POST", [("Allow", "POST")])
        if path == "/out":
            return self.redirect(f"http://localhost:{self.port}/dashboard")
        if path == "/bounce":
            return self.redirect(parse_qs(urlsplit(self.path).query).get("to", ["/"])[0])
        if path == "/_debug":
            with self.state.lock:
                snap = dict(self.state.counters, sessions=len(self.state.sessions),
                            trusted=len(self.state.trusted), foreign=list(self.state.foreign))
            return self.send(200, json.dumps(snap), ctype="application/json")
        return self.page("Not found", "", status=404)

    def do_POST(self):
        path = urlsplit(self.path).path
        data = self.form()
        pid = self.pre_id()
        pre = self.state.pre.get(pid)
        if path == "/login":
            if pre is None:
                return self.redirect("/login")
            pre["user"] = data.get("email", "")
            pre["stage"] = "password"
            return self.redirect("/password")
        if path == "/password":
            if pre is None or pre.get("stage") != "password":
                return self.redirect("/login")
            with self.state.lock:
                self.state.counters["in_flight_password"] += 1
                self.state.counters["max_in_flight_password"] = max(
                    self.state.counters["max_in_flight_password"], self.state.counters["in_flight_password"])
            try:
                if self.state.password_delay:
                    time.sleep(self.state.password_delay)
            finally:
                with self.state.lock:
                    self.state.counters["in_flight_password"] -= 1
            ok = (hmac.compare_digest(pre["user"], self.state.user)
                  and hmac.compare_digest(data.get("password", ""), self.state.password))
            if not ok:
                with self.state.lock:
                    self.state.counters["bad_password"] += 1
                return self.page("Password", self.password_form("Wrong user or password"))
            pre["stage"] = "otp"
            return self.redirect("/otp")
        if path == "/otp":
            if pre is None or pre.get("stage") != "otp":
                return self.redirect("/login")
            if not self.state.totp_ok(data.get("otp", "")):
                with self.state.lock:
                    self.state.counters["bad_totp"] += 1
                return self.page("Code", self.otp_form("Wrong code"))
            if not self.state.challenge or self.cookies().get("device_trust") in self.state.trusted:
                return self.redirect("/dashboard", self.start_session(pre["user"]))
            pre["stage"] = "challenge"
            return self.redirect("/challenge")
        if path == "/challenge":
            if pre is None or pre.get("stage") != "challenge":
                return self.redirect("/login")
            if not hmac.compare_digest(data.get("code", ""), self.state.sms_code):
                with self.state.lock:
                    self.state.counters["challenges_served"] += 1
                return self.page("Verify this device", self.challenge_form("Wrong code"))
            token = secrets.token_urlsafe(16)
            remembered = data.get("remember") == "1"
            with self.state.lock:
                self.state.counters["challenges_passed"] += 1
                if remembered or not self.state.require_remember:
                    self.state.trusted.add(token)
            if self.state.require_remember and not remembered:
                return self.redirect("/dashboard", self.start_session(pre["user"]))
            trust = ("Set-Cookie", f"device_trust={token}; Path=/; Max-Age=2592000; HttpOnly; SameSite=Lax")
            return self.redirect("/dashboard", self.start_session(pre["user"], [trust]))
        if path in ("/logout", "/logout-post"):
            return self.logout()
        return self.page("Not found", "", status=404)

    def logout(self):
        sid = self.cookies().get("sid", "")
        with self.state.lock:
            if self.state.sessions.pop(sid, None) is not None:
                self.state.counters["logouts"] += 1
        return self.redirect("/login", [("Set-Cookie", "sid=; Path=/; Max-Age=0")])

    @staticmethod
    def password_form(error):
        err = f'<p id="error">{error}</p>' if error else ""
        return (f'{err}<form method="post" action="/password"><input id="password" name="password" type="password">'
                '<button id="login" type="submit">Sign in</button></form>')

    @staticmethod
    def otp_form(error):
        err = f'<p id="error">{error}</p>' if error else ""
        return (f'{err}<form method="post" action="/otp"><input id="otp" name="otp" autocomplete="one-time-code">'
                '<button id="verify" type="submit">Verify</button></form>')

    @staticmethod
    def challenge_form(error):
        err = f'<p id="error">{error}</p>' if error else ""
        return (f'{err}<p>We sent a code by SMS.</p><form method="post" action="/challenge">'
                '<input id="code" name="code"><label><input id="remember" name="remember" type="checkbox" value="1"> Remember this device</label>'
                '<button id="go" type="submit">Go</button></form>')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--user", default="tester@example.test")
    ap.add_argument("--password", default="correct horse battery")
    ap.add_argument("--totp-secret", default="JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")
    ap.add_argument("--sms-code", default="424242")
    ap.add_argument("--password-delay", type=float, default=0.0)
    ap.add_argument("--no-challenge", action="store_true", help="never ask for the SMS code")
    ap.add_argument("--require-remember", action="store_true", help="issue the device-trust cookie only when #remember is ticked")
    args = ap.parse_args()
    state = State(args)
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.state = state
    server.daemon_threads = True
    print(json.dumps({"port": server.server_address[1]}), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
