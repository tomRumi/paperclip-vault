#!/usr/bin/env python3
"""Fake OAuth provider for the helper tests: stdlib only, 127.0.0.1:<ephemeral>.

Endpoints
  POST /device     device authorization request  -> device_code, user_code, verification_uri, expires_in, interval
  GET  /authorize  redirect flow: checks response_type/client_id/redirect_uri/state/PKCE S256 and answers 302 to
                   redirect_uri?code=..&state=.. (the owner "approves" at once; --deny answers error=access_denied)
  POST /token      grant_type device_code | authorization_code | refresh_token
  POST /revoke     RFC 7009 token revocation (access tokens)
  GET  /api/me     200 for a valid, unrevoked, unexpired "Authorization: Bearer <access token>", else 401
  GET  /_debug     counters and what was issued/revoked, as JSON

Behaviour switches (all optional)
  --client-secret S     require client_secret=S on every client request
  --interval N          device flow poll interval handed out (default 1)
  --pending N           authorization_pending answers before the device code is approved (default 2)
  --slow-down-at K      the K-th poll (1-based) answers slow_down
  --deny                device flow: access_denied once polled; redirect flow: error=access_denied
  --device-expires N    expires_in of the device code in seconds (default 600)
  --expires-in N        expires_in of access tokens in seconds (default 3600)
  --no-rotate           keep the refresh token fixed (default: every refresh grant returns a new one and
                        invalidates the old one)
  --no-refresh-token    never issue a refresh token (error case)
  --no-revoke           do not serve /revoke (404)

Prints one JSON line {"port": N} on stdout, then serves until killed.
"""
import argparse
import base64
import hashlib
import json
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlsplit

DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"


class State:
    def __init__(self, args):
        self.args = args
        self.lock = threading.Lock()
        self.client_id = None            # first client id seen: all later requests must match
        self.devices = {}                # device_code -> {"polls": n, "scope": ..}
        self.codes = {}                  # authorization code -> {"challenge", "redirect_uri", "scope"}
        self.refresh = {}                # refresh token -> {"scope": str, "live": bool}
        self.access = {}                 # access token -> {"expires": ts, "scope": str, "revoked": bool}
        self.counters = {"device_requests": 0, "device_polls": 0, "slow_downs": 0, "authorize_requests": 0,
                         "code_exchanges": 0, "pkce_failures": 0, "refreshes": 0, "refresh_reuse": 0,
                         "revocations": 0, "bad_client": 0}
        self.last_refresh_scope = None
        self.last_form = {}


def b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    @property
    def state(self):
        return self.server.state

    def log_message(self, *_):
        pass

    def send_json(self, status, obj, headers=()):
        data = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def form(self):
        n = int(self.headers.get("Content-Length") or 0)
        return {k: v[0] for k, v in parse_qs(self.rfile.read(n).decode()).items()}

    def client_ok(self, f):
        """client_id is fixed by the first request; client_secret is checked when the provider has one."""
        st = self.state
        with st.lock:
            if st.client_id is None:
                st.client_id = f.get("client_id")
            ok = f.get("client_id") == st.client_id and f.get("client_id")
            if st.args.client_secret is not None:
                ok = ok and f.get("client_secret") == st.args.client_secret
            if not ok:
                st.counters["bad_client"] += 1
        if not ok:
            self.send_json(401, {"error": "invalid_client"})
        return bool(ok)

    def issue(self, scope, refresh_token=None):
        st = self.state
        access = "at-" + secrets.token_urlsafe(18)
        with st.lock:
            st.access[access] = {"expires": time.time() + st.args.expires_in, "scope": scope, "revoked": False}
        body = {"access_token": access, "token_type": "Bearer", "expires_in": st.args.expires_in, "scope": scope}
        if refresh_token:
            body["refresh_token"] = refresh_token
        return body

    def new_refresh(self, scope):
        st = self.state
        if st.args.no_refresh_token:
            return None
        token = "rt-" + secrets.token_urlsafe(18)
        with st.lock:
            st.refresh[token] = {"scope": scope, "live": True}
        return token

    # -- routes ------------------------------------------------------
    def do_POST(self):
        path = urlsplit(self.path).path
        f = self.form()
        st = self.state
        with st.lock:
            st.last_form = {k: v for k, v in f.items() if k not in ("client_secret",)}
        if path == "/device":
            if not self.client_ok(f):
                return
            code, user = "dc-" + secrets.token_urlsafe(18), "WDJB-" + secrets.token_hex(2).upper()
            with st.lock:
                st.counters["device_requests"] += 1
                st.devices[code] = {"polls": 0, "scope": f.get("scope", ""), "expires": time.time() + st.args.device_expires}
            return self.send_json(200, {"device_code": code, "user_code": user,
                                        "verification_uri": f"http://127.0.0.1:{self.server.server_address[1]}/activate",
                                        "expires_in": st.args.device_expires, "interval": st.args.interval})
        if path == "/token":
            if not self.client_ok(f):
                return
            return self.token(f)
        if path == "/revoke":
            if st.args.no_revoke:
                return self.send_json(404, {"error": "not_found"})
            if not self.client_ok(f):
                return
            with st.lock:
                entry = st.access.get(f.get("token", ""))
                if entry is not None:
                    entry["revoked"] = True
                st.counters["revocations"] += 1
            return self.send_json(200, {})
        return self.send_json(404, {"error": "not_found"})

    def token(self, f):
        st = self.state
        grant = f.get("grant_type")
        if grant == DEVICE_GRANT:
            with st.lock:
                dev = st.devices.get(f.get("device_code", ""))
                if dev is None:
                    return self.send_json(400, {"error": "invalid_grant"})
                if time.time() > dev["expires"]:
                    return self.send_json(400, {"error": "expired_token"})
                dev["polls"] += 1
                st.counters["device_polls"] += 1
                n = st.counters["device_polls"]
                if st.args.slow_down_at == n:
                    st.counters["slow_downs"] += 1
                    return self.send_json(400, {"error": "slow_down"})
                if st.args.deny and dev["polls"] > st.args.pending:
                    return self.send_json(400, {"error": "access_denied"})
                if dev["polls"] <= st.args.pending:
                    return self.send_json(400, {"error": "authorization_pending"})
                scope = dev["scope"]
            return self.send_json(200, self.issue(scope, self.new_refresh(scope)))
        if grant == "authorization_code":
            with st.lock:
                st.counters["code_exchanges"] += 1
                entry = st.codes.pop(f.get("code", ""), None)  # single use
            if entry is None or entry["redirect_uri"] != f.get("redirect_uri"):
                return self.send_json(400, {"error": "invalid_grant"})
            verifier = f.get("code_verifier", "")
            if b64url(hashlib.sha256(verifier.encode()).digest()) != entry["challenge"]:
                with st.lock:
                    st.counters["pkce_failures"] += 1
                return self.send_json(400, {"error": "invalid_grant"})
            return self.send_json(200, self.issue(entry["scope"], self.new_refresh(entry["scope"])))
        if grant == "refresh_token":
            with st.lock:
                st.counters["refreshes"] += 1
                st.last_refresh_scope = f.get("scope")
                entry = st.refresh.get(f.get("refresh_token", ""))
                if entry is None or not entry["live"]:
                    if entry is not None:
                        st.counters["refresh_reuse"] += 1
                    return self.send_json(400, {"error": "invalid_grant"})
                scope = entry["scope"]
                if not st.args.no_rotate:
                    entry["live"] = False
            new = f["refresh_token"] if st.args.no_rotate else self.new_refresh(scope)
            return self.send_json(200, self.issue(f.get("scope") or scope, None if st.args.no_rotate else new))
        return self.send_json(400, {"error": "unsupported_grant_type"})

    def do_GET(self):
        parts = urlsplit(self.path)
        q = {k: v[0] for k, v in parse_qs(parts.query).items()}
        st = self.state
        if parts.path == "/authorize":
            with st.lock:
                st.counters["authorize_requests"] += 1
            if q.get("response_type") != "code" or q.get("code_challenge_method") != "S256" or not q.get("code_challenge") \
                    or not q.get("state") or not q.get("redirect_uri", "").startswith("http://127.0.0.1:"):
                return self.send_json(400, {"error": "invalid_request"})
            if not self.client_ok(q):
                return
            if st.args.deny:
                target = q["redirect_uri"] + "?" + urlencode({"error": "access_denied", "state": q["state"]})
            else:
                code = "ac-" + secrets.token_urlsafe(18)
                with st.lock:
                    st.codes[code] = {"challenge": q["code_challenge"], "redirect_uri": q["redirect_uri"], "scope": q.get("scope", "")}
                target = q["redirect_uri"] + "?" + urlencode({"code": code, "state": q["state"]})
            self.send_response(302)
            self.send_header("Location", target)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if parts.path == "/api/me":
            token = self.headers.get("Authorization", "")[len("Bearer "):]
            with st.lock:
                entry = st.access.get(token)
                ok = entry is not None and not entry["revoked"] and time.time() < entry["expires"]
            return self.send_json(200 if ok else 401, {"ok": ok})
        if parts.path == "/_debug":
            with st.lock:
                snap = dict(st.counters, last_refresh_scope=st.last_refresh_scope, last_form=st.last_form,
                            live_refresh=sum(1 for r in st.refresh.values() if r["live"]),
                            access={t: {"revoked": a["revoked"], "scope": a["scope"]} for t, a in st.access.items()},
                            client_id=st.client_id)
            return self.send_json(200, snap)
        return self.send_json(404, {"error": "not_found"})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--client-secret", default=None)
    ap.add_argument("--interval", type=int, default=1)
    ap.add_argument("--pending", type=int, default=2)
    ap.add_argument("--slow-down-at", type=int, default=None)
    ap.add_argument("--deny", action="store_true")
    ap.add_argument("--device-expires", type=int, default=600)
    ap.add_argument("--expires-in", type=int, default=3600)
    ap.add_argument("--no-rotate", action="store_true")
    ap.add_argument("--no-refresh-token", action="store_true")
    ap.add_argument("--no-revoke", action="store_true")
    args = ap.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.state = State(args)
    server.daemon_threads = True
    print(json.dumps({"port": server.server_address[1]}), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
