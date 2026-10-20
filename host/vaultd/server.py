"""Transports. plugin.sock: the signed line protocol from the Paperclip plugin (Ed25519, replay-protected). admin.sock: the
root/vault-only command socket for vaultctl. Both are Unix sockets whose peers are checked with SO_PEERCRED.

plugin.sock: one connection = one request line + one response line (UTF-8 JSON, "\\n"-terminated), then close.
Request  {"msg": base64url(JSON body bytes), "sig": base64(Ed25519), "kid": keyId}; the signature covers b"pcvault-v1\\n" + body bytes.
Body     {"v":1, "type", "installId", "ts", "nonce", "data"}.
Response {"ok":true,"nonce","data"} or {"ok":false,"nonce","error":{"code","message"}}. Responses are not signed; the nonce echo ties them.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import socket
import socketserver
import struct
import sys
import threading
import time
from datetime import datetime, timezone

from . import __version__, ed25519
from .broker import VaultError, iso

MAX_REQUEST = 256 * 1024
MAX_RESPONSE = 2 * 1024 * 1024
CLOCK_SKEW = 120          # seconds either way
# With socket activation the first message is what starts vaultd: the plugin timestamped and signed it before this process
# existed. A message may therefore be a few seconds older than the start; one older than that is a replay from a previous run.
# Nonces are persisted, so a captured message of the previous run is refused by its nonce as well.
START_GRACE = 10          # seconds
NONCE_TTL = 600
SIGN_PREFIX = b"pcvault-v1\n"
TS_RE = re.compile(r"^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(\.\d{1,9})?Z$")
NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")
INSTALL_ID_RE = re.compile(r"^inst-[0-9a-f]{24}$")
FAIL_AUDIT_FREE, FAIL_AUDIT_EVERY = 20, 100   # failures audited in full per minute, then every Nth


def peer_uid(sock):
    _, uid, _ = struct.unpack("3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
    return uid


def parse_ts(ts):
    m = TS_RE.match(ts) if isinstance(ts, str) else None
    if not m:
        return None
    try:
        y, mo, d, h, mi, s = (int(g) for g in m.groups()[:6])
        return datetime(y, mo, d, h, mi, s, tzinfo=timezone.utc).timestamp() + (float(m.group(7)) if m.group(7) else 0.0)
    except ValueError:
        return None


class Enrolment:
    """The trusted plugin key (/var/lib/vault/plugin-key.json) and the one-time enrolment record the installer leaves in
    /etc/vault/enrol.json. vaultd cannot delete enrol.json (/etc is read-only to it): single use is enforced by remembering
    the code hash that was consumed, so the same record cannot enrol twice and a new installer run (new code) can rotate the key."""

    def __init__(self, key_path, enrol_path, plugin_uid, clock=time.time):
        self.key_path, self.enrol_path, self.plugin_uid, self.clock = key_path, enrol_path, plugin_uid, clock
        self.lock = threading.Lock()

    def current(self):
        try:
            with open(self.key_path) as f:
                return json.load(f)
        except (FileNotFoundError, ValueError):
            return None

    def install_id(self):
        rec = self.current()
        return rec["installId"] if rec else None

    def _pending(self):
        try:
            with open(self.enrol_path) as f:
                spec = json.load(f)
            ok = (isinstance(spec, dict) and INSTALL_ID_RE.match(spec["installId"]) and re.match(r"^[0-9a-f]{64}$", spec["codeHash"])
                  and parse_ts(spec["expiresAt"]) is not None and isinstance(spec["serviceUid"], int))
        except (OSError, ValueError, KeyError, TypeError):
            ok = False
        if not ok:
            raise VaultError("denied", "no enrolment pending")
        return spec

    @staticmethod
    def code_hash(code):
        norm = re.sub(r"[\s-]", "", str(code)).upper()
        return hashlib.sha256(("pcvault-enrol:" + norm).encode()).hexdigest()

    def enrol(self, body, public_key_b64, uid):
        """Proof of possession was already checked (the message is signed with public_key_b64). Check the code and store the key."""
        data = body["data"]
        with self.lock:
            spec = self._pending()
            old = self.current()
            if body["installId"] not in (None, spec["installId"]):
                raise VaultError("denied", "wrong installId")
            if self.clock() >= parse_ts(spec["expiresAt"]):
                raise VaultError("denied", "enrolment code expired")
            if old and old.get("codeHash") == spec["codeHash"]:
                raise VaultError("denied", "enrolment code already used")
            if not isinstance(data.get("code"), str) or not hmac.compare_digest(self.code_hash(data["code"]), spec["codeHash"]):
                raise VaultError("denied", "wrong enrolment code")
            if not (uid == spec["serviceUid"] == self.plugin_uid):
                raise VaultError("denied", "wrong service user")
            rec = {"installId": spec["installId"], "kid": ed25519.key_id(public_key_b64), "publicKey": public_key_b64,
                   "serviceUid": spec["serviceUid"], "enrolledAt": iso(self.clock()), "codeHash": spec["codeHash"]}
            tmp = self.key_path + ".tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "w") as f:
                json.dump(rec, f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.key_path)
        return {"installId": rec["installId"], "vaultdVersion": __version__, "apiVersion": 1}


class PluginProtocol:
    """bytes in, bytes out: everything between the socket and the broker."""

    def __init__(self, broker, enrolment, store, audit, plugin_uid, clock=time.time):
        self.broker, self.enrolment, self.store, self.audit = broker, enrolment, store, audit
        self.plugin_uid, self.clock = plugin_uid, clock
        self.started = float(int(clock())) - START_GRACE   # older than this run (plus the grace) could be a replay from before a restart; ts has whole seconds
        self._fail_lock = threading.Lock()
        self._fail_minute, self._fail_count = 0, 0
        self.routes = {
            "hello": broker.hello, "sites.list": broker.sites_list, "ceilings.get": broker.ceilings_get,
            "request.create": broker.request_create, "verdict.submit": broker.verdict_submit,
            "request.status": broker.request_status, "request.list": broker.request_list, "lease.fetch": broker.lease_fetch,
            "lease.ack": broker.lease_ack, "lease.revoke": broker.lease_revoke, "leases.list": broker.leases_list,
            "log.read": broker.log_read, "judge.testset": broker.judge_testset, "judge.record": broker.judge_record}

    def audit_failure(self, code, **info):
        """Auth-stage failures are audited in full up to FAIL_AUDIT_FREE a minute, then every FAIL_AUDIT_EVERY-th."""
        minute = int(self.clock() // 60)
        with self._fail_lock:
            if minute != self._fail_minute:
                self._fail_minute, self._fail_count = minute, 0
            self._fail_count += 1
            n = self._fail_count
        if n <= FAIL_AUDIT_FREE or n % FAIL_AUDIT_EVERY == 0:
            self.audit.write(dict({"event": "auth_fail", "time": iso(self.clock()), "code": code, "failuresThisMinute": n}, **info))

    @staticmethod
    def _reply(ok, nonce, **kw):
        out = json.dumps(dict({"ok": ok, "nonce": nonce}, **kw), separators=(",", ":")).encode()
        if len(out) >= MAX_RESPONSE:
            out = json.dumps({"ok": False, "nonce": nonce, "error": {"code": "internal", "message": "response too large"}}).encode()
        return out + b"\n"

    def handle(self, line, uid):
        """The response line for one request line, or None to drop the connection (wrong peer)."""
        if uid != self.plugin_uid:
            self.audit_failure("peer_denied", peerUid=uid)
            return None
        seen = {}
        try:
            body, key = self._open(line, seen)
        except VaultError as e:
            self.audit_failure(e.code)
            return self._reply(False, seen.get("nonce", ""), error={"code": e.code, "message": e.message})
        try:
            return self._reply(True, seen["nonce"], data=self._dispatch(body, key, uid))
        except VaultError as e:
            return self._reply(False, seen["nonce"], error={"code": e.code, "message": e.message})
        except Exception as e:      # never leak a traceback or request data to the peer or the journal
            print("internal error: %s" % type(e).__name__, file=sys.stderr, flush=True)
            return self._reply(False, seen["nonce"], error={"code": "internal", "message": "internal error"})

    def _open(self, line, seen):
        """Verify framing, signature, install id, time and nonce; `seen["nonce"]` is set as soon as it is known so that even
        a rejection can echo it. Returns (body, public key used)."""
        if len(line) > MAX_REQUEST:
            raise VaultError("bad_request", "request too large")
        try:
            env = json.loads(line)
            msg = base64.urlsafe_b64decode(env["msg"] + "=" * (-len(env["msg"]) % 4))
            sig = base64.b64decode(env["sig"], validate=True)
            kid = env["kid"]
            body = json.loads(msg)
            if not isinstance(body, dict) or not isinstance(kid, str):
                raise TypeError
        except (ValueError, KeyError, TypeError, RecursionError):
            raise VaultError("bad_request", "not a signed message")
        nonce = body.get("nonce")
        if not (isinstance(nonce, str) and NONCE_RE.match(nonce)):
            raise VaultError("bad_request", "bad nonce")
        seen["nonce"] = nonce
        # enrol is the one message sent before the plugin knows its installId (null); every other message names it
        if body.get("v") != 1 or not isinstance(body.get("type"), str) or not isinstance(body.get("data"), dict) \
                or not isinstance(body.get("installId"), str) and not (body["type"] == "enrol" and body.get("installId") is None):
            raise VaultError("bad_request", "bad body")
        if body["type"] == "enrol":
            pub_b64 = body["data"].get("publicKey")
            raw = ed25519.raw_key_from_spki(pub_b64) if isinstance(pub_b64, str) else None
            if raw is None or ed25519.key_id(pub_b64) != kid:
                raise VaultError("bad_request", "bad public key")
            key = raw
        else:
            rec = self.enrolment.current()
            if rec is None:
                raise VaultError("not_enrolled", "no plugin key enrolled")
            if kid != rec["kid"]:
                raise VaultError("bad_signature", "unknown key")
            key = ed25519.raw_key_from_spki(rec["publicKey"])
        if not ed25519.verify(key, SIGN_PREFIX + msg, sig):
            raise VaultError("bad_signature", "signature does not verify")
        if body["type"] != "enrol" and body["installId"] != self.enrolment.install_id():
            raise VaultError("bad_request", "wrong installId")
        ts = parse_ts(body.get("ts"))
        if ts is None:
            raise VaultError("bad_request", "bad ts")
        now = self.clock()
        if abs(now - ts) > CLOCK_SKEW:
            raise VaultError("clock_skew", "message time is off by more than %d s" % CLOCK_SKEW)
        if ts < self.started:
            raise VaultError("replay", "message is older than this vaultd run")
        if not self.store.use_nonce(nonce, now):
            raise VaultError("replay", "nonce already used")
        return body, key

    def _dispatch(self, body, key, uid):
        t = body["type"]
        if t == "enrol":
            return self.enrolment.enrol(body, body["data"]["publicKey"], uid)
        fn = self.routes.get(t)
        if fn is None:
            raise VaultError("unknown_type", "unknown message type")
        return fn(body["data"])


class _Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    request_queue_size = 64


def _make_server(path, handler, umask, listen_fd=None):
    """A threaded Unix stream server. `listen_fd` is a listening socket handed over by systemd (socket activation): it is used
    as it is (systemd created it with the mode, owner and ACL of vaultd.socket), nothing is unlinked, bound or chmod-ed here."""
    if listen_fd is not None:
        srv = _Server(path, handler, bind_and_activate=False)
        srv.socket.close()
        srv.socket = socket.socket(fileno=listen_fd)
        srv.server_address = srv.socket.getsockname()
        return srv
    if os.path.exists(path):
        os.unlink(path)
    old = os.umask(umask)
    try:
        srv = _Server(path, handler)
    finally:
        os.umask(old)
    return srv


SD_LISTEN_FDS_START = 3


def systemd_listen_fds(environ=None, pid=None):
    """File descriptors passed by systemd socket activation (sd_listen_fds): LISTEN_PID must be this process, LISTEN_FDS the count,
    the first one is fd 3. Returns {name: fd} (LISTEN_FDNAMES, or fd0, fd1, ... without names); {} when not socket-activated.
    The variables are removed from the environment so that no child process inherits them."""
    env = os.environ if environ is None else environ
    try:
        if int(env.get("LISTEN_PID", "")) != (os.getpid() if pid is None else pid):
            return {}
        count = int(env.get("LISTEN_FDS", "0"))
    except ValueError:
        return {}
    names = (env.get("LISTEN_FDNAMES") or "").split(":") if env.get("LISTEN_FDNAMES") else []
    for k in ("LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"):
        env.pop(k, None)
    out = {}
    for i in range(max(count, 0)):
        fd = SD_LISTEN_FDS_START + i
        out[names[i] if i < len(names) and names[i] else "fd%d" % i] = fd
        try:
            os.set_inheritable(fd, False)
        except OSError:
            pass
    return out


def activated_listener(fds):
    """The listening AF_UNIX stream socket among systemd's fds (the only one expected), or None. Anything else is refused."""
    if not fds:
        return None
    if len(fds) != 1:
        raise SystemExit("vaultd: socket activation passed %d sockets, exactly one (plugin.sock) is expected" % len(fds))
    (fd,) = fds.values()
    try:
        s = socket.socket(fileno=os.dup(fd))
    except OSError as e:
        raise SystemExit("vaultd: the socket-activation descriptor %d is not a socket: %s" % (fd, e.strerror))
    try:
        ok = (s.family == socket.AF_UNIX and s.type == socket.SOCK_STREAM and s.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 1)
    finally:
        s.close()
    if not ok:
        raise SystemExit("vaultd: the socket-activation descriptor is not a listening Unix stream socket")
    return fd


def make_plugin_server(protocol, path, handler_timeout=10, max_concurrency=32, listen_fd=None):
    slots = threading.BoundedSemaphore(max_concurrency)

    class Handler(socketserver.StreamRequestHandler):
        timeout = handler_timeout

        def handle(self):
            try:
                uid = peer_uid(self.request)
            except (OSError, struct.error):
                return
            if uid != protocol.plugin_uid:      # before the concurrency check: a stranger learns nothing, not even `busy`
                protocol.audit_failure("peer_denied", peerUid=uid)
                return
            if not slots.acquire(blocking=False):
                self.wfile.write(PluginProtocol._reply(False, "", error={"code": "busy", "message": "too many requests"}))
                return
            try:
                try:
                    line = self.rfile.readline(MAX_REQUEST + 2)
                except OSError:
                    return
                if not line.endswith(b"\n") and len(line) <= MAX_REQUEST + 1:
                    return                      # truncated or idle connection
                out = protocol.handle(line.rstrip(b"\n"), uid)
                if out is not None:
                    self.wfile.write(out)
            finally:
                slots.release()

    return _make_server(path, Handler, 0o117, listen_fd)   # own socket (no activation): mode 0660; activated: vaultd.socket decides


def make_admin_server(broker, path, handler_timeout=10, on_reject=None):
    """`on_reject(uid)` is called for every connection from a uid that is neither root nor the service (it audits)."""
    own = os.getuid()

    class Handler(socketserver.StreamRequestHandler):
        timeout = handler_timeout

        def handle(self):
            try:
                uid = peer_uid(self.request)
            except (OSError, struct.error):
                return
            if uid not in (0, own):
                if on_reject is not None:
                    on_reject(uid)
                return
            try:
                reply = broker.admin(json.loads(self.rfile.readline(MAX_REQUEST)))
            except Exception:
                reply = {"ok": False, "error": "bad json"}
            self.wfile.write((json.dumps(reply) + "\n").encode())

    return _make_server(path, Handler, 0o177)               # socket mode 0600


def start_sweeper(broker, interval=5):
    stop = threading.Event()

    def loop():
        while not stop.wait(interval):
            try:
                broker.sweep()
            except Exception as e:      # never let the sweeper thread die
                print("sweep failed: %s" % type(e).__name__, file=sys.stderr, flush=True)
    threading.Thread(target=loop, daemon=True).start()
    return stop
