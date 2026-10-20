"""vaultd as a client of the helper (Node, owns the browsers and the sealed store): line-JSON over /run/vault-helper/helper.sock.

Authentication is the socket's mode (0660 vault-helper:vault) plus the 32-byte bearer token in /etc/vault/helper.token, sent
as "token" on every request. Responses are {"ok":true,"data":{...}} or {"ok":false,"error":{"code","message"}}.
"""
import json
import socket

MAX_RESPONSE = 4 * 1024 * 1024
TIMEOUTS = {"ping": 5, "session.open": 60, "token.mint": 60, "session.close": 30, "token.revoke": 30}


class HelperError(Exception):
    def __init__(self, code, message=""):
        super().__init__(code, message)
        self.code, self.message = code, message


class HelperClient:
    def __init__(self, socket_path, token_path):
        self.socket_path, self.token_path = socket_path, token_path

    def _token(self):
        with open(self.token_path) as f:
            return f.read().strip()

    def call(self, op, **args):
        """Run one operation and return its data. Raises HelperError (code from the helper, or helper_down / timeout)."""
        timeout = TIMEOUTS.get(op, 30)
        try:
            msg = (json.dumps(dict(args, op=op, token=self._token())) + "\n").encode()
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect(self.socket_path)
                s.sendall(msg)
                line = s.makefile("rb").readline(MAX_RESPONSE + 1)
        except socket.timeout:
            raise HelperError("timeout", "helper did not answer in %d s" % timeout)
        except OSError:
            raise HelperError("helper_down", "helper socket not reachable")
        if not line.endswith(b"\n") or len(line) > MAX_RESPONSE:
            raise HelperError("helper_down", "helper answer is incomplete or too large")
        try:
            reply = json.loads(line)
        except ValueError:
            raise HelperError("helper_down", "helper answer is not JSON")
        if not isinstance(reply, dict):
            raise HelperError("helper_down", "helper answer is not an object")
        if reply.get("ok"):
            return reply.get("data") or {}
        err = reply.get("error") if isinstance(reply.get("error"), dict) else {}
        raise HelperError(str(err.get("code") or "helper_error"), str(err.get("message") or "")[:200])

    def ping(self):
        return self.call("ping")

    def session_open(self, lease_id, site_id, minutes, ends_at):
        return self.call("session.open", leaseId=lease_id, siteId=site_id, minutes=minutes, endsAt=ends_at)

    def session_close(self, lease_id):
        return self.call("session.close", leaseId=lease_id)

    def token_mint(self, lease_id, site_id, minutes, scopes):
        return self.call("token.mint", leaseId=lease_id, siteId=site_id, minutes=minutes, scopes=list(scopes))

    def token_revoke(self, lease_id):
        return self.call("token.revoke", leaseId=lease_id)
