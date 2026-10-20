"""plugin.sock: signatures, replay protection, clock, enrolment, peer credentials, framing, the admin socket."""
import base64
import json
import os
import socket
import threading
import unittest
from unittest import mock

import support
from support import Env, INSTALL_ID, Signer
from vaultd import audit, server
from vaultd.broker import iso


def events(env, kind):
    with open(env.cfg["audit_path"]) as f:
        return [e for e in map(json.loads, f) if e["event"] == kind]


class Signed(unittest.TestCase):
    def setUp(self):
        self.env = Env()
        self.addCleanup(self.env.close)

    def test_hello_roundtrip_echoes_the_nonce(self):
        body = self.env.body("hello")
        r = self.env.send(body)
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["nonce"], body["nonce"])
        self.assertEqual(r["data"]["installId"], INSTALL_ID)
        self.assertEqual(r["data"]["helper"], "up")

    def test_unsigned_and_malformed_requests(self):
        p = self.env.proto
        for line in (b"", b"not json", b"[]", b'{"msg":"e30","sig":"AAAA"}', b'{"msg":1,"sig":2,"kid":3}'):
            r = json.loads(p.handle(line, self.env.uid))
            self.assertEqual((r["ok"], r["error"]["code"]), (False, "bad_request"), line)
        deep = b'{"msg":"' + base64.urlsafe_b64encode(b"[" * 100000) + b'","sig":"AAAA","kid":"x"}'
        self.assertEqual(json.loads(p.handle(deep, self.env.uid))["error"]["code"], "bad_request")

    def test_bad_signature(self):
        self.assertEqual(self.env.send(self.env.body("hello"), tamper=True)["error"]["code"], "bad_signature")
        other = Signer(b"\x02" * 32)
        self.assertEqual(self.env.send(self.env.body("hello"), signer=other, kid=self.env.signer.kid)["error"]["code"], "bad_signature")
        self.assertEqual(self.env.send(self.env.body("hello"), signer=other)["error"]["code"], "bad_signature")   # unknown kid

    def test_signature_covers_the_domain_prefix(self):
        body = self.env.body("hello")
        msg = json.dumps(body).encode()
        sig = self.env.signer.sign(msg)                      # signed WITHOUT the pcvault-v1 prefix
        line = json.dumps({"msg": base64.urlsafe_b64encode(msg).decode(), "sig": base64.b64encode(sig).decode(), "kid": self.env.signer.kid}).encode()
        self.assertEqual(json.loads(self.env.proto.handle(line, self.env.uid))["error"]["code"], "bad_signature")

    def test_replay_is_refused(self):
        body = self.env.body("hello")
        self.assertTrue(self.env.send(body)["ok"])
        self.assertEqual(self.env.send(body)["error"]["code"], "replay")

    def test_wrong_install_id(self):
        self.assertEqual(self.env.ask("hello", installId="inst-" + "00" * 12)["error"]["code"], "bad_request")

    def test_clock_skew_both_ways(self):
        for off in (-130, 130):
            r = self.env.ask("hello", ts=iso(self.env.clock() + off))
            self.assertEqual(r["error"]["code"], "clock_skew", off)
        self.assertTrue(self.env.ask("hello", ts=iso(self.env.clock() + 100))["ok"])

    def test_message_from_before_vaultd_started_is_a_replay(self):
        old = iso(self.env.clock() - 30)                      # inside the skew window but before the start of this run
        self.assertEqual(self.env.ask("hello", ts=old)["error"]["code"], "replay")
        self.assertEqual(self.env.ask("hello", ts=iso(self.env.clock() - server.START_GRACE - 2))["error"]["code"], "replay")
        self.env.clock.advance(60)
        self.assertTrue(self.env.ask("hello")["ok"])

    def test_message_signed_just_before_a_socket_activated_start_is_accepted(self):
        # the message that triggers the start was timestamped before vaultd existed, possibly in the previous second
        self.assertTrue(self.env.ask("hello", ts=iso(self.env.clock() - 1))["ok"])
        self.assertTrue(self.env.ask("hello", ts=iso(self.env.clock() - 3))["ok"])

    def test_bad_fields(self):
        for over in ({"ts": "yesterday"}, {"nonce": "short"}, {"v": 2}, {"type": 5}, {"data": []}):
            body = dict(self.env.body("hello"), **over)
            self.assertEqual(self.env.send(body)["error"]["code"], "bad_request", over)

    def test_unknown_type_and_non_dict_data(self):
        self.assertEqual(self.env.err("no.such.thing"), "unknown_type")
        self.assertEqual(self.env.err("sites.list", {"agentId": 5}), "bad_request")

    def test_request_larger_than_256_kib(self):
        r = json.loads(self.env.proto.handle(b"x" * (server.MAX_REQUEST + 1), self.env.uid))
        self.assertEqual(r["error"]["code"], "bad_request")

    def test_nonces_are_pruned_after_ten_minutes(self):
        self.env.ask("hello")
        self.env.clock.advance(601)
        self.env.store.prune(self.env.clock(), server.NONCE_TTL)
        self.assertEqual(self.env.store._one("SELECT COUNT(*) AS n FROM nonces")["n"], 0)

    def test_failures_are_audited_and_sampled_after_twenty_a_minute(self):
        for _ in range(101):
            self.env.send(self.env.body("hello"), tamper=True)
        fails = events(self.env, "auth_fail")
        self.assertEqual(len(fails), 20 + 1)                  # the first 20, then every 100th
        self.assertEqual(fails[0]["code"], "bad_signature")
        self.assertTrue(audit.verify([self.env.cfg["audit_path"]])[0])

    def test_not_enrolled(self):
        env = Env(enrolled=False)
        self.addCleanup(env.close)
        self.assertEqual(env.ask("hello")["error"]["code"], "not_enrolled")


class Peer(unittest.TestCase):
    def setUp(self):
        self.env = Env()
        self.addCleanup(self.env.close)

    def test_wrong_uid_is_dropped_and_audited(self):
        self.assertIsNone(self.env.send(self.env.body("hello"), uid=self.env.uid + 1))
        self.assertEqual(events(self.env, "auth_fail")[-1]["code"], "peer_denied")
        self.assertEqual(events(self.env, "auth_fail")[-1]["peerUid"], self.env.uid + 1)

    def serve(self):
        srv = server.make_plugin_server(self.env.proto, self.env.cfg["plugin_socket"], handler_timeout=2)
        threading.Thread(target=lambda: srv.serve_forever(0.02), daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        return self.env.cfg["plugin_socket"]

    def exchange(self, path, line):
        with socket.socket(socket.AF_UNIX) as s:
            s.settimeout(5)
            s.connect(path)
            try:
                s.sendall(line + b"\n")
                return s.makefile("rb").readline()
            except (BrokenPipeError, ConnectionResetError):   # dropped by the server before it read our line
                return b""

    def test_real_socket_mode_and_roundtrip(self):
        path = self.serve()
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o660)
        reply = json.loads(self.exchange(path, self.env.signer.line(self.env.body("hello"))))
        self.assertTrue(reply["ok"])

    def test_real_socket_peer_credentials_reject_other_users(self):
        env = Env(plugin_uid=os.getuid() + 1)                 # the plugin is supposed to be somebody else
        self.addCleanup(env.close)
        srv = server.make_plugin_server(env.proto, env.cfg["plugin_socket"], handler_timeout=2)
        threading.Thread(target=lambda: srv.serve_forever(0.02), daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        self.assertEqual(self.exchange(env.cfg["plugin_socket"], env.signer.line(env.body("hello"))), b"")
        self.assertEqual(events(env, "auth_fail")[-1]["code"], "peer_denied")

    def test_wrong_uid_is_checked_before_concurrency(self):
        path = self.serve_limited(max_concurrency=0)                 # every slot is taken: an allowed peer is told `busy`
        self.assertEqual(json.loads(self.exchange(path, b"x"))["error"]["code"], "busy")
        with mock.patch.object(server, "peer_uid", return_value=self.env.uid + 1):
            self.assertEqual(self.exchange(path, b"x"), b"")         # a stranger gets nothing, not even `busy`
        last = events(self.env, "auth_fail")[-1]
        self.assertEqual((last["code"], last["peerUid"]), ("peer_denied", self.env.uid + 1))

    def serve_limited(self, **kw):
        srv = server.make_plugin_server(self.env.proto, self.env.cfg["plugin_socket"], handler_timeout=2, **kw)
        threading.Thread(target=lambda: srv.serve_forever(0.02), daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        return self.env.cfg["plugin_socket"]

    def test_idle_connection_is_dropped(self):
        path = self.serve()
        with socket.socket(socket.AF_UNIX) as s:
            s.settimeout(6)
            s.connect(path)
            self.assertEqual(s.recv(10), b"")                 # no newline sent: the server gives up after handler_timeout

    def test_admin_socket_accepts_owner_and_drops_other_users(self):
        srv = server.make_admin_server(self.env.broker, self.env.cfg["admin_socket"], handler_timeout=2,
                                       on_reject=lambda uid: self.env.proto.audit_failure("peer_denied", socket="admin", peerUid=uid))
        threading.Thread(target=lambda: srv.serve_forever(0.02), daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        path = self.env.cfg["admin_socket"]
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        self.assertTrue(json.loads(self.exchange(path, b'{"cmd":"status"}'))["ok"])
        with mock.patch.object(server, "peer_uid", return_value=4242):
            self.assertEqual(self.exchange(path, b'{"cmd":"status"}'), b"")
        last = events(self.env, "auth_fail")[-1]                  # the rejection is audited (sampled like plugin.sock's)
        self.assertEqual((last["code"], last["socket"], last["peerUid"]), ("peer_denied", "admin", 4242))
        self.assertFalse(json.loads(self.exchange(path, b"not json"))["ok"])

    def test_admin_rejections_are_sampled_like_plugin_failures(self):
        srv = server.make_admin_server(self.env.broker, self.env.cfg["admin_socket"], handler_timeout=2,
                                       on_reject=lambda uid: self.env.proto.audit_failure("peer_denied", socket="admin", peerUid=uid))
        threading.Thread(target=lambda: srv.serve_forever(0.02), daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        with mock.patch.object(server, "peer_uid", return_value=4242):
            for _ in range(server.FAIL_AUDIT_FREE + 5):
                self.exchange(self.env.cfg["admin_socket"], b"{}")
        self.assertEqual(len(events(self.env, "auth_fail")), server.FAIL_AUDIT_FREE)


class Enrolment(unittest.TestCase):
    CODE = "ABCD-EFGH-JKLM-NPQR"

    def setUp(self):
        self.env = Env(enrolled=False)
        self.addCleanup(self.env.close)
        self.write_enrol()

    def write_enrol(self, code=None, expires=None, uid=None, install_id=INSTALL_ID):
        with open(self.env.cfg["enrol_path"], "w") as f:
            json.dump({"installId": install_id, "codeHash": server.Enrolment.code_hash(code or self.CODE),
                       "expiresAt": expires or iso(self.env.clock() + 900), "serviceUid": self.env.uid if uid is None else uid}, f)

    def enrol(self, code=None, signer=None, **over):
        s = signer or self.env.signer
        body = self.env.body("enrol", {"code": code or self.CODE, "publicKey": s.spki, "pluginVersion": "0.1.0"}, **over)
        return self.env.send(body, signer=s)

    def test_enrolment_stores_the_key_and_unlocks_signed_calls(self):
        r = self.enrol()
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["data"], {"installId": INSTALL_ID, "vaultdVersion": "0.1.0", "apiVersion": 1})
        self.assertEqual(os.stat(self.env.cfg["key_path"]).st_mode & 0o777, 0o600)
        with open(self.env.cfg["key_path"]) as f:
            rec = json.load(f)
        self.assertEqual((rec["kid"], rec["publicKey"], rec["serviceUid"]), (self.env.signer.kid, self.env.signer.spki, self.env.uid))
        self.assertNotIn(self.CODE, json.dumps(rec))                       # only the hash is stored
        self.assertTrue(self.env.ask("hello")["ok"])

    def test_enrol_is_sent_without_an_install_id(self):
        body = self.env.body("enrol", {"code": self.CODE, "publicKey": self.env.signer.spki}, installId=None)
        self.assertTrue(self.env.send(body)["ok"])
        self.assertEqual(self.env.send(self.env.body("hello", installId=None))["error"]["code"], "bad_request")   # any other type names it

    def test_code_is_single_use(self):
        self.assertTrue(self.enrol()["ok"])
        r = self.enrol(signer=Signer(b"\x05" * 32))                        # an attacker with the (leaked) code and its own key
        self.assertEqual((r["ok"], r["error"]["code"]), (False, "denied"))
        self.assertTrue(self.env.ask("hello")["ok"])                       # the first key still works

    def test_a_new_installer_run_with_a_new_code_rotates_the_key(self):
        self.assertTrue(self.enrol()["ok"])
        self.write_enrol(code="ZZZZ-YYYY-XXXX-WWWW")
        second = Signer(b"\x06" * 32)
        r = self.enrol(code="ZZZZ-YYYY-XXXX-WWWW", signer=second)
        self.assertTrue(r["ok"], r)
        self.assertEqual(self.env.send(self.env.body("hello"), signer=second)["data"]["installId"], INSTALL_ID)
        self.assertEqual(self.env.send(self.env.body("hello"))["error"]["code"], "bad_signature")

    def test_wrong_code_expired_code_wrong_install_wrong_user(self):
        self.assertEqual(self.enrol(code="AAAA-BBBB-CCCC-DDDD")["error"]["code"], "denied")
        self.env.clock.advance(901)
        self.assertEqual(self.enrol()["error"]["message"], "enrolment code expired")
        self.write_enrol(install_id="inst-" + "00" * 12)
        self.assertEqual(self.enrol()["error"]["message"], "wrong installId")
        self.write_enrol(uid=self.env.uid + 1)
        self.assertEqual(self.enrol()["error"]["message"], "wrong service user")
        self.assertFalse(os.path.exists(self.env.cfg["key_path"]))

    def test_code_is_normalised(self):
        self.assertTrue(self.enrol(code="abcd efgh-jklm npqr")["ok"])

    def test_wrong_proof_of_possession(self):
        a, b = self.env.signer, Signer(b"\x09" * 32)
        body = self.env.body("enrol", {"code": self.CODE, "publicKey": a.spki, "pluginVersion": "0"})
        self.assertEqual(self.env.send(body, signer=b, kid=a.kid)["error"]["code"], "bad_signature")      # key sent is not the signing key
        self.assertEqual(self.env.send(self.env.body("enrol", {"code": self.CODE, "publicKey": a.spki}), signer=a, kid=b.kid)["error"]["code"],
                         "bad_request")                                                                      # kid does not match the key
        self.assertFalse(os.path.exists(self.env.cfg["key_path"]))

    def test_no_enrolment_pending(self):
        os.unlink(self.env.cfg["enrol_path"])
        self.assertEqual(self.enrol()["error"]["message"], "no enrolment pending")
        with open(self.env.cfg["enrol_path"], "w") as f:
            f.write("{broken")
        self.assertEqual(self.enrol()["error"]["code"], "denied")

    def test_malformed_public_key(self):
        body = self.env.body("enrol", {"code": self.CODE, "publicKey": "AAAA"})
        self.assertEqual(self.env.send(body)["error"]["code"], "bad_request")


if __name__ == "__main__":
    unittest.main()
