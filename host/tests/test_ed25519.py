"""Pure-Python Ed25519 verification against RFC 8032, signatures made by Node (node:crypto) and by openssl."""
import base64
import json
import os
import shutil
import subprocess
import tempfile
import unittest

import support
from vaultd import ed25519

# RFC 8032 section 7.1 (TEST 1, TEST 2)
RFC = [
    ("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
]


class RFC8032(unittest.TestCase):
    def test_rfc_vectors(self):
        for pk, msg, sig in RFC:
            self.assertTrue(ed25519.verify(bytes.fromhex(pk), bytes.fromhex(msg), bytes.fromhex(sig)), pk[:8])
            self.assertFalse(ed25519.verify(bytes.fromhex(pk), bytes.fromhex(msg) + b"x", bytes.fromhex(sig)))

    def test_rejects_malformed_input(self):
        pk, msg, sig = (bytes.fromhex(x) for x in RFC[0])
        self.assertFalse(ed25519.verify(pk[:31], msg, sig))
        self.assertFalse(ed25519.verify(pk, msg, sig[:63]))
        # S >= L (non-canonical signature scalar) must be refused even though S + L verifies arithmetically
        s = int.from_bytes(sig[32:], "little") + ed25519.L
        self.assertFalse(ed25519.verify(pk, msg, sig[:32] + s.to_bytes(32, "little")))
        # a y coordinate that is not on the curve, and a 32-byte string that is not a point
        self.assertFalse(ed25519.verify(bytes([2]) + bytes(31), msg, sig))
        self.assertFalse(ed25519.verify(pk, msg, bytes([2]) + bytes(31) + sig[32:]))
        self.assertFalse(ed25519.verify(pk, msg, bytes(64)))

    def test_rejects_small_order_keys_and_nonces(self):
        # the eight small-order encodings: y = 0 (x = +-sqrt(-1)), y = 1 (identity), y = -1, and the two y's of order 8
        small = [bytes.fromhex(h) for h in (
            "0100000000000000000000000000000000000000000000000000000000000000",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000080",
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85")]
        for enc in small:
            self.assertIsNotNone(ed25519.decode(enc))
            self.assertTrue(ed25519._small_order(ed25519.decode(enc)), enc.hex())
        identity = small[0]
        forged = identity + bytes(32)                      # R = identity, S = 0: [0]B == R + [h]A for every message
        for msg in (b"", b"anything", b"pcvault-v1\n{}"):
            self.assertFalse(ed25519.verify(identity, msg, forged))
        for enc in small:
            self.assertFalse(ed25519.verify(enc, b"m", forged))
            self.assertFalse(ed25519.verify(enc, b"m", enc + bytes(32)))
        # a small-order R under an honest key is refused too
        sg = support.Signer()
        sig = sg.sign(b"m")
        for enc in small:
            self.assertFalse(ed25519.verify(sg.public, b"m", enc + sig[32:]))
        self.assertFalse(ed25519._small_order(ed25519.BASE))
        self.assertTrue(ed25519.verify(sg.public, b"m", sig))

    def test_spki_and_key_id(self):
        sg = support.Signer()
        self.assertEqual(ed25519.raw_key_from_spki(sg.spki), sg.public)
        self.assertIsNone(ed25519.raw_key_from_spki("not base64!"))
        self.assertIsNone(ed25519.raw_key_from_spki(base64.b64encode(b"\x30\x2a" + bytes(42)).decode()))
        self.assertEqual(len(sg.kid), 16)
        self.assertEqual(sg.kid, __import__("hashlib").sha256(base64.b64decode(sg.spki)).hexdigest()[:16])

    def test_signing_helper_matches_verify(self):
        sg = support.Signer(b"\x07" * 32)
        for msg in (b"", b"abc", os.urandom(300)):
            self.assertTrue(ed25519.verify(sg.public, msg, sg.sign(msg)))
            self.assertFalse(ed25519.verify(sg.public, msg + b"1", sg.sign(msg)))


def shared_vectors():
    with open(os.path.join(support.REPO, "tests", "vectors", "ed25519.json")) as f:
        return json.load(f)


class NodeSignatures(unittest.TestCase):
    """The plugin's shared vectors (tests/vectors/ed25519.json, made with node:crypto)."""

    def test_rfc8032_vectors(self):
        for c in shared_vectors()["rfc8032"]:
            got = ed25519.verify(bytes.fromhex(c["publicKeyHex"]), bytes.fromhex(c["msgHex"]), bytes.fromhex(c["sigHex"]))
            self.assertEqual(got, c["valid"], c["name"])

    def test_signatures_over_prefix_and_body(self):
        v = shared_vectors()
        cases = v["signatures"]
        self.assertGreaterEqual(len(cases), 10)
        for c in cases:
            pk = ed25519.raw_key_from_spki(c["publicKeySpkiB64"])
            msg = base64.urlsafe_b64decode(c["msgB64url"] + "=" * (-len(c["msgB64url"]) % 4))
            got = ed25519.verify(pk, v["signedPrefix"].encode() + msg, base64.b64decode(c["sigB64"]))
            self.assertEqual(got, c["valid"], c["name"])
        self.assertEqual(ed25519.key_id(v["key"]["publicKeySpkiB64"]), v["key"]["kid"])

    def test_wire_lines_through_the_protocol(self):
        import time
        from vaultd import server
        v = shared_vectors()
        for c in v["wire"]:
            env = support.Env(enrolled=False)
            self.addCleanup(env.close)
            install = "inst-0123456789abcdef01234567"
            env.clock.t = 1_792_411_200.0                                            # 2026-10-19T12:00:00Z
            if c["body"] and c["body"]["type"] == "enrol":
                with open(env.cfg["enrol_path"], "w") as f:
                    json.dump({"installId": install, "codeHash": server.Enrolment.code_hash(c["body"]["data"]["code"]),
                               "expiresAt": "2026-10-19T12:15:00Z", "serviceUid": env.uid}, f)
            else:
                with open(env.cfg["key_path"], "w") as f:
                    json.dump({"installId": install, "kid": v["key"]["kid"], "publicKey": v["key"]["publicKeySpkiB64"], "serviceUid": env.uid,
                               "enrolledAt": "2026-01-01T00:00:00Z", "codeHash": "0" * 64}, f)
            env.build()
            reply = json.loads(env.proto.handle(c["line"].encode(), env.uid))
            self.assertEqual(reply["ok"], c["valid"], (c["name"], reply))
            if c["valid"]:
                self.assertEqual(reply["nonce"], c["nonce"])
            else:
                self.assertIn(reply["error"]["code"], ("bad_signature", "bad_request"), c["name"])


@unittest.skipUnless(shutil.which("openssl"), "openssl not installed")
class OpensslSignatures(unittest.TestCase):
    def test_openssl_signature_verifies(self):
        with tempfile.TemporaryDirectory() as d:
            key, msg, sig, pub = (os.path.join(d, n) for n in ("k.pem", "m", "s", "p.der"))
            run = lambda *a: subprocess.run(a, check=True, capture_output=True)
            run("openssl", "genpkey", "-algorithm", "ed25519", "-out", key)
            with open(msg, "wb") as f:
                f.write(b"pcvault-v1\n" + os.urandom(200))
            run("openssl", "pkeyutl", "-sign", "-inkey", key, "-rawin", "-in", msg, "-out", sig)
            run("openssl", "pkey", "-in", key, "-pubout", "-outform", "DER", "-out", pub)
            data = {}
            for name, path in (("spki", pub), ("msg", msg), ("sig", sig)):
                with open(path, "rb") as f:
                    data[name] = f.read()
            raw = ed25519.raw_key_from_spki(base64.b64encode(data["spki"]).decode())
            self.assertTrue(ed25519.verify(raw, data["msg"], data["sig"]))
            self.assertFalse(ed25519.verify(raw, data["msg"] + b"x", data["sig"]))


if __name__ == "__main__":
    unittest.main()
