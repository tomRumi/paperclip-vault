"""Hash-chained audit log: chain, truncated head, torn tail, rotation (.gz), seq numbers, backwards event reader."""
import gzip
import json
import os
import shutil
import tempfile
import unittest

import support
from vaultd import audit


def read(*parts):
    with open(os.path.join(support.HOST, *parts)) as f:
        return f.read()


class Chain(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="au", dir="/tmp")
        self.addCleanup(shutil.rmtree, self.d, True)
        self.path = os.path.join(self.d, "audit.jsonl")
        self.log = audit.AuditLog(self.path)
        for i in range(4):
            self.log.write({"event": "e", "i": i})

    def lines(self):
        with open(self.path) as f:
            return f.read().splitlines()

    def test_chain_verifies_and_every_record_has_a_seq(self):
        ok, msg = audit.verify([self.path])
        self.assertTrue(ok, msg)
        self.assertEqual([json.loads(l)["seq"] for l in self.lines()], [1, 2, 3, 4])

    def test_altered_record_is_detected(self):
        lines = self.lines()
        lines[1] = lines[1].replace('"i": 1', '"i": 9')
        with open(self.path, "w") as f:
            f.write("\n".join(lines) + "\n")
        self.assertFalse(audit.verify([self.path])[0])

    def test_truncated_head_is_detected(self):
        kept = self.lines()[1:]
        with open(self.path, "w") as f:
            f.write("\n".join(kept) + "\n")
        ok, msg = audit.verify([self.path])
        self.assertFalse(ok)
        self.assertIn("genesis", msg)
        self.assertTrue(audit.verify([self.path], from_genesis=False)[0])

    def test_torn_final_line_is_skipped_with_alert_and_chain_continues(self):
        with open(self.path, "a") as f:
            f.write('{"agent": "a1", "tru')
        alerts = []
        log = audit.AuditLog(self.path, alert=alerts.append)
        self.assertTrue(any("torn" in a for a in alerts))
        self.assertIn("WARNING", audit.verify([self.path])[1])
        log.write({"x": 1})
        ok, msg = audit.verify([self.path])
        self.assertTrue(ok, msg)
        self.assertNotIn("WARNING", msg)
        self.assertEqual(log.seq, 6)                         # 4 records, the recovery record, the new one

    def test_garbage_in_the_middle_still_fails(self):
        lines = self.lines()
        lines.insert(1, "garbage")
        with open(self.path, "w") as f:
            f.write("\n".join(lines) + "\n")
        self.assertFalse(audit.verify([self.path])[0])

    def test_restart_continues_hash_and_seq(self):
        log2 = audit.AuditLog(self.path)
        log2.write({"event": "after"})
        self.assertTrue(audit.verify([self.path])[0])
        self.assertEqual(json.loads(self.lines()[-1])["seq"], 5)

    def test_read_events_newest_first_with_paging_and_a_torn_tail(self):
        for i in range(30):
            self.log.write({"event": "decision" if i % 3 == 0 else "other", "n": i})
        with open(self.path, "a") as f:
            f.write('{"event": "decision", "tru')
        got = audit.read_events(self.path, "decision", 5)
        self.assertEqual([e["n"] for e in got], [27, 24, 21, 18, 15])
        older = audit.read_events(self.path, "decision", 100, before_seq=got[-1]["seq"])
        self.assertEqual([e["n"] for e in older], [12, 9, 6, 3, 0])
        self.assertEqual(audit.read_events(self.path, "nothing", 5), [])

    def test_read_events_across_many_blocks(self):
        for i in range(2000):
            self.log.write({"event": "decision", "n": i, "pad": "x" * 100})
        got = audit.read_events(self.path, "decision", 1500)
        self.assertEqual([e["n"] for e in got], list(range(1999, 499, -1)))


class Retention(unittest.TestCase):
    """Rotation/retention (vault-audit-rotate): compressed rotated months stay verifiable and recoverable."""

    def make(self, d, n):
        log = audit.AuditLog(os.path.join(d, "audit.jsonl"))
        for i in range(n):
            log.write({"event": "e", "i": i})
        return log

    def gz(self, path):
        with open(path, "rb") as a, gzip.open(path + ".gz", "wb") as b:
            shutil.copyfileobj(a, b)
        os.remove(path)

    def test_gz_rotated_file_is_verified_and_chain_and_seq_recover_from_it(self):
        with tempfile.TemporaryDirectory() as d:
            last = self.make(d, 3)
            live = os.path.join(d, "audit.jsonl")
            rot = os.path.join(d, "audit-2026-09.jsonl")
            os.rename(live, rot)
            self.gz(rot)
            fresh = audit.AuditLog(live)
            self.assertEqual((fresh.prev, fresh.seq), (last.prev, 3))       # new live file continues from the .gz
            fresh.write({"event": "after"})
            self.assertTrue(audit.verify([rot + ".gz", live])[0])

    def test_rotation_time_names_sort_newest_last_across_gz_and_plain(self):
        with tempfile.TemporaryDirectory() as d:
            live = os.path.join(d, "audit.jsonl")
            self.make(d, 1)
            os.rename(live, os.path.join(d, "audit-2026-10-01T003000Z.jsonl"))
            audit.AuditLog(live).write({"event": "x"})
            os.rename(live, os.path.join(d, "audit-2026-11-01T003000Z.jsonl"))
            self.gz(os.path.join(d, "audit-2026-10-01T003000Z.jsonl"))
            with open(os.path.join(d, "audit-2026-11-01T003000Z.jsonl")) as f:
                want = json.loads(f.readlines()[-1])["hash"]
            self.assertEqual(audit.AuditLog(live).prev, want)

    def test_rotation_script_and_units_exist_and_are_safe(self):
        sh = read("sbin", "vault-audit-rotate")
        for needle in ("trap ", "systemctl start vaultd", "chattr -a", "chattr +a", "mask::r--", "-mtime", "set -euo pipefail"):
            self.assertIn(needle, sh)
        self.assertIn("Persistent=true", read("units", "vault-audit-rotate.timer"))
        self.assertIn("ExecStart=/opt/vault/sbin/vault-audit-rotate", read("units", "vault-audit-rotate.service"))
        self.assertIn("verify-audit", read("INSTALL.md"))

    def test_rotation_recreates_the_live_log_0600_and_keeps_the_vaultaudit_acl(self):
        """vault-helper is in group vault and must not read the audit log: no 0640 anywhere, the ACL check stays."""
        sh = read("sbin", "vault-audit-rotate")
        code = [l for l in sh.splitlines() if not l.lstrip().startswith("#")]
        self.assertFalse([l for l in code if "0640" in l], "audit files must never be group readable by mode")
        recreate = [l for l in code if "install " in l and '"$LIVE"' in l]
        self.assertEqual(len(recreate), 2, recreate)             # the rotation and the restore() fallback
        for l in recreate:
            self.assertIn("-o vault -g vault -m 0600 /dev/null", l)
            self.assertIn("setfacl -m g:vaultaudit:r,m::r", l + sh)
        self.assertTrue([l for l in code if "chmod 0600" in l and "$tmp" in l and "g:vaultaudit:r,m::r" in l], "rotated .gz")
        self.assertIn("group:vaultaudit:r--", sh)
        self.assertIn("mask::r--", sh)


if __name__ == "__main__":
    unittest.main()
