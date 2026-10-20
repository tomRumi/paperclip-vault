"""Package-level checks: removed features are gone (grep), the unit is hardened as designed, the examples are consistent."""
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import unittest

import support
from support import HOST, Signer, INSTALL_ID, COMPANY, AGENT_QA, ISSUE, site_json, POLICY, SECRETS
from vaultd.policy import Policy

REMOVED = re.compile(r"call_decisions_api|modelgate|standing|judge_url|judge_model|judge_margin|judge_key|approval|manual|vault-get|"
                     r"vault-bridge|judge-models|status_path|proposal_path|locked_path|paperclip_url|PAPERCLIP_API_KEY|Decisions API", re.I)


def read(*parts):
    with open(os.path.join(HOST, *parts)) as f:
        return f.read()


def text_files(*roots):
    for root in roots:
        path = os.path.join(HOST, root)
        if os.path.isfile(path):
            yield path
            continue
        for d, _, files in os.walk(path):
            if "__pycache__" in d:
                continue
            for n in files:
                yield os.path.join(d, n)


class RemovedFeatures(unittest.TestCase):
    def test_manual_approval_standing_mode_model_call_and_agent_cli_are_gone(self):
        for gone in ("vaultd/modelgate.py", "vaultd/paperclip.py", "vaultd/status.py", "bin/vault-get", "tests/test_modelgate.py",
                     "judge-tests/prompt.md"):
            self.assertFalse(os.path.exists(os.path.join(HOST, gone)), gone)
        hits = []
        for path in text_files("vaultd", "bin", "units", "policy.example.json", "config.example.json", "judge-tests/score.py"):
            for i, line in enumerate(read(os.path.relpath(path, HOST)).splitlines(), 1):
                if REMOVED.search(line):
                    hits.append("%s:%d: %s" % (os.path.relpath(path, HOST), i, line.strip()[:100]))
        self.assertEqual(hits, [])

    def test_the_docs_do_not_describe_removed_features(self):
        for doc in ("README.md", "INSTALL.md", "judge-tests/README.md", "../docs/judge-model-selection.md"):
            body = read(doc)
            for word in ("vault-get", "standing mode", "judge_url", "judge_margin", "modelgate", "Decisions API", "manual approval"):
                self.assertNotIn(word, body, "%s mentions %s" % (doc, word))

    def test_policy_refuses_the_removed_class_flags_and_vaultctl_the_removed_commands(self):
        for key in ("standing", "approval"):
            bad = {"roles": {}, "classes": {"c": {"match": "c-*", "scopes": ["use"], key: True}}}
            with self.assertRaises(ValueError):
                Policy(bad)
        ctl = read("bin", "vaultctl")
        for cmd in ("mode", "queue", "approve", "deny"):
            self.assertNotRegex(ctl, r'cmd == "%s"' % cmd)
        r = subprocess.run([sys.executable, "-B", os.path.join(HOST, "bin", "vaultctl"), "approve", "x"], capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("vaultctl status", r.stderr)

    def test_config_example_has_only_keys_vaultd_reads(self):
        from vaultd.__main__ import DEFAULTS
        ex = json.loads(read("config.example.json"))
        self.assertEqual(set(ex) - set(DEFAULTS) - {"plugin_uid"}, set())
        self.assertIn("plugin_uid", ex)
        self.assertNotIn("mode", ex)


class Unit(unittest.TestCase):
    unit = read("units", "vaultd.service")

    def lines(self):
        return [l.strip() for l in self.unit.splitlines() if l.strip() and not l.startswith("#")]

    def test_hardening(self):
        for need in ("User=vault", "Group=vault", "ImportCredential=vault.*", "PrivateNetwork=yes",
                     "RestrictAddressFamilies=AF_UNIX", "RuntimeDirectory=vault", "RuntimeDirectoryMode=0711", "StateDirectory=vault",
                     "ReadWritePaths=/var/log/vault", "NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes",
                     "PrivateDevices=yes", "MemoryDenyWriteExecute=yes", "CapabilityBoundingSet=", "UMask=0077", "LockPersonality=yes",
                     "RestrictNamespaces=yes", "SystemCallFilter=@system-service", "SystemCallFilter=~@privileged @resources",
                     "ProtectKernelTunables=yes", "ProtectKernelModules=yes", "ProtectKernelLogs=yes", "ProtectControlGroups=yes",
                     "ProtectClock=yes", "ProtectHostname=yes", "RestrictSUIDSGID=yes", "RestrictRealtime=yes", "PrivateIPC=yes",
                     "TasksMax=64", "MemoryMax=256M"):
            self.assertIn(need, self.lines())
        self.assertTrue(any("ExecStart=/usr/bin/python3 -s -m vaultd serve --config /etc/vault/config.json" == l for l in self.lines()))
        self.assertTrue(any("PYTHON_JIT=0" in l for l in self.lines()))

    def test_no_group_access_and_a_socket_unit(self):
        self.assertNotIn("vault-plugin", self.unit)
        self.assertNotIn("SupplementaryGroups", self.unit)
        self.assertIn("Requires=vaultd.socket", self.unit)
        sock = read("units", "vaultd.socket")
        lines = [l.strip() for l in sock.splitlines() if l.strip() and not l.startswith("#")]
        for need in ("ListenStream=/run/vault/plugin.sock", "SocketUser=vault", "SocketGroup=vault", "SocketMode=0600",
                     "ExecStartPost=/usr/bin/setfacl -m u:@SVC@:rw /run/vault/plugin.sock", "Service=vaultd.service",
                     "WantedBy=sockets.target"):
            self.assertIn(need, lines)
        self.assertNotIn("vault-plugin", sock)
        self.assertIn("RuntimeDirectoryMode=0711", self.lines())
        self.assertIn("RuntimeDirectoryPreserve=yes", self.lines())
        self.assertIn("DirectoryMode=0711", lines)

    def test_no_network_no_judge_key_no_bridge(self):
        for gone in ("network-online", "vaultd-judge", "vault-bridge", "AF_INET"):
            self.assertNotIn(gone, self.unit)
        self.assertEqual([l for l in self.lines() if l.startswith("ImportCredential")], ["ImportCredential=vault.*"])
        self.assertEqual([l for l in self.lines() if l.startswith("ReadWritePaths")], ["ReadWritePaths=/var/log/vault"])

    def test_unit_files_live_in_units(self):
        for n in ("vaultd.service", "vaultd.socket", "vault-audit-rotate.service", "vault-audit-rotate.timer"):
            self.assertTrue(os.path.exists(os.path.join(HOST, "units", n)), n)
            self.assertFalse(os.path.exists(os.path.join(HOST, n)), n)


class Service(unittest.TestCase):
    """The real process: python3 -m vaultd serve, signed hello over plugin.sock, vaultctl over admin.sock."""

    def test_serve_end_to_end(self):
        env = support.Env(enrolled=False)
        self.addCleanup(env.close)
        env.write_key()
        creds = env.creds
        cfg = dict(env.cfg, plugin_socket=os.path.join(env.dir, "p2.sock"), admin_socket=os.path.join(env.dir, "a2.sock"))
        cfg_path = os.path.join(env.dir, "config.json")
        with open(cfg_path, "w") as f:
            json.dump(cfg, f)
        err = open(os.path.join(env.dir, "stderr.txt"), "w+")
        self.addCleanup(err.close)
        # this test is the plugin user AND vaultd's user, which a real config refuses: only the own-uid lookup is stubbed
        stub = "import sys, vaultd.__main__ as m; m.own_uid = lambda: -1; sys.exit(m.main(['serve', '--config', sys.argv[1]]))"
        proc = subprocess.Popen([sys.executable, "-s", "-B", "-c", stub, cfg_path], cwd=HOST,
                                env={"PATH": os.environ["PATH"], "PYTHONPATH": HOST, "CREDENTIALS_DIRECTORY": creds},
                                stdout=subprocess.DEVNULL, stderr=err)
        self.addCleanup(proc.wait)
        self.addCleanup(proc.terminate)
        deadline = time.time() + 10
        while time.time() < deadline and not (os.path.exists(cfg["plugin_socket"]) and os.path.exists(cfg["admin_socket"])):
            if proc.poll() is not None:
                err.seek(0)
                self.fail(err.read())
            time.sleep(0.05)
        import socket
        sig = Signer()
        body = {"v": 1, "type": "hello", "installId": INSTALL_ID, "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "nonce": "x" * 24, "data": {}}
        with socket.socket(socket.AF_UNIX) as s:
            s.settimeout(10)
            s.connect(cfg["plugin_socket"])
            s.sendall(sig.line(body) + b"\n")
            reply = json.loads(s.makefile("rb").readline())
        self.assertTrue(reply["ok"], reply)
        self.assertEqual((reply["data"]["installId"], reply["data"]["helper"]), (INSTALL_ID, "up"))
        r = subprocess.run([sys.executable, "-B", os.path.join(HOST, "bin", "vaultctl"), "status"], capture_output=True, text=True,
                           env={"PATH": os.environ["PATH"], "VAULT_ADMIN_SOCKET": cfg["admin_socket"]})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout)["installId"], INSTALL_ID)
        r = subprocess.run([sys.executable, "-B", os.path.join(HOST, "bin", "vaultctl"), "company", "add", "cccccccc-0000-4000-8000-0000000000ac"],
                           capture_output=True, text=True, env={"PATH": os.environ["PATH"], "VAULT_ADMIN_SOCKET": cfg["admin_socket"]})
        self.assertIn(COMPANY, json.loads(r.stdout)["companies"])
        r = subprocess.run([sys.executable, "-B", os.path.join(HOST, "bin", "vaultctl"), "verify-audit", cfg["audit_path"]], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(os.stat(cfg["plugin_socket"]).st_mode & 0o777, 0o660)
        self.assertEqual(os.stat(cfg["admin_socket"]).st_mode & 0o777, 0o600)

    def test_socket_activation_takes_fd_3_and_leaves_the_socket_as_systemd_made_it(self):
        import socket
        env = support.Env(enrolled=False)
        self.addCleanup(env.close)
        env.write_key()
        path = os.path.join(env.dir, "act.sock")
        cfg = dict(env.cfg, plugin_socket=path, admin_socket=os.path.join(env.dir, "a3.sock"))
        cfg_path = os.path.join(env.dir, "config-act.json")
        with open(cfg_path, "w") as f:
            json.dump(cfg, f)
        listener = socket.socket(socket.AF_UNIX)           # what systemd does for vaultd.socket: bind, chmod, listen
        listener.bind(path)
        os.chmod(path, 0o600)
        listener.listen(8)
        self.addCleanup(listener.close)
        ino = os.stat(path).st_ino
        err = open(os.path.join(env.dir, "stderr-act.txt"), "w+")
        self.addCleanup(err.close)
        # LISTEN_PID must be the server's own pid, so a stub sets it (and moves the fd to 3) before serving, as systemd does
        stub = ("import os, sys, vaultd.__main__ as m; m.own_uid = lambda: -1; os.dup2(int(sys.argv[2]), 3); "
                "os.environ.update(LISTEN_PID=str(os.getpid()), LISTEN_FDS='1', LISTEN_FDNAMES='plugin.sock'); "
                "sys.exit(m.main(['serve', '--config', sys.argv[1]]))")
        proc = subprocess.Popen([sys.executable, "-s", "-B", "-c", stub, cfg_path, str(listener.fileno())], cwd=HOST,
                                env={"PATH": os.environ["PATH"], "PYTHONPATH": HOST, "CREDENTIALS_DIRECTORY": env.creds},
                                stdout=subprocess.DEVNULL, stderr=err, pass_fds=(listener.fileno(),))
        self.addCleanup(proc.wait)
        self.addCleanup(proc.terminate)
        sig = Signer()
        body = {"v": 1, "type": "hello", "installId": INSTALL_ID, "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "nonce": "y" * 24, "data": {}}
        with socket.socket(socket.AF_UNIX) as s:           # queued by the kernel on the listener even before vaultd has started to accept
            s.settimeout(15)
            s.connect(path)
            s.sendall(sig.line(body) + b"\n")
            try:
                reply = json.loads(s.makefile("rb").readline())
            except ValueError:
                err.seek(0)
                self.fail(err.read())
        self.assertTrue(reply["ok"], reply)
        self.assertEqual(reply["data"]["installId"], INSTALL_ID)
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600, "vaultd must not chmod the socket systemd made")
        self.assertEqual(os.stat(path).st_ino, ino, "vaultd must not unlink and rebind it")

    def test_listen_fds_parsing(self):
        from vaultd import server
        env = {"LISTEN_PID": "123", "LISTEN_FDS": "1", "LISTEN_FDNAMES": "plugin.sock"}
        self.assertEqual(server.systemd_listen_fds(dict(env), pid=123), {"plugin.sock": 3})
        e = dict(env)
        server.systemd_listen_fds(e, pid=123)
        self.assertEqual(e, {}, "the variables are consumed")
        self.assertEqual(server.systemd_listen_fds(dict(env), pid=124), {}, "another process's descriptors are not ours")
        self.assertEqual(server.systemd_listen_fds({}, pid=1), {})
        self.assertEqual(server.systemd_listen_fds({"LISTEN_PID": "x", "LISTEN_FDS": "1"}, pid=1), {})
        self.assertEqual(server.systemd_listen_fds({"LISTEN_PID": "5", "LISTEN_FDS": "2"}, pid=5), {"fd0": 3, "fd1": 4})
        self.assertIsNone(server.activated_listener({}))
        with self.assertRaises(SystemExit):
            server.activated_listener({"a": 3, "b": 4})
        with self.assertRaises(SystemExit):
            server.activated_listener({"a": 2 ** 20})

    def test_missing_plugin_uid_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "c.json")
            with open(p, "w") as f:
                json.dump({}, f)
            r = subprocess.run([sys.executable, "-B", "-m", "vaultd", "serve", "--config", p], cwd=HOST, env={"PATH": os.environ["PATH"], "PYTHONPATH": HOST},
                               capture_output=True, text=True)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("plugin_uid", r.stderr)

    def serve_refused(self, cfg):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "c.json")
            with open(p, "w") as f:
                json.dump(cfg, f)
            r = subprocess.run([sys.executable, "-B", "-m", "vaultd", "serve", "--config", p], cwd=HOST, env={"PATH": os.environ["PATH"], "PYTHONPATH": HOST},
                               capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)
        return r.stderr

    def test_plugin_uid_zero_and_the_service_uid_are_refused(self):
        self.assertIn("must not be 0", self.serve_refused({"plugin_uid": 0}))
        self.assertIn("own uid (%d)" % os.getuid(), self.serve_refused({"plugin_uid": os.getuid()}))
        from vaultd import __main__ as main
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "c.json")
            with open(p, "w") as f:
                json.dump({"plugin_uid": os.getuid() + 1}, f)
            self.assertEqual(main.load_config(p)["plugin_uid"], os.getuid() + 1)


if __name__ == "__main__":
    unittest.main()
