"""python3 -m vaultd serve --config FILE | verify-audit FILE..."""
import argparse
import json
import os
import sys
import threading

from . import audit
from .broker import Broker
from .helperclient import HelperClient
from .policy import Policy
from .server import (Enrolment, PluginProtocol, activated_listener, make_admin_server, make_plugin_server, start_sweeper,
                     systemd_listen_fds)
from .store import Store

DEFAULTS = {
    "policy_path": "/etc/vault/policy.json", "sites_dir": "/etc/vault/sites", "enrol_path": "/etc/vault/enrol.json",
    "judge_tests_dir": os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "judge-tests"),
    "plugin_socket": "/run/vault/plugin.sock", "admin_socket": "/run/vault/admin.sock",
    "helper_socket": "/run/vault-helper/helper.sock", "helper_token_path": "/etc/vault/helper.token",
    "audit_path": "/var/log/vault/audit.jsonl", "db_path": "/var/lib/vault/vault.db", "key_path": "/var/lib/vault/plugin-key.json",
    "allowed_company_ids": [], "verdict_timeout_s": 180, "max_concurrency": 32, "handler_timeout": 10,
}
REQUIRED = ("plugin_uid",)     # the uid of the Paperclip service user, written by the installer


def own_uid():
    return os.getuid()


def load_config(path):
    with open(path) as f:
        cfg = dict(DEFAULTS, **json.load(f))
    for k in REQUIRED:
        if k not in cfg:
            sys.exit("config: %s is required" % k)
    if not isinstance(cfg["plugin_uid"], int) or isinstance(cfg["plugin_uid"], bool) or cfg["plugin_uid"] < 0:
        sys.exit("config: plugin_uid must be a user id")
    if cfg["plugin_uid"] == 0:
        sys.exit("config: plugin_uid must not be 0 (root): the plugin runs as the Paperclip service user")
    if cfg["plugin_uid"] == own_uid():
        sys.exit("config: plugin_uid must not be vaultd's own uid (%d): the plugin runs as the Paperclip service user" % own_uid())
    return cfg


def build(cfg, creds_dir, spawn=None):
    """The wired-up service objects (no sockets yet)."""
    log = audit.AuditLog(cfg["audit_path"])
    store = Store(cfg["db_path"])
    enrolment = Enrolment(cfg["key_path"], cfg["enrol_path"], cfg["plugin_uid"])
    broker = Broker(cfg, Policy.load(cfg["policy_path"]), store, HelperClient(cfg["helper_socket"], cfg["helper_token_path"]),
                    log, creds_dir, enrolment.install_id, spawn=spawn)
    return broker, PluginProtocol(broker, enrolment, store, log, cfg["plugin_uid"])


def serve(config_path):
    cfg = load_config(config_path)
    broker, protocol = build(cfg, os.environ["CREDENTIALS_DIRECTORY"])   # set by systemd (ImportCredential=vault.*)
    # plugin.sock comes from vaultd.socket (systemd socket activation: LISTEN_FDS/LISTEN_PID, fd 3); without activation (tests, dev)
    # vaultd binds cfg["plugin_socket"] itself.
    plugin_srv = make_plugin_server(protocol, cfg["plugin_socket"], cfg["handler_timeout"], cfg["max_concurrency"],
                                    listen_fd=activated_listener(systemd_listen_fds()))
    admin_srv = make_admin_server(broker, cfg["admin_socket"], cfg["handler_timeout"],
                                  lambda uid: protocol.audit_failure("peer_denied", socket="admin", peerUid=uid))
    broker.reconcile()
    start_sweeper(broker)
    threading.Thread(target=admin_srv.serve_forever, daemon=True).start()
    plugin_srv.serve_forever()


def main(argv=None):
    p = argparse.ArgumentParser(prog="vaultd")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve")
    s.add_argument("--config", required=True)
    v = sub.add_parser("verify-audit")
    v.add_argument("files", nargs="+", help="audit files, oldest first")
    v.add_argument("--allow-partial", action="store_true",
                   help="do not require the first record to chain from genesis")
    a = p.parse_args(argv)
    if a.cmd == "serve":
        serve(a.config)
    ok, msg = audit.verify(a.files, from_genesis=not a.allow_partial)
    print(msg)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
