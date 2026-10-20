"""Append-only, SHA-256 hash-chained audit log (JSON Lines). Never receives secrets."""
import glob
import gzip
import hashlib
import json
import os
import sys
import threading

GENESIS = "0" * 64


def _digest(entry):
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _alert_default(msg):
    print("ALERT " + msg, file=sys.stderr, flush=True)


def _open(path):
    """Text reader; rotated months compressed by the retention job (audit-<UTC time>.jsonl.gz) read transparently."""
    return gzip.open(path, "rt") if path.endswith(".gz") else open(path)


def _last_record(path, alert=_alert_default):
    """The last parsable record. A torn final line (crash mid-write) is skipped with an
    ALERT. Returns (last good record or None, torn_line or None)."""
    last = torn = None
    with _open(path) as f:
        for line in f:
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
                rec["hash"]      # a record without a hash is as unusable as a torn one
                last, torn = rec, None
            except (ValueError, KeyError, TypeError):
                torn = line.rstrip("\n")
    if torn is not None:
        alert(f"audit: {path} ends with an unparsable (torn) record; continuing the chain from the last good one")
    return last, torn


class AuditLog:
    def __init__(self, path, alert=_alert_default):
        self.path = path
        self.alert = alert
        self.lock = threading.Lock()
        self.torn = None
        self.prev, self.seq = self._recover()

    def _recover(self):
        # Continue the chain from this file, or from the newest rotated file
        # (audit-*.jsonl or .jsonl.gz next to it) when this one is new or empty.
        if os.path.exists(self.path):
            rec, self.torn = _last_record(self.path, self.alert)
            if rec:
                return rec["hash"], rec.get("seq", 0)
        d, base = os.path.split(self.path)
        stem, ext = os.path.splitext(base)
        rotated_files = glob.glob(os.path.join(d, f"{stem}-*{ext}")) + glob.glob(os.path.join(d, f"{stem}-*{ext}.gz"))
        for rotated in sorted(rotated_files, key=lambda r: r[:-3] if r.endswith(".gz") else r, reverse=True):
            rec, _ = _last_record(rotated, self.alert)
            if rec:
                return rec["hash"], rec.get("seq", 0)
        return GENESIS, 0

    def write(self, entry):
        with self.lock:
            if self.torn is not None:
                # Close the torn line and record that we did, so verify can tell it from tampering.
                self._append({"event": "torn-tail-recovered",
                              "bad_line_sha256": hashlib.sha256(self.torn.encode()).hexdigest()},
                             lead="\n" if self.torn else "")
                self.torn = None
            self._append(entry)

    def _append(self, entry, lead=""):
        entry = dict(entry, prev_hash=self.prev, seq=self.seq + 1)
        entry["hash"] = _digest(entry)
        # Opened per write so an admin can rotate the file under us.
        with open(self.path, "a") as f:
            f.write(lead + json.dumps(entry, sort_keys=True) + "\n")
            f.flush()
            os.fsync(f.fileno())
        self.prev, self.seq = entry["hash"], entry["seq"]


def read_events(path, event, limit, before_seq=None):
    """Up to `limit` records of one event type from the live file, newest first, with seq < before_seq. Reads the file
    backwards in blocks, so a long log costs only what is asked for. Unparsable lines (a torn tail) are skipped."""
    out = []
    with open(path, "rb") as f:
        f.seek(0, os.SEEK_END)
        pos, tail = f.tell(), b""
        while pos > 0 and len(out) < limit:
            step = min(65536, pos)
            pos -= step
            f.seek(pos)
            lines = (f.read(step) + tail).split(b"\n")
            tail, lines = (lines[0], lines[1:]) if pos > 0 else (b"", lines)
            for line in reversed(lines):
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                if isinstance(e, dict) and e.get("event") == event and (before_seq is None or e.get("seq", 0) < before_seq):
                    out.append(e)
                    if len(out) >= limit:
                        break
    return out


def verify(paths, from_genesis=True):
    """Check the chain across files given oldest first. Returns (ok, message).
    from_genesis: the first record must chain from GENESIS (detects deleted oldest records);
    pass False when the oldest file is deliberately not included."""
    prev, n, torn = None, 0, None
    for path in paths:
        with _open(path) as f:
            for i, line in enumerate(f, 1):
                if not line.strip():
                    continue
                try:
                    e = json.loads(line)
                except ValueError:
                    if torn:
                        return False, f"{path}:{i}: not JSON"
                    torn = (path, i, hashlib.sha256(line.rstrip("\n").encode()).hexdigest())
                    continue
                if not isinstance(e, dict):
                    return False, f"{path}:{i}: not an audit record"
                if torn:   # only a recorded recovery may follow an unparsable line
                    if e.get("event") != "torn-tail-recovered" or e.get("bad_line_sha256") != torn[2]:
                        return False, f"{torn[0]}:{torn[1]}: not JSON"
                    torn = None
                if prev is None:
                    if from_genesis and e.get("prev_hash") != GENESIS:
                        return False, f"{path}:{i}: chain does not start at genesis (oldest records removed?)"
                elif e.get("prev_hash") != prev:
                    return False, f"{path}:{i}: chain broken (prev_hash mismatch)"
                if e.get("hash") != _digest(e):
                    return False, f"{path}:{i}: hash mismatch (record altered)"
                prev, n = e["hash"], n + 1
    if torn:
        return True, f"ok: {n} records; WARNING {torn[0]}:{torn[1]} is a torn final record (restart vaultd to recover)"
    return True, f"ok: {n} records"
