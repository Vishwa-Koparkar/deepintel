"""
Personal feedback database.

Stores the user's corrections of DeepIntel's verdicts (false positives / false negatives) in a
local SQLite file. Two consumers:
  1. analyzer.analyze()  - looks the URL up so a correction takes effect immediately (lookup()).
  2. training            - scripts/pipeline/rebuild_features.py adds the corrections to the
                           training set (training_rows()); tune_model.py then marks them learned.

The DB path can be overridden with DEEPINTEL_FEEDBACK_DB (used by the tests).
"""

import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from urllib.parse import urlparse, urlunparse

LABELS = ("benign", "phishing", "malware")
MAX_NOTE = 500
MAX_URL = 2048

_init_lock = threading.Lock()
_initialised = set()


def db_path():
    return os.environ.get("DEEPINTEL_FEEDBACK_DB", os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "feedback.db"))


@contextmanager
def _conn():
    path = db_path()
    with _init_lock:
        if path not in _initialised:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            c = sqlite3.connect(path)
            c.execute("""
                CREATE TABLE IF NOT EXISTS feedback (
                    id             INTEGER PRIMARY KEY AUTOINCREMENT,
                    url            TEXT NOT NULL,
                    norm_url       TEXT NOT NULL,
                    host           TEXT NOT NULL,
                    base_domain    TEXT NOT NULL,
                    scope          TEXT NOT NULL CHECK (scope IN ('url','host','domain')),
                    scope_key      TEXT NOT NULL,
                    verdict_given  TEXT NOT NULL,
                    correct_label  TEXT NOT NULL CHECK (correct_label IN ('benign','phishing','malware')),
                    kind           TEXT NOT NULL,
                    note           TEXT,
                    created_at     TEXT NOT NULL,
                    trained_at     TEXT
                )""")
            c.execute("CREATE INDEX IF NOT EXISTS idx_feedback_scope ON feedback(scope, scope_key)")
            c.commit()
            c.close()
            _initialised.add(path)
    c = sqlite3.connect(path)
    c.row_factory = sqlite3.Row
    try:
        yield c
        c.commit()
    finally:
        c.close()


def normalize_url(url):
    """Lowercase scheme/host, drop fragment and a bare trailing slash, add a scheme if missing."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    p = urlparse(url)
    path = p.path if p.path != "/" else ""
    return urlunparse((p.scheme.lower(), p.netloc.lower(), path, p.params, p.query, ""))


def _host(url):
    return urlparse(url).netloc.lower().split(":")[0]


def choose_scope(correct_label, host, base, is_ip, is_trusted_host, has_threat_history):
    """
    How far a correction reaches. A "safe" report must never turn a whole shared platform into a blind
    spot, so anything that could host other people's content stays narrow.
      - IP address, or a shared platform (github.io, docs.google.com, ...)     -> that exact URL
      - "this is safe" on an ordinary site                                     -> the whole registered domain
      - "this is phishing" on the main site of a big trusted domain (www.x.com) -> that exact URL, so one
                                                                                   slip can't flag a whole big site
      - "this is phishing" on any other host (google.abc.com)                  -> that host, every page on it
    """
    if is_ip or has_threat_history:
        return "url"
    if correct_label == "benign":
        return "domain"
    if is_trusted_host and host in (base, "www." + base):
        return "url"
    return "host"


def add(url, correct_label, verdict_given, scope, base_domain, note=None):
    if correct_label not in LABELS:
        raise ValueError(f"correct_label must be one of {LABELS}")
    if len(url) > MAX_URL:
        raise ValueError("URL too long")
    norm = normalize_url(url)
    host = _host(norm)
    if not host:
        raise ValueError("URL has no host")
    key = {"url": norm, "host": host, "domain": base_domain}[scope]
    if verdict_given == correct_label:
        kind = "confirmed"
    elif verdict_given != "benign" and correct_label == "benign":
        kind = "false_positive"
    elif verdict_given == "benign":
        kind = "false_negative"
    else:
        kind = "wrong_class"
    note = (note or "").strip()[:MAX_NOTE] or None
    with _conn() as c:
        # One live opinion per scope key: a newer correction replaces the older one
        c.execute("DELETE FROM feedback WHERE scope=? AND scope_key=?", (scope, key))
        cur = c.execute(
            "INSERT INTO feedback (url,norm_url,host,base_domain,scope,scope_key,verdict_given,correct_label,kind,note,created_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (url, norm, host, base_domain, scope, key, verdict_given, correct_label, kind, note,
             datetime.now(timezone.utc).isoformat(timespec="seconds")))
        row = c.execute("SELECT * FROM feedback WHERE id=?", (cur.lastrowid,)).fetchone()
    return dict(row)


def lookup(url, base_domain):
    """Most specific matching correction (url > host > domain), or None."""
    norm = normalize_url(url)
    host = _host(norm)
    with _conn() as c:
        for scope, key in (("url", norm), ("host", host), ("domain", base_domain)):
            row = c.execute("SELECT * FROM feedback WHERE scope=? AND scope_key=?", (scope, key)).fetchone()
            if row:
                return dict(row)
    return None


def list_all(limit=200):
    with _conn() as c:
        return [dict(r) for r in c.execute("SELECT * FROM feedback ORDER BY id DESC LIMIT ?", (limit,))]


def delete(feedback_id):
    with _conn() as c:
        return c.execute("DELETE FROM feedback WHERE id=?", (feedback_id,)).rowcount > 0


def count_untrained():
    with _conn() as c:
        return c.execute("SELECT COUNT(*) FROM feedback WHERE trained_at IS NULL AND kind != 'confirmed'").fetchone()[0]


def training_rows():
    """[(url, label)] for every correction worth learning from (confirmations add nothing new)."""
    with _conn() as c:
        return [(r["norm_url"], r["correct_label"]) for r in
                c.execute("SELECT norm_url, correct_label FROM feedback WHERE kind != 'confirmed'")]


def mark_trained():
    with _conn() as c:
        c.execute("UPDATE feedback SET trained_at=? WHERE trained_at IS NULL",
                  (datetime.now(timezone.utc).isoformat(timespec="seconds"),))
