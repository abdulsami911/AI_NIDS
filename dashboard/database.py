import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path

BASE_SETTINGS = {"pcap_model": "auto", "full_model": "auto", "interface": "", "idle": 30,
                 "upload_mb": 32, "retention_days": 30, "alerts": True,
                 "severity": {"Analysis": "Medium", "Backdoor": "High", "DoS": "High",
                              "Exploits": "High", "Fuzzers": "Medium", "Generic": "Medium",
                              "Reconnaissance": "Medium", "Shellcode": "High", "Worms": "High"}}
DDL = """
CREATE TABLE IF NOT EXISTS captures(
 id TEXT PRIMARY KEY, name TEXT NOT NULL, suffix TEXT NOT NULL, bytes INTEGER NOT NULL,
 created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, origin TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS runs(
 id INTEGER PRIMARY KEY, capture TEXT NOT NULL REFERENCES captures ON DELETE CASCADE,
 family TEXT NOT NULL, model TEXT NOT NULL, version TEXT NOT NULL, schema TEXT NOT NULL,
 idle INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'Queued', stage TEXT NOT NULL DEFAULT 'Waiting',
 message TEXT NOT NULL DEFAULT '', created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 frames INTEGER, mapped INTEGER, nflows INTEGER, skipped TEXT DEFAULT '{}', cancelled INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS flows(
 id INTEGER PRIMARY KEY, run INTEGER NOT NULL REFERENCES runs ON DELETE CASCADE, row_no INTEGER NOT NULL,
 first_ns INTEGER, last_ns INTEGER, src TEXT, dst TEXT, sport INTEGER, dport INTEGER,
 proto TEXT NOT NULL, dur REAL, packets INTEGER, bytes INTEGER, category TEXT, score REAL,
 severity TEXT, reason TEXT, stats TEXT NOT NULL, UNIQUE(run,row_no));
CREATE TABLE IF NOT EXISTS packets(
 flow INTEGER NOT NULL REFERENCES flows ON DELETE CASCADE, frame INTEGER NOT NULL,
 ns INTEGER NOT NULL, src TEXT NOT NULL, dst TEXT NOT NULL, sport INTEGER, dport INTEGER,
 proto TEXT NOT NULL, length INTEGER NOT NULL, forward INTEGER NOT NULL, flags INTEGER,
 PRIMARY KEY(flow,frame));
CREATE TABLE IF NOT EXISTS alerts(
 id INTEGER PRIMARY KEY, flow INTEGER NOT NULL UNIQUE REFERENCES flows ON DELETE CASCADE,
 status TEXT NOT NULL DEFAULT 'New');
CREATE TABLE IF NOT EXISTS notes(
 id INTEGER PRIMARY KEY, alert INTEGER NOT NULL REFERENCES alerts ON DELETE CASCADE,
 created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS flow_category ON flows(category,run);
CREATE INDEX IF NOT EXISTS flow_time ON flows(first_ns);
CREATE INDEX IF NOT EXISTS run_capture ON runs(capture,status,id);
CREATE VIEW IF NOT EXISTS latest AS
 SELECT r.* FROM runs r JOIN (SELECT capture, MAX(id) AS id FROM runs
 WHERE status='Completed' GROUP BY capture) x ON r.id=x.id;
"""


class Store:
    def __init__(self, folder):
        self.folder = Path(folder).resolve()
        self.captures = self.folder / "captures"
        self.captures.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.path = self.folder / "analysis.sqlite3"
        with self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript(DDL)
            db.execute("UPDATE runs SET status='Interrupted', stage='Server restarted' WHERE status IN ('Queued','Processing')")

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=30)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        try:
            with db:
                yield db
        finally:
            db.close()

    def all(self, sql, args=()):
        with self.connect() as db:
            return [dict(r) for r in db.execute(sql, args)]

    def one(self, sql, args=()):
        rows = self.all(sql, args)
        return rows[0] if rows else None

    def settings(self):
        return {**BASE_SETTINGS, **{r["key"]: json.loads(r["value"]) for r in self.all("SELECT * FROM settings")}}

    def file(self, capture):
        return self.captures / (capture["id"] + capture["suffix"])
