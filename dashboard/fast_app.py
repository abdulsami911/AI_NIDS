"""Local-first Flask web UI for actual PCAP flow inference and packet investigation.

Run through `python run_nids.py` from the AI-NIDS root.
The local web app never classifies raw packets independently of their flows.
"""
from __future__ import annotations

import csv
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import secrets
import sqlite3
import uuid
from copy import deepcopy

import numpy as np
import pandas as pd

from flask import (
    Flask, abort, flash, jsonify, redirect, render_template,
    request, send_file, session, url_for, Response,
)
from werkzeug.utils import secure_filename

from src.prediction.pcap_service import (
    ACTIVE_MODELS, MODEL_TITLES, classify_flows, resolve_model, suite_report,
)
from src.traffic.pcap_engine import IP_FEATURES, SCHEMAS, extract_pcap

ROOT = Path(__file__).resolve().parents[1]
STORAGE = ROOT / "storage"
CAPTURES = STORAGE / "captures"
DB_PATH = STORAGE / "ai_nids.sqlite3"
MAX_MB = 30

SCHEMA = """
CREATE TABLE IF NOT EXISTS captures (
    id TEXT PRIMARY KEY, filename TEXT NOT NULL, created TEXT NOT NULL,
    original_path TEXT NOT NULL, status TEXT NOT NULL,
    total_frames INTEGER DEFAULT 0, analyzed_packets INTEGER DEFAULT 0,
    unsupported_packets INTEGER DEFAULT 0, flow_count INTEGER DEFAULT 0,
    attack_count INTEGER DEFAULT 0, normal_count INTEGER DEFAULT 0,
    model_name TEXT DEFAULT '', error TEXT DEFAULT '', alert_count INTEGER, alert_threshold REAL
);
CREATE TABLE IF NOT EXISTS flows (
    capture_id TEXT NOT NULL, flow_id TEXT NOT NULL,
    src_ip TEXT, src_port TEXT, dst_ip TEXT, dst_port TEXT,
    proto TEXT, start_time TEXT, end_time TEXT, duration REAL,
    total_packets INTEGER, total_bytes INTEGER, predicted_category TEXT,
    model_score REAL, review_flag TEXT, features_json TEXT, predictions_json TEXT,
    PRIMARY KEY(capture_id, flow_id)
);
CREATE TABLE IF NOT EXISTS packets (
    capture_id TEXT NOT NULL, flow_id TEXT NOT NULL,
    frame_number INTEGER NOT NULL, timestamp TEXT NOT NULL,
    src_ip TEXT, src_port TEXT, dst_ip TEXT, dst_port TEXT,
    protocol TEXT, direction TEXT, packet_size INTEGER,
    PRIMARY KEY(capture_id, frame_number)
);
CREATE INDEX IF NOT EXISTS idx_flow_category ON flows(capture_id,predicted_category);
CREATE INDEX IF NOT EXISTS idx_packets_flow ON packets(capture_id,flow_id);
"""


def database():
    con = sqlite3.connect(DB_PATH, timeout=15)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    return con


def make_id():
    return uuid.uuid4().hex


def valid_capture_file(path: Path) -> bool:
    with path.open("rb") as f:
        prefix = f.read(4)
    return prefix in {
        b"\x0a\x0d\x0d\x0a",  # pcapng
        b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",  # classic pcap
        b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",  # nanosecond pcap
    }


def now_utc():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def register_capture(capture_id: str, filename: str, path: Path, status="processing"):
    with database() as con:
        con.execute(
            "INSERT INTO captures(id,filename,created,original_path,status) VALUES(?,?,?,?,?)",
            (capture_id, filename, now_utc(), str(path.resolve()), status),
        )


def extract_feature_csv(path: Path):
    """Read a strict UNSW-compatible flow-feature CSV; never treat it as packet data."""
    frame = pd.read_csv(path, low_memory=False)
    if frame.empty or len(frame) > 100_000:
        raise ValueError("CSV must contain between 1 and 100,000 flow rows")
    missing = set(IP_FEATURES) - set(frame.columns)
    if missing:
        raise ValueError("CSV is missing required flow features: " + ", ".join(sorted(missing)))
    frame = frame.copy()
    frame["proto"] = frame["proto"].astype(str).str.strip().str.lower()
    frame["service"] = frame["service"].fillna("-").astype(str).str.strip().str.lower().replace("", "-")
    if not frame["proto"].isin(["tcp", "udp"]).all():
        raise ValueError("CSV upload supports only TCP and UDP flow rows")
    numeric = [c for c in IP_FEATURES if c not in ("proto", "service")]
    for column in numeric:
        frame[column] = pd.to_numeric(frame[column], errors="raise")
    values = frame[numeric].to_numpy(dtype=float)
    if not np.isfinite(values).all() or (values < 0).any():
        raise ValueError("CSV flow measurements must be finite and nonnegative")
    for column in ("spkts", "dpkts", "is_sm_ips_ports"):
        if (frame[column] % 1 != 0).any():
            raise ValueError(f"CSV column {column} must contain integers")
    if not frame["is_sm_ips_ports"].isin([0, 1]).all():
        raise ValueError("CSV is_sm_ips_ports must be 0 or 1")
    flows = []
    for index, row in frame.iterrows():
        flow = {key: row[key].item() if hasattr(row[key], "item") else row[key] for key in IP_FEATURES}
        flow.update({
            "flow_id": f"FLOW-{index + 1:05d}", "src_ip": str(row.get("src_ip", "CSV")),
            "src_port": str(row.get("src_port", "")), "dst_ip": str(row.get("dst_ip", "CSV")),
            "dst_port": str(row.get("dst_port", "")), "total_packets": int(row.spkts + row.dpkts),
            "total_bytes": int(row.sbytes + row.dbytes), "start_time": str(row.get("start_time", "")),
            "end_time": str(row.get("end_time", "")),
        })
        flows.append(flow)
    return flows, [], {"total_frames": 0, "analyzed_packets": 0,
                       "unsupported_packets": 0, "flow_count": len(flows)}


def process_capture(capture_id: str, path: Path):
    """Synchronously parse, classify, then transactionally store traceable results."""
    try:
        raw_flows, packet_map, counts = (extract_feature_csv(path) if path.suffix.lower() == ".csv"
                                         else extract_pcap(path))
        model_results = {}
        model_names = {}
        for key in ACTIVE_MODELS:
            model_results[key], model_names[key] = (classify_flows(deepcopy(raw_flows), resolve_model(key))
                                                     if raw_flows else ([], MODEL_TITLES[key]))
        flows = model_results.get("ensemble", [])
        model_name = "All models: Ensemble, Random Forest, XGBoost and KNN"
        by_model = {key: {row["flow_id"]: row for row in rows} for key, rows in model_results.items()}
        attacks = sum(f["is_predicted_attack"] is True for f in flows)
        normals = sum(f["is_predicted_attack"] is False for f in flows)
        alerts = sum(f["alert_raised"] for f in flows)
        threshold = flows[0]["alert_score_threshold"] if flows else None
        with database() as con:
            con.execute("BEGIN IMMEDIATE")
            row = con.execute("SELECT status FROM captures WHERE id=?", (capture_id,)).fetchone()
            if row is None or row["status"] == "cleared":
                raise ValueError("This result has been cleared")
            con.execute("DELETE FROM packets WHERE capture_id=?", (capture_id,))
            con.execute("DELETE FROM flows WHERE capture_id=?", (capture_id,))
            con.executemany(
                """INSERT INTO flows(capture_id,flow_id,src_ip,src_port,dst_ip,dst_port,
                proto,start_time,end_time,duration,total_packets,total_bytes,predicted_category,
                model_score,review_flag,features_json,predictions_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                [(
                    capture_id, f["flow_id"], f["src_ip"], f["src_port"],
                    f["dst_ip"], f["dst_port"], f["proto"], f["start_time"],
                    f["end_time"], f["dur"], f["total_packets"], f["total_bytes"],
                    f["predicted_category"], f["model_score"], f["review_flag"],
                    json.dumps({k: f[k] for k in SCHEMAS[f["feature_schema"]]}, allow_nan=False),
                    json.dumps({key: {field: by_model[key][f["flow_id"]][field]
                                     for field in ("predicted_category", "model_score", "review_flag", "alert_raised")}
                                for key in ACTIVE_MODELS}, allow_nan=False),
                ) for f in flows],
            )
            con.executemany(
                """INSERT INTO packets(capture_id,flow_id,frame_number,timestamp,src_ip,
                src_port,dst_ip,dst_port,protocol,direction,packet_size)
                VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                [(
                    capture_id, p["flow_id"], p["frame_number"], p["timestamp"],
                    p["src_ip"], p["src_port"], p["dst_ip"], p["dst_port"],
                    p["protocol"], p["direction"], p["packet_size"],
                ) for p in packet_map],
            )
            con.execute(
                """UPDATE captures SET status='complete',total_frames=?,analyzed_packets=?,
                unsupported_packets=?,flow_count=?,attack_count=?,normal_count=?,model_name=?,error='',
                alert_count=?,alert_threshold=?
                WHERE id=?""",
                (counts["total_frames"], counts["analyzed_packets"],
                 counts["unsupported_packets"], counts["flow_count"], attacks,
                 normals, model_name, alerts, threshold, capture_id),
            )
    except Exception as exc:
        with database() as con:
            con.execute("UPDATE captures SET status='failed',error=? WHERE id=? AND status IN ('processing','recording')",
                        (str(exc)[:1200], capture_id))
        raise


def capture_or_404(capture_id):
    with database() as con:
        capture = con.execute("SELECT * FROM captures WHERE id=?", (capture_id,)).fetchone()
    if capture is None:
        abort(404)
    return capture


def model_view(row, model):
    """Overlay one saved model result on a stored flow row."""
    item = dict(row)
    saved = json.loads(item.get("predictions_json") or "{}")
    result = saved.get(model)
    if result:
        item.update(predicted_category=result["predicted_category"], model_score=result["model_score"],
                    review_flag=result["review_flag"], alert_raised=bool(result["alert_raised"]))
    else:
        item["alert_raised"] = item.get("review_flag") == "Alert"
    return item


def create_app():
    CAPTURES.mkdir(parents=True, exist_ok=True)
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with database() as con:
        con.executescript(SCHEMA)
        con.execute("BEGIN IMMEDIATE")
        cols = {row["name"] for row in con.execute("PRAGMA table_info(captures)")}
        for column, type_name in (("alert_count", "INTEGER"), ("alert_threshold", "REAL")):
            if column not in cols:
                con.execute(f"ALTER TABLE captures ADD COLUMN {column} {type_name}")
        flow_cols = {r["name"] for r in con.execute("PRAGMA table_info(flows)")}
        if "features_json" not in flow_cols:
            con.execute("ALTER TABLE flows ADD COLUMN features_json TEXT")
        if "predictions_json" not in flow_cols:
            con.execute("ALTER TABLE flows ADD COLUMN predictions_json TEXT")
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.secret_key = os.environ.get("AI_NIDS_SECRET", secrets.token_hex(32))
    app.config.update(MAX_CONTENT_LENGTH=MAX_MB * 1024 * 1024, SESSION_COOKIE_SAMESITE="Lax",
                      SESSION_COOKIE_HTTPONLY=True)

    @app.before_request
    def csrf_check():
        if "csrf" not in session:
            session["csrf"] = secrets.token_hex(24)
        if request.method == "POST" and not secrets.compare_digest(
            request.form.get("csrf_token", ""), session["csrf"]
        ):
            abort(403)

    def model_available():
        try:
            return resolve_model().is_file()
        except (FileNotFoundError, ValueError):
            return False

    @app.context_processor
    def template_defaults():
        return {"csrf_token": session.get("csrf", ""), "model_available": model_available()}

    @app.route("/")
    def home():
        with database() as con:
            latest = con.execute("""SELECT * FROM captures WHERE status!='cleared'
                                  ORDER BY created DESC, rowid DESC LIMIT 15""").fetchall()
            stats = con.execute("""SELECT COUNT(*) AS captures,
                COUNT(CASE WHEN status IN ('complete','failed') THEN 1 END) AS clearable,
                MAX(CASE WHEN status IN ('complete','failed') THEN rowid END) AS clear_through,
                COALESCE(SUM(CASE WHEN status='complete' THEN flow_count ELSE 0 END),0) AS flows,
                COALESCE(SUM(CASE WHEN status='complete' THEN analyzed_packets ELSE 0 END),0) AS packets,
                COALESCE(SUM(CASE WHEN status='complete' THEN coalesce(alert_count,attack_count) ELSE 0 END),0) AS attacks
                FROM captures WHERE status!='cleared'""").fetchone()
            categories = con.execute("""SELECT predicted_category,COUNT(*) AS n
                FROM flows GROUP BY predicted_category ORDER BY n DESC""").fetchall()
        return render_template("overview.html", latest=latest, stats=stats, categories=categories,
                               suite=suite_report(), titles=MODEL_TITLES)

    @app.post("/results/clear")
    @app.post("/captures/<capture_id>/clear")
    def clear_results(capture_id=None):
        if request.form.get("confirm") != "clear":
            abort(400, "Confirm which results to clear.")
        with database() as con:
            con.execute("BEGIN IMMEDIATE")
            if capture_id is None:
                through = request.form.get("through", type=int)
                if through is None:
                    abort(400, "Reload the overview before clearing results.")
                targets = con.execute("""SELECT id FROM captures WHERE rowid <= ?
                                      AND status IN ('complete','failed')""", (through,)).fetchall()
            else:
                row = con.execute("SELECT id,status FROM captures WHERE id=?", (capture_id,)).fetchone()
                if row is None:
                    abort(404)
                if row["status"] in ("recording", "processing"):
                    abort(409, "Wait for recording or processing to finish.")
                targets = [row] if row["status"] != "cleared" else []
            ids = [(r["id"],) for r in targets]
            con.executemany("DELETE FROM packets WHERE capture_id=?", ids)
            con.executemany("DELETE FROM flows WHERE capture_id=?", ids)
            con.executemany("""UPDATE captures SET status='cleared',total_frames=0,analyzed_packets=0,
                            unsupported_packets=0,flow_count=0,attack_count=0,normal_count=0,
                            alert_count=0,alert_threshold=NULL,model_name='',error='' WHERE id=?""", ids)
        flash(f"Cleared {len(ids)} saved result(s). You can upload a new capture.", "success")
        return redirect(url_for("home"))

    @app.route("/upload", methods=["POST"])
    def upload():
        file = request.files.get("capture")
        if file is None or not file.filename:
            flash("Select a PCAP or PCAPNG file first.", "error")
            return redirect(url_for("home"))
        name = secure_filename(file.filename)
        suffix = Path(name).suffix.lower()
        if suffix not in (".pcap", ".pcapng", ".csv"):
            flash("Only .pcap, .pcapng and compatible flow-feature .csv files are supported.", "error")
            return redirect(url_for("home"))
        capture_id = make_id()
        folder = CAPTURES / capture_id
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / ("capture" + suffix)
        file.save(path)
        if suffix != ".csv" and not valid_capture_file(path):
            path.unlink(missing_ok=True)
            flash("Not a valid PCAP/PCAPNG header.", "error")
            return redirect(url_for("home"))
        register_capture(capture_id, name, path)
        try:
            process_capture(capture_id, path)
            flash("File analyzed with Random Forest, XGBoost, KNN and the ensemble.", "success")
        except Exception as exc:
            flash("Analysis failed: " + str(exc)[:250], "error")
        return redirect(url_for("capture_page", capture_id=capture_id))

    @app.route("/captures/<capture_id>")
    def capture_page(capture_id):
        capture = capture_or_404(capture_id)
        selected_model = request.args.get("model", "ensemble")
        if selected_model not in ACTIVE_MODELS:
            abort(400, "Unknown capture model")
        category = request.args.get("category", "")
        page = max(1, min(request.args.get("page", default=1, type=int), 999999))
        page_size = 60
        with database() as con:
            all_flows = [model_view(row, selected_model) for row in con.execute(
                "SELECT * FROM flows WHERE capture_id=?", (capture_id,)).fetchall()]
        from collections import Counter
        category_counts = Counter(row["predicted_category"] for row in all_flows)
        categories = [{"predicted_category": key, "n": value}
                      for key, value in category_counts.most_common()]
        reason_counts = Counter(row["review_flag"] for row in all_flows
                                if row["predicted_category"] == "Unassessed")
        coverage_reasons = [{"review_flag": key, "n": value} for key, value in reason_counts.most_common()]
        provisional_normal = sum(row["predicted_category"] == "Unassessed" and
                                 "ensemble lead Normal at" in row["review_flag"] for row in all_flows)
        model_counts = {
            "normal": category_counts["Normal"],
            "attack": sum(row["predicted_category"] not in ("Normal", "Unassessed") for row in all_flows),
            "alerts": sum(row["alert_raised"] for row in all_flows),
            "unassessed": category_counts["Unassessed"],
        }
        filtered = [row for row in all_flows if not category or row["predicted_category"] == category]
        filtered.sort(key=lambda row: (
            0 if row["alert_raised"] else 1 if row["predicted_category"] not in ("Normal", "Unassessed")
            else 2 if row["predicted_category"] == "Unassessed" else 3,
            -(row["model_score"] or 0) if row["predicted_category"] == "Unassessed" else 0,
            row["flow_id"],
        ))
        count = len(filtered)
        flows = filtered[(page - 1) * page_size:page * page_size]
        return render_template("capture.html", capture=capture, flows=flows, model_counts=model_counts,
                               unassessed=model_counts["unassessed"], selected_model=selected_model,
                               model_options=ACTIVE_MODELS, titles=MODEL_TITLES,
                               provisional_normal=provisional_normal, categories=categories,
                               coverage_reasons=coverage_reasons, selected=category, page=page,
                               pages=max(1, (count + page_size - 1) // page_size), count=count)

    @app.route("/captures/<capture_id>/flows/<flow_id>")
    def flow_page(capture_id, flow_id):
        capture = capture_or_404(capture_id)
        selected_model = request.args.get("model", "ensemble")
        if selected_model not in ACTIVE_MODELS:
            abort(400, "Unknown capture model")
        with database() as con:
            flow = con.execute("SELECT * FROM flows WHERE capture_id=? AND flow_id=?",
                               (capture_id, flow_id)).fetchone()
            if flow is None:
                abort(404)
            total_packets = con.execute("SELECT COUNT(*) FROM packets WHERE capture_id=? AND flow_id=?",
                                        (capture_id, flow_id)).fetchone()[0]
            packets = con.execute("""SELECT * FROM packets WHERE capture_id=? AND flow_id=?
                ORDER BY frame_number LIMIT 3000""", (capture_id, flow_id)).fetchall()
        flow = model_view(flow, selected_model)
        return render_template("flow.html", capture=capture, flow=flow, packets=packets,
                               selected_model=selected_model, model_options=ACTIVE_MODELS, titles=MODEL_TITLES,
                               total_packets=total_packets, measurements=json.loads(flow["features_json"] or "{}"))

    @app.route("/captures/<capture_id>/download")
    def download_capture(capture_id):
        capture = capture_or_404(capture_id)
        path = Path(capture["original_path"])
        if not path.exists():
            abort(404)
        return send_file(path, as_attachment=True, download_name=capture["filename"])

    @app.route("/captures/<capture_id>/export.csv")
    def export_csv(capture_id):
        capture = capture_or_404(capture_id)
        selected_model = request.args.get("model", "ensemble")
        if selected_model not in ACTIVE_MODELS:
            abort(400, "Unknown capture model")
        if capture["status"] == "cleared":
            abort(410, "The flow results have been cleared.")
        output = io.StringIO()
        writer = csv.writer(output)
        fields = ["flow_id", "src_ip", "src_port", "dst_ip", "dst_port", "proto",
                  "duration", "total_packets", "total_bytes", "predicted_category", "model_score", "review_flag"]
        measures = [k for k in IP_FEATURES if k not in ("proto", "dur")]
        writer.writerow([*fields, "alert_raised", "alert_score_threshold", "model_name", *measures])
        with database() as con:
            cursor = con.execute("SELECT " + ",".join(fields) + ",features_json,predictions_json FROM flows WHERE capture_id=?",
                                 (capture_id,))  # Fields are fixed developer-authored identifiers.
            for row in cursor:
                row = model_view(row, selected_model)
                raised = row["alert_raised"]
                values = json.loads(row["features_json"] or "{}")
                writer.writerow([*(row[field] for field in fields), raised, capture["alert_threshold"],
                                 MODEL_TITLES[selected_model], *(values.get(k) for k in measures)])
        return Response(output.getvalue(), mimetype="text/csv", headers={
            "Content-Disposition": f"attachment; filename=AI-NIDS-{capture_id[:8]}.csv"
        })

    @app.route("/models")
    def models():
        secondary = ROOT / "reports/evaluation/nsl_kdd_suite.json"
        external_file = ROOT / "reports/evaluation/external_pcap_checks.json"
        external = json.loads(external_file.read_text()) if external_file.is_file() else None
        nsl = json.loads(secondary.read_text()) if secondary.is_file() else {}
        suite = suite_report()
        full = [json.loads(path.read_text()) for path in sorted((ROOT / "artifacts/registry/full").glob("*.json"))]
        algorithm = request.args.get("algorithm", suite.get("selected_model", "xgboost"))
        benchmark = request.args.get("benchmark", "capture")
        if algorithm not in MODEL_TITLES or benchmark not in ("capture", "full", "nsl"):
            abort(400, "Unknown benchmark or algorithm.")
        capture_record = suite.get("models", {}).get(algorithm, {})
        if benchmark == "capture":
            detail, classes = capture_record.get("test", {}), suite.get("classes", [])
        elif benchmark == "nsl":
            detail, classes = nsl.get("models", {}).get(algorithm, {}), nsl.get("classes", [])
        else:
            record = next((r for r in full if r["name"] == algorithm), {})
            detail, classes = record.get("metrics", {}), record.get("classes", [])
        with database() as con:
            page = max(1, request.args.get("page", default=1, type=int))
            count = con.execute("SELECT COUNT(*) FROM captures WHERE status='complete'").fetchone()[0]
            pages = max(1, (count + 19) // 20)
            page = min(page, pages)
            captures = con.execute("""SELECT * FROM captures WHERE status='complete'
                                    ORDER BY created DESC,rowid DESC LIMIT 20 OFFSET ?""", ((page-1)*20,)).fetchall()
        return render_template("models.html", suite=suite, titles=MODEL_TITLES, full=full, secondary=nsl,
                               external=external, captures=captures, page=page, pages=pages,
                               algorithm=algorithm, benchmark=benchmark, detail=detail, classes=classes,
                               capture_record=capture_record)

    @app.route("/api/health")
    def health():
        ready = model_available()
        return jsonify({"service": "AI-NIDS", "model_available": ready,
                        "status": "ready" if ready else "model_missing"})

    @app.errorhandler(413)
    def too_large(exc):
        flash(f"Capture exceeds the {MAX_MB} MB upload limit.", "error")
        return redirect(url_for("home"))

    return app
