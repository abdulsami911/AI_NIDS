"""Exercise the actual upload, sqlite counters, packet investigation and CSV export."""
import csv
import io
import json
import shutil
import struct

import pytest
from dashboard import fast_app


def arp_capture():
    # A classic little-endian PCAP with one Ethernet ARP request.
    payload = bytes.fromhex("ffffffffffff00112233445508060001080006040001001122334455"
                            "c0000201000000000000c0000202")
    return (bytes.fromhex("d4c3b2a1") + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
            + struct.pack("<IIII", 1, 0, len(payload), len(payload)) + payload)


@pytest.mark.skipif(shutil.which("tshark") is None, reason="TShark is needed to dissect a capture")
def test_unsupported_capture_retains_observed_frame_count(tmp_path, monkeypatch):
    monkeypatch.setattr(fast_app, "DB_PATH", tmp_path / "analysis.sqlite")
    monkeypatch.setattr(fast_app, "CAPTURES", tmp_path / "captures")
    client = fast_app.create_app().test_client()
    client.get("/")
    with client.session_transaction() as session:
        token = session["csrf"]
    response = client.post("/upload", data={"csrf_token": token, "capture": (io.BytesIO(arp_capture()), "arp.pcap")},
                           follow_redirects=True)
    assert response.status_code == 200
    with fast_app.database() as con:
        record = con.execute("SELECT * FROM captures").fetchone()
    assert record["status"] == "complete"
    assert (record["total_frames"], record["unsupported_packets"], record["flow_count"]) == (1, 1, 0)
    assert (record["attack_count"], record["normal_count"], record["alert_count"]) == (0, 0, 0)


@pytest.mark.skipif(shutil.which("tshark") is None, reason="TShark is needed to dissect a capture")
def test_upload_matches_frozen_model_and_original_frames(tmp_path, monkeypatch):
    from src.prediction.pcap_service import suite_report
    from src.traffic.pcap_engine import extract_pcap

    sample = fast_app.ROOT / "datasets/pcap_samples/firsttime.pcapng"
    if not sample.is_file() or not suite_report():
        pytest.skip("Requires the local training release and sample capture")
    monkeypatch.setattr(fast_app, "DB_PATH", tmp_path / "analysis.sqlite")
    monkeypatch.setattr(fast_app, "CAPTURES", tmp_path / "captures")
    client = fast_app.create_app().test_client()
    assert client.get("/models").status_code == 200
    client.get("/")
    with client.session_transaction() as session:
        token = session["csrf"]
    with sample.open("rb") as f:
        resp = client.post("/upload", data={"csrf_token": token, "capture": (f, sample.name)})
    assert resp.status_code == 302
    detail = resp.headers["Location"]
    assert client.get(detail).status_code == 200
    rows = list(csv.DictReader(io.StringIO(client.get(detail + "/export.csv").get_data(as_text=True))))
    flows, frames, counts = extract_pcap(sample)
    expected, name = fast_app.classify_flows(flows)
    assert {r["flow_id"]: r["predicted_category"] for r in rows} == {
        f["flow_id"]: f["predicted_category"] for f in expected}
    assert all(r["model_name"] == fast_app.MODEL_TITLES["ensemble"] for r in rows)
    capture = detail.split("/")[-1]
    with fast_app.database() as con:
        stored = con.execute("SELECT * FROM captures WHERE id=?", (capture,)).fetchone()
        indexed = con.execute("SELECT frame_number,flow_id FROM packets ORDER BY frame_number").fetchall()
        saved_predictions = json.loads(con.execute(
            "SELECT predictions_json FROM flows WHERE capture_id=? LIMIT 1", (capture,)).fetchone()[0])
    assert set(saved_predictions) == set(fast_app.ACTIVE_MODELS)
    for model in fast_app.ACTIVE_MODELS:
        assert client.get(detail + "?model=" + model).status_code == 200
    assert stored["total_frames"] == counts["total_frames"]
    assert stored["normal_count"] == sum(f["predicted_category"] == "Normal" for f in expected)
    assert stored["alert_count"] == sum(f["alert_raised"] for f in expected)
    assert [tuple(r) for r in indexed] == [(f["frame_number"], f["flow_id"]) for f in frames]
    for flow_id in {f["flow_id"] for f in expected}:
        assert client.get(detail + "/flows/" + flow_id).status_code == 200


def test_compatible_csv_runs_every_model_and_rejects_other_files(tmp_path, monkeypatch):
    monkeypatch.setattr(fast_app, "DB_PATH", tmp_path / "csv.sqlite")
    monkeypatch.setattr(fast_app, "CAPTURES", tmp_path / "captures")
    client = fast_app.create_app().test_client()
    client.get("/")
    with client.session_transaction() as session:
        token = session["csrf"]
    data = ("proto,dur,spkts,dpkts,sinpkt,dinpkt,is_sm_ips_ports,service,sbytes,dbytes\n"
            "tcp,0.2,4,3,20,30,0,http,400,500\n")
    response = client.post("/upload", data={"csrf_token": token,
        "capture": (io.BytesIO(data.encode()), "flows.csv")})
    assert response.status_code == 302
    detail = response.headers["Location"]
    assert b"Compare model results" in client.get(detail).data
    with fast_app.database() as con:
        row = con.execute("SELECT predictions_json FROM flows").fetchone()
    assert set(json.loads(row[0])) == set(fast_app.ACTIVE_MODELS)
    bad = client.post("/upload", data={"csrf_token": token,
        "capture": (io.BytesIO(b"hello"), "notes.txt")}, follow_redirects=True)
    assert b"Only .pcap, .pcapng and compatible flow-feature .csv" in bad.data


def test_clear_and_restart_preserves_captures_and_active_jobs(tmp_path, monkeypatch):
    import json

    monkeypatch.setattr(fast_app, "DB_PATH", tmp_path / "history.sqlite")
    monkeypatch.setattr(fast_app, "CAPTURES", tmp_path / "captures")
    client = fast_app.create_app().test_client()
    assert client.get("/").status_code == 200
    with client.session_transaction() as session:
        token = session["csrf"]
    form = {"csrf_token": token, "confirm": "clear"}

    def add(cid, status):
        path = tmp_path / f"{cid}.pcap"
        path.write_bytes(arp_capture())
        fast_app.register_capture(cid, path.name, path, status)
        if status == "complete":
            with fast_app.database() as con:
                con.execute("UPDATE captures SET flow_count=1,normal_count=1,model_name='Prior run' WHERE id=?", (cid,))
                con.execute("INSERT INTO flows(capture_id,flow_id,predicted_category,features_json) VALUES(?,?,?,?)",
                            (cid, "F1", "Normal", json.dumps({"proto": "tcp"})))
                con.execute("INSERT INTO packets(capture_id,flow_id,frame_number,timestamp) VALUES(?,?,?,?)", (cid, "F1", 1, "0"))
        return path

    saved = add("first", "complete")
    add("second", "complete")
    add("active", "recording")
    assert client.get("/captures/first/clear").status_code == 405
    assert client.post("/captures/first/clear", data={"confirm": "clear"}).status_code == 403
    assert client.post("/captures/first/clear", data={"csrf_token": token}).status_code == 400
    assert client.post("/captures/active/clear", data=form).status_code == 409
    assert client.post("/captures/first/clear", data=form).status_code == 302
    assert saved.read_bytes() == arp_capture()
    assert client.get("/captures/first/export.csv").status_code == 410
    assert client.get("/captures/first/flows/F1").status_code == 404
    assert client.get("/captures/first/download").data == arp_capture()
    assert b"Prior run" in client.get("/models").data
    with fast_app.database() as con:
        assert con.execute("SELECT count(*) FROM packets").fetchone()[0] == 1
        through = con.execute("SELECT max(rowid) FROM captures").fetchone()[0]
    add("later", "complete")
    client.post("/results/clear", data={**form, "through": through})
    with fast_app.database() as con:
        assert dict(con.execute("SELECT id,status FROM captures")) == {
            "first": "cleared", "second": "cleared", "active": "recording", "later": "complete"}
    assert b"second.pcap" not in client.get("/models").data
    assert b"later.pcap" in client.get("/").data
    assert b"first.pcap" not in client.get("/").data


@pytest.mark.parametrize("scope", ["full", "capture", "nsl"])
def test_model_analytics_shows_selected_benchmark(tmp_path, monkeypatch, scope):
    monkeypatch.setattr(fast_app, "DB_PATH", tmp_path / "results.sqlite")
    monkeypatch.setattr(fast_app, "CAPTURES", tmp_path / "caps")
    client = fast_app.create_app().test_client()
    r = client.get(f"/models?benchmark={scope}&algorithm=knn")
    assert r.status_code == 200
    if b"No evaluation report" not in r.data:
        assert b"Confusion matrix" in r.data and b"K-Nearest Neighbors" in r.data
        expected = b"KDDTest+.txt" if scope == "nsl" else b"UNSW_NB15_testing-set.csv"
        assert expected in r.data
    assert client.get("/models?benchmark=invalid").status_code == 400
