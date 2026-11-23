import json
from pathlib import Path

from dashboard import fast_app


ROOT = Path(__file__).resolve().parents[1]


def test_live_capture_feature_is_not_exposed():
    app = fast_app.create_app()
    client = app.test_client()
    assert client.get("/live").status_code == 404
    assert not any(rule.rule.startswith("/live") for rule in app.url_map.iter_rules())


def test_capture_release_uses_only_unsw_csv_splits():
    report = json.loads((ROOT / "reports/evaluation/pcap_suite.json").read_text())
    assert set(report["files_sha256"]) == {
        "UNSW_NB15_training-set.csv",
        "UNSW_NB15_testing-set.csv",
    }
    assert set(report["models"]) == {"random_forest", "xgboost", "knn", "ensemble"}
    for name in ("random_forest", "xgboost", "knn", "ensemble"):
        artifact = ROOT / "artifacts/models" / report["models"][name]["artifact"]
        assert artifact.is_file()
