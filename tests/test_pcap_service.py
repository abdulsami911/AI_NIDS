import joblib
import pytest
from sklearn.preprocessing import LabelEncoder

from src.prediction.pcap_service import classify_flows
from src.traffic.pcap_engine import LEGACY_FEATURES


class DummyPipeline:
    def predict_proba(self, frame):
        assert list(frame.columns) == list(LEGACY_FEATURES)
        return [[0.8, 0.2] for _ in range(len(frame))]

    @property
    def named_steps(self):
        return {"classifier": DummyClassifier()}


class DummyClassifier:
    classes_ = [0, 1]


def test_model_prediction_marks_flow_not_frames(tmp_path):
    le = LabelEncoder().fit(['DoS','Normal'])
    path = tmp_path / 'artifact.joblib'
    joblib.dump({'pipeline': DummyPipeline(), 'label_encoder': le,
                 'features': list(LEGACY_FEATURES), 'feature_schema':'pcap_7f_v1',
                 'model_name':'TEST'}, path)
    flow = {'flow_id':'FLOW-00001','proto':'udp','dur':0.1,
            'spkts':1,'dpkts':1,'sinpkt':0,'dinpkt':0,'is_sm_ips_ports':0}
    output,name = classify_flows([flow], path)
    assert name=='TEST'
    assert output[0]['predicted_category']=='DoS'
    assert output[0]['is_predicted_attack'] is True
    assert output[0]['model_score'] == 0.8
    assert 'frame_number' not in output[0]


def test_incompatible_model_is_blocked(tmp_path):
    path=tmp_path/'bad.joblib'
    joblib.dump({'pipeline': DummyPipeline(), 'label_encoder':None,
                 'features':['proto','dur'], 'feature_schema':'other'},path)
    with pytest.raises(ValueError, match='schema mismatch'):
        classify_flows([{'proto':'udp'}],path)


def test_absent_coverage_and_threshold_ties_never_raise_an_alert(tmp_path):
    encoder = LabelEncoder().fit(["DoS", "Normal"])
    path = tmp_path / "model.joblib"
    joblib.dump({"pipeline": DummyPipeline(), "label_encoder": encoder,
                 "features": list(LEGACY_FEATURES), "feature_schema": "pcap_7f_v1",
                 "training_coverage": {("tcp", "*", 1, 1)}, "alert_score_threshold": 0.8}, path)
    f = dict(proto="tcp", spkts=1, dpkts=1, dur=0.02, sinpkt=0, dinpkt=0, is_sm_ips_ports=0)
    results, _ = classify_flows([dict(f, proto="udp"), f], path)
    assert results[0]["predicted_category"] == "Unassessed"
    assert results[0]["model_score"] == 0.8 and results[0]["is_predicted_attack"] is None
    assert "Triage suggestion only" in results[0]["review_flag"]
    assert results[0]["alert_raised"] is False
    assert results[1]["predicted_category"] == "DoS"
    assert results[1]["is_predicted_attack"] and not results[1]["alert_raised"]


def test_normal_margin_only_recovers_close_second_and_respects_coverage(tmp_path):
    enc = LabelEncoder().fit(["DoS", "Normal"])
    path = tmp_path / "margin.joblib"
    joblib.dump({"pipeline": DummyPipeline(), "label_encoder": enc, "features": list(LEGACY_FEATURES),
                 "feature_schema": "pcap_7f_v1", "normal_runner_up_margin": 0.61,
                 "training_coverage": {("tcp", "*", 1, 1)}}, path)
    f = dict(proto="tcp", spkts=1, dpkts=1, dur=0.02, sinpkt=0, dinpkt=0, is_sm_ips_ports=0)
    rows, _ = classify_flows([f, dict(f, proto="udp")], path)
    assert (rows[0]["predicted_category"], rows[0]["model_score"], rows[0]["alert_raised"]) == ("Normal", .2, False)
    assert rows[1]["predicted_category"] == "Unassessed" and rows[1]["model_score"] == .2
    assert rows[1]["is_predicted_attack"] is None and not rows[1]["alert_raised"]


def test_validation_normal_margin_respects_attack_recall_budget_and_ties():
    import numpy as np
    from src.models.train_pcap_suite import fit_normal_margin
    from src.prediction.pcap_service import decision_positions
    probs = np.array([[.51, .49]] + [[.6, .4]] * 99 + [[.52, .48], [.6, .4]])
    is_attack = np.array([True] * 100 + [False] * 2)
    margin = fit_normal_margin(probs, 1, is_attack)
    predicted = decision_positions(probs, 1, margin)
    assert (predicted[is_attack] == 1).sum() == 1
    assert (predicted[~is_attack] == 1).sum() == 1
    assert decision_positions(np.array([[.4, .35, .25]]), 2, 1.0)[0] == 0
