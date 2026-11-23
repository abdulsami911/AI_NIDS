"""Serializable probability ensemble used by capture training and inference."""
import numpy as np


class AverageProbabilityEnsemble:
    """Serializable weighted-probability ensemble with an sklearn-like interface."""

    def __init__(self, pipelines, weights=None):
        self.pipelines = pipelines
        class_sets = [tuple(p.named_steps["classifier"].classes_) for p in pipelines.values()]
        if not class_sets or len(set(class_sets)) != 1:
            raise ValueError("Ensemble members must use the same encoded classes")
        self.classes_ = np.asarray(class_sets[0])
        supplied = weights or {name: 1.0 for name in pipelines}
        if set(supplied) != set(pipelines) or any(float(value) <= 0 for value in supplied.values()):
            raise ValueError("Ensemble weights must be positive and match the member names")
        total = sum(float(value) for value in supplied.values())
        self.weights = {name: float(supplied[name]) / total for name in pipelines}

    @property
    def named_steps(self):
        return {"classifier": self}

    def predict_proba(self, frame):
        weights = getattr(self, "weights", None) or {
            name: 1.0 / len(self.pipelines) for name in self.pipelines
        }
        return sum(weights[name] * member.predict_proba(frame)
                   for name, member in self.pipelines.items())
