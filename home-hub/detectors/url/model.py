"""The link model's numbers, and scoring with them.

train_url.py fits a logistic regression with scikit-learn, then saves only the numbers
it learned (the idf weights, the coefficients and the scaling of the numeric features)
in a small .npz file. Scoring here is a few lines of numpy, so the file works with any
scikit-learn version on the Pi, and loading it never runs pickled code.
"""
import json

import numpy as np

from .features import HASHER, NUMERIC_NAMES, numeric

N_TEXT = HASHER.n_features


class LinkModel:
    def __init__(self, idf, coef, intercept, mean, scale, meta=None):
        self.idf = np.asarray(idf, dtype=np.float64)
        self.coef = np.asarray(coef, dtype=np.float64)
        self.intercept = float(intercept)
        self.mean = np.asarray(mean, dtype=np.float64)
        self.scale = np.asarray(scale, dtype=np.float64)
        self.meta = meta or {}
        if self.idf.shape != (N_TEXT,) or self.coef.shape != (N_TEXT + len(NUMERIC_NAMES),):
            raise ValueError("link model file does not match this code's features; retrain it")

    @classmethod
    def from_sklearn(cls, clf, tfidf, scaler, meta=None):
        return cls(tfidf.idf_, clf.coef_[0], clf.intercept_[0], scaler.mean_, scaler.scale_, meta)

    def save(self, path):
        np.savez_compressed(path, idf=self.idf.astype(np.float32), coef=self.coef.astype(np.float32),
                            intercept=np.array([self.intercept]), mean=self.mean, scale=self.scale,
                            meta=np.array(json.dumps(self.meta)))

    @classmethod
    def load(cls, path):
        with np.load(path, allow_pickle=False) as z:
            return cls(z["idf"], z["coef"], z["intercept"][0], z["mean"], z["scale"], json.loads(str(z["meta"])))

    def scores(self, pairs):
        """[(domain, suffix)] -> probability of phishing for each, like the fitted model's predict_proba."""
        texts = [f"{d}.{s}" if s else d for d, s in pairs]
        x = HASHER.transform(texts).tocsr().astype(np.float64)
        # TfidfTransformer(sublinear_tf=True, norm="l2"): 1 + log(count), times idf, unit length.
        x.data = (1.0 + np.log(x.data)) * self.idf[x.indices]
        norms = np.sqrt(np.asarray(x.multiply(x).sum(axis=1)).ravel())
        norms[norms == 0] = 1.0
        text_part = np.asarray(x @ self.coef[:N_TEXT]).ravel() / norms
        num = (np.array([numeric(d, s) for d, s in pairs], dtype=np.float64) - self.mean) / self.scale
        z = text_part + num @ self.coef[N_TEXT:] + self.intercept
        return 1.0 / (1.0 + np.exp(-z))

    def score(self, domain, suffix):
        return float(self.scores([(domain, suffix)])[0])
