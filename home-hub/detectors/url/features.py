"""What the link model sees: only the registered domain, the part someone buys (for
example "hdfcbank.com" or "sbi-kyc-update.xyz"), never the path or the subdomain.
"""
import math
from collections import Counter

import numpy as np
from scipy import sparse
from sklearn.feature_extraction.text import HashingVectorizer

VOWELS = set("aeiou")
NUMERIC_NAMES = ["length", "digit_ratio", "hyphens", "entropy", "vowel_ratio", "consonant_run", "suffix_parts"]

# Character pieces of 2 to 5 letters, hashed into a fixed-size table: small and needs no
# vocabulary in memory, which matters on the Pi.
HASHER = HashingVectorizer(analyzer="char_wb", ngram_range=(2, 5), n_features=2 ** 18,
                           alternate_sign=False, norm=None, lowercase=True)


def numeric(domain: str, suffix: str) -> list:
    d = domain.lower()
    n = len(d) or 1
    letters = [c for c in d if c.isalpha()]
    counts = Counter(d)
    entropy = -sum(k / n * math.log2(k / n) for k in counts.values()) if d else 0.0
    run = best = 0
    for c in d:
        run = run + 1 if (c.isalpha() and c not in VOWELS) else 0
        best = max(best, run)
    return [len(d), sum(c.isdigit() for c in d) / n, d.count("-"), entropy,
            (sum(c in VOWELS for c in letters) / len(letters)) if letters else 0.0, best,
            suffix.count(".") + 1 if suffix else 0]


def matrix(pairs, tfidf, scaler):
    """pairs: [(domain, suffix)] -> features for the model (fitted tfidf and scaler)."""
    texts = [f"{d}.{s}" if s else d for d, s in pairs]
    x_text = tfidf.transform(HASHER.transform(texts))
    x_num = scaler.transform(np.array([numeric(d, s) for d, s in pairs], dtype=float))
    return sparse.hstack([x_text, sparse.csr_matrix(x_num)]).tocsr()
