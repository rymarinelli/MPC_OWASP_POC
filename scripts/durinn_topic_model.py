# durinn_topic_model.py
"""
Real topic modeling pipeline for vulnerability records.

Steps:
1. Build a text representation of each vulnerability (rule_id + snippet)
2. Encode using sentence-transformers
3. Dimensionality reduction (optional)
4. Clustering (HDBSCAN)
5. LLM cluster labeling (optional but recommended)
"""

from typing import Dict, List
import numpy as np
from sentence_transformers import SentenceTransformer
import hdbscan
import umap
import hashlib
import json
import os
import time
import openai   # or use your internal LLM call

# --------------------------------------
# CONFIG
# --------------------------------------
EMBED_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
USE_UMAP = False     # set True if you want cleaner clusters
CLUSTER_MIN_SIZE = 2
LLM_MODEL = "gpt-4o-mini"  # or local model


# --------------------------------------
# GLOBAL MODEL (cached)
# --------------------------------------
_model = None
def get_embedding_model():
    global _model
    if _model is None:
        _model = SentenceTransformer(EMBED_MODEL)
    return _model


# --------------------------------------
# UTIL
# --------------------------------------
def vuln_to_text(v: dict) -> str:
    """Create a useful text description of the vuln for embeddings."""
    return (
        f"rule:{v.get('rule_id','')}\n"
        f"severity:{v.get('severity','')}\n"
        f"file:{v.get('file','')}\n"
        f"code:{v.get('code','')}"
    )


def llm_label_cluster(samples: List[str]) -> str:
    """
    Summarize the theme of a cluster using an LLM.
    Takes the first 4 samples.
    """
    if not samples:
        return "misc"

    prompt = (
        "You are a senior application security researcher. "
        "Given these code vulnerability descriptions, produce a short 1-3 word topic name, "
        "kebab-case, describing the common theme.\n\n"
        "Examples:\n"
        " - 'hardcoded-secrets'\n"
        " - 'unsafe-file-access'\n"
        " - 'sql-injection'\n"
        " - 'crypto-misuse'\n"
        " - 'authz-bypass'\n\n"
        "Vulnerabilities:\n"
        + "\n---\n".join(samples[:4]) +
        "\n\nReturn ONLY the short kebab-case topic name."
    )

    try:
        resp = openai.ChatCompletion.create(
            model=LLM_MODEL,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=15,
            temperature=0.2,
        )
        out = resp["choices"][0]["message"]["content"].strip()
        return out
    except Exception:
        return "misc"


# --------------------------------------
# MAIN PIPELINE
# --------------------------------------
def topic_model_vulns(vuln_records: Dict[str, dict]) -> Dict[str, str]:
    """
    Mapping:
        uid -> topic label
    """
    if not vuln_records:
        return {}

    uids = list(vuln_records.keys())
    texts = [vuln_to_text(v) for v in vuln_records.values()]

    # -------------------------
    # 1. EMBEDDINGS
    # -------------------------
    model = get_embedding_model()
    embeddings = model.encode(texts, show_progress_bar=False)

    # -------------------------
    # 2. OPTIONAL: DIM REDUCT
    # -------------------------
    if USE_UMAP:
        reducer = umap.UMAP(n_neighbors=15, min_dist=0.1)
        emb_small = reducer.fit_transform(embeddings)
        X = emb_small
    else:
        X = embeddings

    # -------------------------
    # 3. HDBSCAN CLUSTERING
    # -------------------------
    clusterer = hdbscan.HDBSCAN(
        min_cluster_size=CLUSTER_MIN_SIZE,
        metric="euclidean",
        cluster_selection_method="leaf",
    )
    labels = clusterer.fit_predict(X)

    # -------------------------
    # 4. LABEL CLUSTERS USING LLM
    # -------------------------
    cluster_texts = {}
    for idx, cid in enumerate(labels):
        cluster_texts.setdefault(cid, []).append(texts[idx])

    cluster_names = {}
    for cid, samples in cluster_texts.items():
        if cid == -1:
            cluster_names[cid] = "misc"
        else:
            cluster_names[cid] = llm_label_cluster(samples)

    # -------------------------
    # 5. MAP UID -> TOPIC LABEL
    # -------------------------
    return {
        uids[i]: cluster_names[labels[i]]
        for i in range(len(uids))
    }
