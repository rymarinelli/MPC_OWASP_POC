%%writefile durinn_topic_model.py

"""
Topic modeling for vulnerability records using embeddings + HDBSCAN + Magicoder cluster labeling.
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
from transformers import pipeline

# --------------------------------------
# CONFIG
# --------------------------------------
EMBED_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
USE_UMAP = False               # optional dimensionality reduction
CLUSTER_MIN_SIZE = 2
MAGICODER_MODEL = "ise-uiuc/Magicoder-CL-7B"   # your local HF model


# --------------------------------------
# GLOBAL MODELS
# --------------------------------------
_embed_model = None
_magicoder = None


def get_embed_model():
    global _embed_model
    if _embed_model is None:
        _embed_model = SentenceTransformer(EMBED_MODEL)
    return _embed_model


def get_magicoder():
    """
    Create Magicoder generation pipeline once and reuse it.
    """
    global _magicoder
    if _magicoder is None:
        _magicoder = pipeline(
            "text-generation",
            model=MAGICODER_MODEL,
            trust_remote_code=True,
            device=0  # GPU, or use `None` for CPU
        )
    return _magicoder


# --------------------------------------
# UTIL
# --------------------------------------
def vuln_to_text(v: dict) -> str:
    """Clean text representation of a vulnerability."""
    return (
        f"rule:{v.get('rule_id','')}\n"
        f"severity:{v.get('severity','')}\n"
        f"file:{v.get('file','')}\n"
        f"code:{v.get('code','')}"
    )


def llm_label_cluster(samples: List[str]) -> str:
    """
    Summarize the cluster theme using Magicoder.
    Returns 1–3 word kebab-case label.
    """
    if not samples:
        return "misc"

    prompt = (
        "You are a senior application security researcher. "
        "Given these vulnerability descriptions, produce a short 1–3 word topic name "
        "in kebab-case describing the common theme.\n\n"
        "Examples:\n"
        "- hardcoded-secrets\n"
        "- unsafe-file-access\n"
        "- sql-injection\n"
        "- authz-bypass\n"
        "- crypto-misuse\n\n"
        "Vulnerabilities:\n" +
        "\n---\n".join(samples[:4]) +
        "\n\nReturn ONLY the kebab-case topic name, no explanation:"
    )

    try:
        gen = get_magicoder()(
            prompt,
            max_new_tokens=20,
            do_sample=False
        )[0]["generated_text"]

        # Extract only the answer (Magicoder sometimes echoes)
        out = gen[len(prompt):].strip()
        out = out.split("\n")[0].strip()

        # Sanitize output → kebab-case
        out = out.lower().replace(" ", "-")
        return out or "misc"

    except Exception:
        return "misc"


# --------------------------------------
# MAIN PIPELINE
# --------------------------------------
def topic_model_vulns(vuln_records: Dict[str, dict]) -> Dict[str, str]:
    """
    Input:
        { vuln_uid: vuln_record }
    Output:
        { vuln_uid: topic_label }
    """
    if not vuln_records:
        return {}

    uids = list(vuln_records.keys())
    texts = [vuln_to_text(v) for v in vuln_records.values()]

    # --------------------------------------
    # 1) Embeddings
    # --------------------------------------
    model = get_embed_model()
    embeddings = model.encode(texts, show_progress_bar=False)

    # --------------------------------------
    # 2) Dimensionality reduction (optional)
    # --------------------------------------
    if USE_UMAP:
        reducer = umap.UMAP(n_neighbors=15, min_dist=0.1)
        X = reducer.fit_transform(embeddings)
    else:
        X = embeddings

    # --------------------------------------
    # 3) HDBSCAN clustering
    # --------------------------------------
    clusterer = hdbscan.HDBSCAN(
        min_cluster_size=CLUSTER_MIN_SIZE,
        metric="euclidean",
        cluster_selection_method="leaf",
    )
    labels = clusterer.fit_predict(X)

    # --------------------------------------
    # 4) Cluster labeling using Magicoder
    # --------------------------------------
    cluster_samples = {}
    for i, cid in enumerate(labels):
        cluster_samples.setdefault(cid, []).append(texts[i])

    cluster_names = {}
    for cid, samples in cluster_samples.items():
        if cid == -1:
            cluster_names[cid] = "misc"
        else:
            cluster_names[cid] = llm_label_cluster(samples)

    # --------------------------------------
    # 5) Map UIDs → cluster names
    # --------------------------------------
    return {
        uids[i]: cluster_names[labels[i]]
        for i in range(len(uids))
    }
