# durinn_topic_drift.py
"""
Topic drift + commit → topic heatmap utilities.

Works with output from topic_model_vulns().
"""

from typing import Dict, List, Tuple
import math
from collections import Counter


# -----------------------------------------------------------
# 1. Compute topic distribution for a commit
# -----------------------------------------------------------
def topic_distribution(topics: Dict[str, str]) -> Dict[str, int]:
    return dict(Counter(topics.values()))


# -----------------------------------------------------------
# 2. KL Divergence for drift between two topic distributions
# -----------------------------------------------------------
def kl_divergence(p: Dict[str, int], q: Dict[str, int]) -> float:
    # Convert to probability distributions
    total_p = sum(p.values()) or 1
    total_q = sum(q.values()) or 1

    keys = set(p.keys()) | set(q.keys())
    kl = 0.0

    for k in keys:
        p_k = p.get(k, 0) / total_p
        q_k = q.get(k, 0) / total_q

        if p_k > 0 and q_k > 0:
            kl += p_k * math.log(p_k / q_k)
        elif p_k > 0 and q_k == 0:
            # Full surprise
            kl += p_k * math.log(p_k / 1e-9)

    return kl


# -----------------------------------------------------------
# 3. Jaccard distance (simple drift)
# -----------------------------------------------------------
def jaccard_drift(prev_topics: Dict[str, str], curr_topics: Dict[str, str]) -> float:
    prev_set = set(prev_topics.values())
    curr_set = set(curr_topics.values())
    intersection = len(prev_set & curr_set)
    union = len(prev_set | curr_set)
    if union == 0:
        return 0.0
    return 1 - (intersection / union)


# -----------------------------------------------------------
# 4. Heatmap rows for TSDB ingestion
# -----------------------------------------------------------
def topic_heatmap_points(
    commit_sha: str,
    timestamp: str,
    topics: Dict[str, str],
    owner: str,
    repo: str
):
    """
    Return a list of time-series ready "topic frequency" points:
    
    Example:
    {
      measurement: "topic_heatmap",
      time: <ISO>,
      tags: { owner, repo, commit_sha, topic },
      fields: { count: <int> }
    }
    """
    dist = Counter(topics.values())
    points = []

    for topic, count in dist.items():
        points.append({
            "measurement": "topic_heatmap",
            "time": timestamp,
            "tags": {
                "owner": owner,
                "repo": repo,
                "commit_sha": commit_sha,
                "topic": topic
            },
            "fields": {
                "count": int(count)
            }
        })
    return points

def topic_drift_points(
    commit_sha: str,
    timestamp: str,
    drift: dict,
    owner: str,
    repo: str
):
    """
    Drift metrics → TSDB rows.
    Example:
      measurement: "topic_drift"
      tags: { owner, repo, commit_sha }
      fields: { jaccard: 0.55, kl_divergence: 1.38 }
    """

    return [{
        "measurement": "topic_drift",
        "time": timestamp,
        "tags": {
            "owner": owner,
            "repo": repo,
            "commit_sha": commit_sha
        },
        "fields": {
            "jaccard": float(drift.get("jaccard", 0.0)),
            "kl_divergence": float(drift.get("kl_divergence", 0.0))
        }
    }]
