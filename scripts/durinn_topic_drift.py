%%writefile durinn_topic_drift.py
# durinn_topic_drift.py
"""
Topic drift analytics support module.

Functions:
- topic_distribution(topics)
- kl_divergence(prev_dist, curr_dist)
- jaccard_drift(prev_topics, curr_topics)
- topic_heatmap_points(commit_sha, timestamp, topics, owner, repo)
- topic_drift_points(commit_sha, timestamp, drift_dict, owner, repo)
"""

from typing import Dict, List
import math
from collections import Counter


# ------------------------------------------------------------
# Topic Distribution
# ------------------------------------------------------------
def topic_distribution(topics: Dict[str, str]) -> Dict[str, float]:
    """
    Convert topic labels into normalized frequency distribution.

    Input:
        { uid: "sql-injection" }

    Output:
        { "sql-injection": 0.44, "misc": 0.12, ... }
    """
    if not topics:
        return {}

    counts = Counter(topics.values())
    total = sum(counts.values())
    return {topic: count / total for topic, count in counts.items()}


# ------------------------------------------------------------
# KL Divergence
# ------------------------------------------------------------
def kl_divergence(prev: Dict[str, float], curr: Dict[str, float]) -> float:
    """
    KL divergence between two discrete distributions.
    Missing keys are treated as epsilon.
    """
    if not prev or not curr:
        return 0.0

    epsilon = 1e-8
    all_keys = set(prev) | set(curr)

    divergence = 0.0
    for k in all_keys:
        p = prev.get(k, epsilon)
        q = curr.get(k, epsilon)
        divergence += p * math.log(p / q)

    return float(divergence)


# ------------------------------------------------------------
# Jaccard Drift
# ------------------------------------------------------------
def jaccard_drift(prev_topics: Dict[str, str], curr_topics: Dict[str, str]) -> float:
    """
    Jaccard similarity of topic *sets*, returned as drift (1 - similarity):

    Drift = 1 - |Intersection| / |Union|

    Used to measure qualitative change in topic composition.
    """
    prev_set = set(prev_topics.values())
    curr_set = set(curr_topics.values())

    if not prev_set and not curr_set:
        return 0.0

    intersection = len(prev_set & curr_set)
    union = len(prev_set | curr_set)

    similarity = intersection / union
    drift = 1.0 - similarity
    return float(drift)


# ------------------------------------------------------------
# Heatmap Points (TSDB)
# ------------------------------------------------------------
def topic_heatmap_points(commit_sha: str,
                         timestamp: str,
                         topics: Dict[str, str],
                         owner: str,
                         repo: str) -> List[dict]:
    """
    For each topic T, emit one TSDB heatmap point:

    measurement: "topic_heatmap"
    tags: owner, repo, commit_sha, topic
    fields: count
    """
    if not topics:
        return []

    counts = Counter(topics.values())

    points = []
    for topic, count in counts.items():
        points.append({
            "measurement": "topic_heatmap",
            "time": timestamp,
            "tags": {
                "owner": owner,
                "repo": repo,
                "commit_sha": commit_sha,
                "topic": topic,
            },
            "fields": {
                "count": int(count),
            },
        })

    return points


# ------------------------------------------------------------
# Topic Drift Points (Optional TSDB)
# ------------------------------------------------------------
def topic_drift_points(commit_sha: str,
                       timestamp: str,
                       drift: Dict[str, float],
                       owner: str,
                       repo: str) -> List[dict]:
    """
    Converts drift metrics into TSDB time-series points.

    Example drift dict:
        {
            "jaccard": 0.18,
            "kl_divergence": 0.52
        }

    Emits one point per metric.
    """
    if not drift:
        return []

    points = []
    for metric, value in drift.items():
        points.append({
            "measurement": "topic_drift",
            "time": timestamp,
            "tags": {
                "owner": owner,
                "repo": repo,
                "commit_sha": commit_sha,
                "metric": metric,
            },
            "fields": {
                "value": float(value),
            },
        })

    return points
