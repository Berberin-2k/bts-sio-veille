"""Conservative, evidence-based classification of security bulletin severity.

Never infer a CVSS level from a generic vulnerability title, the publisher,
the article category or an AI-generated summary. Only explicit source-provided
scores and clearly labelled severity statements yield rated levels.
"""
from __future__ import annotations

import re
from typing import Any

SEVERITY_VERSION = 1
SEVERITIES = {"critique", "elevee", "moderee", "faible", "aucune", "non_evaluee", "information"}

# A standalone "CVSS 4.0" can identify the *version*, not a score.
# A score must have a clear "score" word or ": / =" separator.
_CVSS_SCORES = [
    re.compile(
        r"\bCVSS(?:\s+v(?:ersion)?\s*(?:2\.0|3\.0|3\.1|4\.0))?"
        r"\s*(?:base\s+)?(?:score|note|rating)\s*(?:[:=\-]\s*)?"
        r"(10(?:[.,]0)?|[0-9][.,][0-9])(?=\D|$)",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bCVSS(?:\s+v(?:ersion)?\s*(?:2\.0|3\.0|3\.1|4\.0))?"
        r"\s*[:=]\s*(10(?:[.,]0)?|[0-9][.,][0-9])(?=\D|$)",
        re.IGNORECASE,
    ),
]
_OFFICIAL_LABEL = re.compile(
    r"\b(?:severity|severity\s+level|sévérité|gravité)"
    r"\s*[:=\-]\s*(critical|critique|high|élevée?|elevee?|medium|moderate|modérée?|moderee?|low|faible|none|aucune)\b",
    re.IGNORECASE,
)
_SECURITY_WORDS = re.compile(
    r"\b(?:CVE-\d{4}-\d{4,}|vulnerabilit(?:y|ies)|vulnérabilit(?:é|és)|"
    r"vulnerabilit[eé]s?|exploit(?:ed|ation)?|zero[- ]day|0[- ]day|"
    r"ransomware|malware|patch\s+de\s+sécurité|"
    r"security\s+(?:advisory|bulletin|vulnerability|alert|notice)|"
    r"alerte\s+de\s+sécurité|faill?e\s+de\s+sécurité)\b",
    re.IGNORECASE,
)
_LABEL_MAP = {
    "critical": "critique", "critique": "critique",
    "high": "elevee", "élevé": "elevee", "élevée": "elevee",
    "eleve": "elevee", "elevee": "elevee",
    "medium": "moderee", "moderate": "moderee",
    "modéré": "moderee", "modérée": "moderee",
    "modere": "moderee", "moderee": "moderee",
    "low": "faible", "faible": "faible",
    "none": "aucune", "aucune": "aucune",
}
_RANK = {"aucune": 0, "faible": 1, "moderee": 2, "elevee": 3, "critique": 4}


def from_cvss_score(score: float) -> str:
    if not 0 <= score <= 10:
        raise ValueError("CVSS score out of range")
    if score == 0:
        return "aucune"
    if score < 4.0:
        return "faible"
    if score < 7.0:
        return "moderee"
    if score < 9.0:
        return "elevee"
    return "critique"


def security_relevant(item: dict[str, Any]) -> bool:
    source = str(item.get("source") or "")
    if source.startswith("CERT-FR") or source == "Ubuntu Security":
        return True
    # Category Cybersécurité alone is insufficient: an educational security
    # article can be a harmless news item, not a vulnerability notice.
    title = str(item.get("title") or "")
    excerpt = str(item.get("excerpt") or "")
    return bool(_SECURITY_WORDS.search(title + " " + excerpt))


def classify(item: dict[str, Any], *, source_excerpt: str | None = None) -> dict[str, Any]:
    """Return machine-friendly fields, safe for public JSON and website badges.

    source_excerpt is source RSS text, *never* an unverified AI summary.
    For historical AI summaries with no retained RSS text, inspect title only.
    """
    title = str(item.get("title") or "")
    if source_excerpt is None:
        source_excerpt = item.get("excerpt")
        if source_excerpt is None and item.get("summary_kind") == "extrait":
            source_excerpt = item.get("summary_fr")
    text = (title + " " + str(source_excerpt or ""))[:6000]
    scores: list[float] = []
    for pattern in _CVSS_SCORES:
        for match in pattern.finditer(text):
            try:
                score = float(match.group(1).replace(",", "."))
            except ValueError:
                continue
            if 0 <= score <= 10:
                scores.append(score)
    if scores:
        score = max(scores)
        return {
            "severity": from_cvss_score(score),
            "severity_basis": "cvss",
            "cvss_score": score,
            "severity_version": SEVERITY_VERSION,
        }

    explicit = [_LABEL_MAP[m.group(1).lower()] for m in _OFFICIAL_LABEL.finditer(text) if m.group(1).lower() in _LABEL_MAP]
    if explicit:
        return {
            "severity": max(explicit, key=lambda value: _RANK[value]),
            "severity_basis": "mention_source",
            "cvss_score": None,
            "severity_version": SEVERITY_VERSION,
        }

    if security_relevant({**item, "excerpt": source_excerpt or ""}):
        label, basis = "non_evaluee", "donnees_insuffisantes"
    else:
        label, basis = "information", "actualite"
    return {
        "severity": label,
        "severity_basis": basis,
        "cvss_score": None,
        "severity_version": SEVERITY_VERSION,
    }
