"""Verify CVE identifiers against original bulletins, enrich via NIST NVD CVSS.

No LLM-estimated scores. All external article URLs are restricted to known
bulletin domains. Strict per-run lookups, NVD pacing and a persistent cache.
"""
from __future__ import annotations

import datetime as dt
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import time
from urllib import error, parse, request

from severity import classify as classify_source, from_cvss_score, security_relevant

ENRICH_VERSION = 2
MAX_CVE_REQUESTS = 14
MAX_NOTICE_REQUESTS = 12
MAX_CVES_PER_ARTICLE = 80
MAX_CACHE_ITEMS = 2400
NVD_SECONDS_BETWEEN_REQUESTS = 7.0
CVE_RE = re.compile(r"\bCVE-(?:19|20)\d{2}-\d{4,}\b", re.IGNORECASE)
USN_PATH = re.compile(r"/security/notices/(USN-\d{3,6}-\d{1,3})/?$", re.IGNORECASE)
CERT_PATH = re.compile(r"/(?:alerte|avis|cti|actualite)/[A-Z0-9\-]+/?$", re.IGNORECASE)
USER_AGENT = "BTS-SIO-Veille/2.0 (public advisory reader)"
NVD_PREFIX = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
CHECKED_POSITIVE_DAYS = 14
CHECKED_EMPTY_DAYS = 2


def now_utc() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def parse_date(raw: object) -> dt.datetime | None:
    if not isinstance(raw, str):
        return None
    try:
        stamp = dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if stamp.tzinfo is None:
        return None
    return stamp.astimezone(dt.timezone.utc)


def cve_ids_from(text: str) -> list[str]:
    return list(dict.fromkeys(x.upper() for x in CVE_RE.findall(text)))[:MAX_CVES_PER_ARTICLE]


class NoticeParser(HTMLParser):
    """Get referenced CVEs from a vendor page, excluding script/style text."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.linked: list[str] = []
        self.visible: list[str] = []
        self.skip = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in ("script", "style", "noscript"):
            self.skip += 1
        if tag == "a":
            href = dict(attrs).get("href") or ""
            # Official Ubuntu/CERT link references, not arbitrary external links.
            if "/security/cves/" in href or "cve.mitre.org/cgi-bin/cvename.cgi" in href or "nvd.nist.gov/vuln/detail/" in href:
                self.linked.extend(cve_ids_from(href))

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style", "noscript") and self.skip:
            self.skip -= 1

    def handle_data(self, data: str) -> None:
        if not self.skip and "CVE-" in data.upper():
            self.visible.append(data[:20000])


def parse_notice_html(raw: str) -> list[str]:
    parser = NoticeParser()
    parser.feed(raw[:2_000_000])
    # Linked CVE references are the most reliable, but the vendor may also
    # list CVEs in plain text of the bulletin.
    ordered = parser.linked + [
        x for text in parser.visible for x in cve_ids_from(text)
    ]
    return list(dict.fromkeys(ordered))[:MAX_CVES_PER_ARTICLE]


def official_notice_url(article: dict) -> str | None:
    url = article.get("url", "")
    if not isinstance(url, str):
        return None
    parts = parse.urlsplit(url)
    if parts.scheme != "https" or parts.username or parts.password:
        return None
    if article.get("source") == "Ubuntu Security" and parts.hostname == "ubuntu.com":
        match = USN_PATH.fullmatch(parts.path)
        if match:
            return "https://ubuntu.com/security/notices/" + match.group(1).upper()
    if (str(article.get("source") or "").startswith("CERT-FR") and
            parts.hostname == "cert.cyber.gouv.fr" and CERT_PATH.fullmatch(parts.path)):
        return "https://cert.cyber.gouv.fr" + parts.path
    return None


def fetch_official_notice(url: str) -> str:
    req = request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "text/html"})
    with request.urlopen(req, timeout=16) as resp:
        final = parse.urlsplit(resp.geturl())
        if final.scheme != "https" or final.hostname != parse.urlsplit(url).hostname:
            raise ValueError("Official bulletin redirected outside the trusted host")
        body = resp.read(2_000_001)
        if len(body) > 2_000_000:
            raise ValueError("Bulletin HTML exceeds 2 MB limit")
        content_type = resp.headers.get_content_charset() or "utf-8"
        return body.decode(content_type, errors="replace")


def extract_nvd_score(payload: dict, expected_cve: str) -> dict | None:
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cve", {})
        if cve.get("id", "").upper() != expected_cve:
            continue
        if str(cve.get("vulnStatus", "")).lower() in ("rejected", "reserved"):
            return None
        metrics = cve.get("metrics", {})
        found = []
        for metric_type in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
            for metric in metrics.get(metric_type, []):
                cvss = metric.get("cvssData", {})
                raw = cvss.get("baseScore")
                if isinstance(raw, bool) or not isinstance(raw, (float, int)):
                    continue
                score = float(raw)
                if not 0 <= score <= 10:
                    continue
                found.append({
                    "score": score,
                    "cvss_version": str(cvss.get("version") or ""),
                    "score_source": str(metric.get("source") or cve.get("sourceIdentifier") or "NVD")[:100],
                })
        if found:
            return max(found, key=lambda x: x["score"])
    return None


def fetch_nvd_cve(cve_id: str) -> dict | None:
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    key = os.getenv("NVD_API_KEY", "").strip()
    if key:
        headers["apiKey"] = key
    req = request.Request(NVD_PREFIX + parse.quote(cve_id, safe="-"), headers=headers)
    with request.urlopen(req, timeout=22) as resp:
        raw = resp.read(650_001)
        if len(raw) > 650_000:
            raise ValueError("NVD response exceeds limit")
        payload = json.loads(raw)
    return extract_nvd_score(payload, cve_id)


def read_cache(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RuntimeError("CVSS cache corrupted; refusing to overwrite") from exc
    if not isinstance(raw, dict) or raw.get("version") != 1 or not isinstance(raw.get("entries"), dict):
        raise RuntimeError("Invalid CVSS cache schema")
    return raw["entries"]


def write_cache(path: Path, entries: dict) -> None:
    # Keep a finite, auditable public cache without raw NVD responses.
    ranked = sorted(
        ((cve, item) for cve, item in entries.items()
         if CVE_RE.fullmatch(cve) and isinstance(item, dict) and parse_date(item.get("checked_at"))),
        key=lambda pair: pair[1]["checked_at"],
        reverse=True,
    )[:MAX_CACHE_ITEMS]
    path.parent.mkdir(parents=True, exist_ok=True)
    dest = path.with_name(path.name + ".tmp")
    dest.write_text(json.dumps({"version": 1, "entries": dict(ranked)}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    dest.replace(path)


def cache_fresh(record: dict | None, now: dt.datetime) -> bool:
    if not record:
        return False
    last = parse_date(record.get("checked_at"))
    if not last:
        return False
    days = CHECKED_POSITIVE_DAYS if record.get("score") is not None else CHECKED_EMPTY_DAYS
    return now - last < dt.timedelta(days=days)


def is_security_article(article: dict) -> bool:
    return article.get("severity") != "information" and security_relevant(article)


def refresh_article_scores(article: dict, cache: dict, now: dt.datetime) -> None:
    cves = [x for x in article.get("cve_ids", []) if isinstance(x, str) and CVE_RE.fullmatch(x)]
    cves = list(dict.fromkeys(cves))[:MAX_CVES_PER_ARTICLE]
    verified = []
    looked_up = 0
    for cve in cves:
        record = cache.get(cve)
        if record and parse_date(record.get("checked_at")):
            looked_up += 1
            if isinstance(record.get("score"), (float, int)) and not isinstance(record.get("score"), bool):
                if 0 <= record["score"] <= 10:
                    verified.append((cve, record))
    article["cve_ids"] = cves
    article["cve_identified_count"] = len(cves)
    article["cve_checked_count"] = looked_up
    article["cve_assessed_count"] = len(verified)
    article["severity_coverage"] = ("complete" if cves and looked_up == len(cves) else
                                    "partial" if looked_up else "pending" if cves else "unavailable")
    article["enrichment_version"] = ENRICH_VERSION
    if verified:
        highest_cve, highest = max(verified, key=lambda pair: pair[1]["score"])
        # Keep a stronger explicit source score if one is already present.
        if (article.get("severity_basis") not in ("cvss", "mention_source") or
                not isinstance(article.get("cvss_score"), (float, int)) or
                highest["score"] >= article["cvss_score"]):
            article.update({
                "severity": from_cvss_score(highest["score"]),
                "severity_basis": "nvd_cvss",
                "cvss_score": highest["score"],
                "cvss_version": highest.get("cvss_version"),
                "severity_cve": highest_cve,
                "severity_source": highest.get("score_source", "NVD"),
                "severity_source_url": "https://nvd.nist.gov/vuln/detail/" + highest_cve,
                "severity_checked_at": highest["checked_at"],
            })


def enrich_articles(
    articles: list[dict], feed_by_url: dict[str, dict], cache: dict, *,
    now: dt.datetime | None = None, max_nvd: int = MAX_CVE_REQUESTS,
    max_notices: int = MAX_NOTICE_REQUESTS,
    notice_fetcher=fetch_official_notice,
    nvd_fetcher=fetch_nvd_cve,
    sleeper=time.sleep,
) -> dict:
    now = now or now_utc()
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    # Prioritize current security bulletins for incremental migration.
    sorted_articles = sorted(articles, key=lambda a: a.get("published_at") or a.get("collected_at") or "", reverse=True)
    candidates = [a for a in sorted_articles if is_security_article(a)]
    notices = 0
    errors = 0
    for article in candidates:
        feed = feed_by_url.get(article.get("url"), {})
        old_ids = article.get("cve_ids") or []
        ids = list(dict.fromkeys(x for x in old_ids if CVE_RE.fullmatch(str(x))))
        rss_text = str(feed.get("excerpt") or "")
        ids = list(dict.fromkeys(ids + cve_ids_from(str(article.get("title") or "") + " " + rss_text)))
        article["cve_ids"] = ids[:MAX_CVES_PER_ARTICLE]
        # Fetch original bulletin only when no successful original-page discovery
        # has yet occurred; attempt again after 7 days if the page was unavailable.
        last_page = parse_date(article.get("notice_checked_at"))
        should_fetch = (
            notices < max_notices and official_notice_url(article) and
            len(article["cve_ids"]) < 2 and
            (not last_page or now - last_page > dt.timedelta(days=7))
        )
        if should_fetch:
            notices += 1
            try:
                html_text = notice_fetcher(official_notice_url(article))
                page_ids = parse_notice_html(html_text)
                article["cve_ids"] = list(dict.fromkeys(article["cve_ids"] + page_ids))[:MAX_CVES_PER_ARTICLE]
                article["notice_checked_at"] = iso(now)
                article["notice_url"] = official_notice_url(article)
            except (error.HTTPError, error.URLError, TimeoutError, ValueError, UnicodeError, OSError) as exc:
                errors += 1
                # Rate-limit reattempts; keep previously discovered evidence.
                article["notice_checked_at"] = iso(now - dt.timedelta(days=6))
                print(f"[WARN] Bulletin non disponible: {type(exc).__name__} {article.get('title','')[:70]}")
        article["enrichment_version"] = ENRICH_VERSION

    budget = max(0, max_nvd)
    queried = set()
    requests_made = 0
    # One CVE per bulletin per round avoids allowing multi-CVE Ubuntu notices
    # to monopolize the unauthenticated NVD quota.
    while budget:
        progress = False
        for article in candidates:
            if budget <= 0:
                break
            unseen = next((x for x in article.get("cve_ids", [])
                           if x not in queried and not cache_fresh(cache.get(x), now)), None)
            if not unseen:
                continue
            queried.add(unseen)
            # NVD allows five unauthenticated requests per 30 seconds. Use a
            # conservative 7s interval; the optional API key is not required.
            if requests_made:
                sleeper(NVD_SECONDS_BETWEEN_REQUESTS)
            try:
                score = nvd_fetcher(unseen)
                cache[unseen] = {"checked_at": iso(now), **(score or {"score": None})}
                requests_made += 1
                budget -= 1
                progress = True
            except (error.HTTPError, error.URLError, TimeoutError, ValueError, json.JSONDecodeError, OSError) as exc:
                errors += 1
                requests_made += 1
                budget -= 1
                print(f"[WARN] NVD {unseen}: {type(exc).__name__}")
                if isinstance(exc, error.HTTPError) and exc.code in (401, 403, 429):
                    budget = 0
                    break
        if not progress:
            break

    verified_articles = 0
    pending_articles = 0
    for article in candidates:
        refresh_article_scores(article, cache, now)
        if article.get("severity_basis") == "nvd_cvss":
            verified_articles += 1
        if article.get("severity_coverage") in ("pending", "partial"):
            pending_articles += 1

    return {
        "notice_requests": notices,
        "nvd_requests": requests_made,
        "enrichment_errors": errors,
        "cvss_verified_articles": verified_articles,
        "enrichment_pending_articles": pending_articles,
        "cve_cache_records": len(cache),
    }
