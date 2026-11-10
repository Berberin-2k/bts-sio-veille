"""Offline tests for conservative bulletin enrichment and caching."""
import datetime as dt
import json
from pathlib import Path
import sys
import tempfile
import unittest
from urllib import error

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import enrich_cvss


NOW = dt.datetime(2026, 11, 10, 12, tzinfo=dt.timezone.utc)


def advisory(title, source="Ubuntu Security", url="https://ubuntu.com/security/notices/USN-9016-1"):
    return {
        "title": title, "url": url, "source": source,
        "published_at": "2026-11-10T02:40:00Z",
        "severity": "non_evaluee", "severity_basis": "donnees_insuffisantes",
        "summary_kind": "ia", "summary_fr": "Gemini made up CVSS 10.0",
    }


class EnrichmentTests(unittest.TestCase):
    def test_vendor_cve_extraction_ignores_script(self):
        html = """<html><body><a href='/security/cves/CVE-2026-57941'>CVE-2026-57941</a>
        A second issue (CVE-2026-120208) was fixed.
        <script>const fake='CVE-2026-999999';</script></body></html>"""
        self.assertEqual(
            enrich_cvss.parse_notice_html(html),
            ["CVE-2026-57941", "CVE-2026-120208"],
        )

    def test_notice_url_restricted_to_official_bulletin(self):
        self.assertEqual(
            enrich_cvss.official_notice_url(advisory("Apache")),
            "https://ubuntu.com/security/notices/USN-9016-1",
        )
        for url in ("https://evil.example/security/notices/USN-9016-1",
                    "https://ubuntu.com.evil.example/security/notices/USN-9016-1",
                    "http://ubuntu.com/security/notices/USN-9016-1",
                    "https://ubuntu.com/security/notices/../../etc/passwd"):
            self.assertIsNone(enrich_cvss.official_notice_url(advisory("Apache", url=url)))

    def test_nvd_metrics_verified_and_provenance(self):
        body = {
            "vulnerabilities": [
                {"cve": {"id": "CVE-2026-57941", "vulnStatus": "Analyzed",
                         "metrics": {"cvssMetricV31": [
                             {"source": "CISA-ADP", "type": "Secondary",
                              "cvssData": {"baseScore": 9.8, "version": "3.1"}}]}}}
            ]
        }
        metric = enrich_cvss.extract_nvd_score(body, "CVE-2026-57941")
        self.assertEqual(metric, {"score": 9.8, "cvss_version": "3.1", "score_source": "CISA-ADP"})
        self.assertIsNone(enrich_cvss.extract_nvd_score(body, "CVE-2026-00000"))

    def test_rejected_cve_and_nonsensical_metrics_not_rated(self):
        payload = {"vulnerabilities": [
            {"cve": {"id": "CVE-2026-57941", "vulnStatus": "Rejected",
                     "metrics": {"cvssMetricV31": [
                         {"cvssData": {"version": "3.1", "baseScore": 10.0}}]}}}
        ]}
        self.assertIsNone(enrich_cvss.extract_nvd_score(payload, "CVE-2026-57941"))
        payload["vulnerabilities"][0]["cve"]["vulnStatus"] = "Analyzed"
        payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"] = 11
        self.assertIsNone(enrich_cvss.extract_nvd_score(payload, "CVE-2026-57941"))

    def test_usn_enrichment_produces_partial_critical_with_evidence(self):
        article = advisory("USN-9016-1: Apache HTTP Server vulnerabilities")
        cache = {}
        queried = []
        def nvd(cve):
            queried.append(cve)
            return ({"score": 9.8, "cvss_version": "3.1", "score_source": "CISA-ADP"}
                    if cve == "CVE-2026-57941" else None)
        count = enrich_cvss.enrich_articles(
            [article], {}, cache, now=NOW, max_nvd=1,
            notice_fetcher=lambda url: '<a href="/security/cves/CVE-2026-57941">CVE-2026-57941</a>'
                                       '<a href="/security/cves/CVE-2026-48005">CVE-2026-48005</a>',
            nvd_fetcher=nvd, sleeper=lambda seconds: None,
        )
        self.assertEqual(count["nvd_requests"], 1)
        self.assertEqual(article["severity"], "critique")
        self.assertEqual(article["cvss_score"], 9.8)
        self.assertEqual(article["severity_cve"], "CVE-2026-57941")
        self.assertEqual(article["severity_source_url"], "https://nvd.nist.gov/vuln/detail/CVE-2026-57941")
        self.assertEqual(article["cve_identified_count"], 2)
        self.assertEqual(article["cve_checked_count"], 1)
        self.assertEqual(article["severity_coverage"], "partial")

    def test_budget_round_robin_and_cache_persistence(self):
        a = advisory("USN-9016-1: Apache vulnerabilities")
        b = advisory("USN-9015-1: OpenJDK vulnerabilities",
                     url="https://ubuntu.com/security/notices/USN-9015-1")
        cache = {}
        seen = []
        def notice(url):
            if url.endswith("9016-1"):
                return "<p>CVE-2026-57941 CVE-2026-48005</p>"
            return "<p>CVE-2026-91410 CVE-2026-91400</p>"
        def nvd(cve):
            seen.append(cve)
            return {"score": 7.5, "cvss_version": "3.1", "score_source": "NIST"}
        enrich_cvss.enrich_articles([a, b], {}, cache, now=NOW, max_nvd=2,
                                    notice_fetcher=notice, nvd_fetcher=nvd,
                                    sleeper=lambda _: None)
        self.assertEqual(len(seen), 2)
        self.assertIn("CVE-2026-57941", seen)
        self.assertIn("CVE-2026-91410", seen)
        self.assertEqual(a["severity"], "elevee")
        self.assertEqual(b["severity"], "elevee")
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "cvss-cache.json"
            enrich_cvss.write_cache(path, cache)
            loaded = enrich_cvss.read_cache(path)
            self.assertEqual(set(cache), set(loaded))
            self.assertEqual(loaded["CVE-2026-57941"]["score"], 7.5)
            rerun = enrich_cvss.enrich_articles([a, b], {}, loaded, now=NOW,
                                                max_nvd=0, max_notices=0,
                                                nvd_fetcher=lambda _: (_ for _ in ()).throw(AssertionError("should not query")))
            self.assertEqual(rerun["nvd_requests"], 0)

    def test_failures_preserve_unrated_state(self):
        a = advisory("USN-9012-1: libheif vulnerability")
        # Even if official page is unreachable, unverified scores must never appear.
        stats = enrich_cvss.enrich_articles(
            [a], {}, {}, now=NOW, max_nvd=1,
            notice_fetcher=lambda _: (_ for _ in ()).throw(error.URLError("offline")),
            nvd_fetcher=lambda _: (_ for _ in ()).throw(AssertionError("should not query")),
            sleeper=lambda _: None,
        )
        self.assertEqual(stats["enrichment_errors"], 1)
        self.assertEqual(a["severity"], "non_evaluee")
        self.assertEqual(a["severity_coverage"], "unavailable")

    def test_no_ai_summary_as_cve_source(self):
        a = advisory("USN-9012-1: vulnerabilities")
        stats = enrich_cvss.enrich_articles(
            [a], {}, {}, now=NOW, max_nvd=0, max_notices=0,
            nvd_fetcher=lambda _: (_ for _ in ()).throw(AssertionError("nvd forbidden")),
        )
        self.assertEqual(a["cve_identified_count"], 0)
        self.assertEqual(stats["nvd_requests"], 0)

    def test_cache_ttl(self):
        old = {"checked_at": enrich_cvss.iso(NOW-dt.timedelta(days=3)), "score": None}
        ok = {"checked_at": enrich_cvss.iso(NOW-dt.timedelta(days=3)), "score": 9.8}
        self.assertFalse(enrich_cvss.cache_fresh(old, NOW))
        self.assertTrue(enrich_cvss.cache_fresh(ok, NOW))

    def test_invalid_cache_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "cvss-cache.json"
            path.write_text("{broken", encoding="utf-8")
            with self.assertRaises(RuntimeError):
                enrich_cvss.read_cache(path)


if __name__ == "__main__":
    unittest.main()
