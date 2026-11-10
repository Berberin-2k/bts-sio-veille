"""Offline regression tests for RSS parsing, retention, migration and fail-safe runs."""
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import retention
import severity

spec = importlib.util.spec_from_file_location("collector", ROOT / "scripts" / "collect.py")
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


def item(url, at, summary_kind="ia"):
    return {
        "url": url, "title": "Test article", "published_at": at,
        "collected_at": at, "source": "CERT-FR · Avis", "category": "Cybersécurité",
        "summary_fr": "Information source.", "summary_kind": summary_kind,
    }


class CollectorTests(unittest.TestCase):
    def test_tracking_cleanup(self):
        self.assertEqual(collector.canonical("https://example.org/a?x=1&utm_source=rss#hi"), "https://example.org/a?x=1")
        self.assertIsNone(collector.canonical("javascript:alert(1)"))

    def test_rss_and_atom(self):
        rss = b"<rss><channel><item><title>Alerte</title><link>https://a.test/1</link><description>Information</description><pubDate>Mon, 09 Nov 2026 10:00:00 GMT</pubDate></item></channel></rss>"
        atom = b'<feed xmlns="http://www.w3.org/2005/Atom"><entry><title>Linux</title><link rel="alternate" href="https://a.test/2"/><summary>Update</summary><updated>2026-11-09T10:00:00Z</updated></entry></feed>'
        source = ("A", "https://a.test/feed", "Systèmes")
        self.assertEqual(collector.parse_feed(rss, source)[0]["title"], "Alerte")
        self.assertEqual(collector.parse_feed(atom, source)[0]["url"], "https://a.test/2")

    def test_long_rss_description_retains_cves_beyond_1600_characters(self):
        long_intro = "Technical fix notes. " * 105
        rss = ("<rss><channel><item><title>Security notice</title>"
               "<link>https://ubuntu.com/security/notices/USN-9001-1</link>"
               "<description>" + long_intro + " CVE-2026-57941</description>"
               "</item></channel></rss>").encode()
        items = collector.parse_feed(rss, ("Ubuntu Security", "https://ubuntu.com/security/notices/rss.xml", "Systèmes"))
        self.assertIn("CVE-2026-57941", items[0]["excerpt"])
        self.assertGreater(len(items[0]["excerpt"]), 1600)

    def test_windows_itpro_source_and_classification(self):
        self.assertTrue(any(s[0] == "Microsoft · Windows IT Pro" and s[2] == "Windows" for s in collector.SOURCES))
        self.assertEqual(collector.category_for({"title":"Windows 11 enterprise management update","source":"Microsoft · Windows IT Pro","excerpt":"Windows IT admin","category":"Windows"}), "Windows")
        self.assertEqual(collector.parse_feed(b"<rss><channel><item><title>Windows Server update</title><link>https://techcommunity.microsoft.com/windows/post</link><pubDate>Mon, 09 Nov 2026 10:00:00 GMT</pubDate></item></channel></rss>",("Microsoft · Windows IT Pro","https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=Windows-ITPro-blog","Windows"))[0]["category"],"Windows")

    def test_round_robin_guarantees_windows_source_when_available(self):
        now = dt.datetime(2026, 11, 10, tzinfo=dt.timezone.utc)
        cutoff = now - dt.timedelta(days=60)
        sources = [s[0] for s in collector.SOURCES]
        candidates = []
        for index, source in enumerate(sources):
            for rank in range(3):
                published = (now - dt.timedelta(days=rank+index+1)).isoformat()
                candidates.append({
                    "source": source, "url": f"https://example.org/{index}/{rank}",
                    "title": "Windows management" if source == "Microsoft · Windows IT Pro" else "Security update",
                    "excerpt": "Enterprise system information",
                    "category": "Windows" if source == "Microsoft · Windows IT Pro" else "Systèmes",
                    "published_at": published,
                })
        selected = collector.select_articles(candidates, set(), cutoff, limit=8)
        self.assertEqual(len(selected), 8)
        self.assertIn("Microsoft · Windows IT Pro", [x["source"] for x in selected])
        self.assertEqual(len(set(x["source"] for x in selected)), 8)

    def test_cvss_severity_exact_thresholds(self):
        examples = [
            (0.0, "aucune"), (0.1, "faible"), (3.9, "faible"),
            (4.0, "moderee"), (6.9, "moderee"),
            (7.0, "elevee"), (8.9, "elevee"), (9.0, "critique"),
            (10.0, "critique"),
        ]
        for score, expected in examples:
            with self.subTest(score=score):
                self.assertEqual(severity.from_cvss_score(score), expected)
        with self.assertRaises(ValueError):
            severity.from_cvss_score(10.1)

    def test_source_cvss_score_and_provenance(self):
        article = {"title": "Notice CVE-2026-10002", "source": "Ubuntu Security",
                   "excerpt": "CVSS v3.1 base score: 9.8; CVSS v4.0 score: 7.5."}
        result = severity.classify(article)
        self.assertEqual(result["severity"], "critique")
        self.assertEqual(result["cvss_score"], 9.8)
        self.assertEqual(result["severity_basis"], "cvss")
        self.assertEqual(result["severity_version"], 1)

    def test_source_declared_severity(self):
        article = {"title": "Security advisory", "source": "CERT-FR · Alertes",
                   "excerpt": "Severity: High. No explicit numeric score."}
        result = severity.classify(article)
        self.assertEqual(result["severity"], "elevee")
        self.assertEqual(result["severity_basis"], "mention_source")
        self.assertIsNone(result["cvss_score"])

    def test_non_evaluated_security_is_not_automatically_critical(self):
        result = severity.classify({"title": "USN-9015: vulnerabilities", "source": "Ubuntu Security",
                                     "excerpt": "Multiple vulnerabilities have been fixed."})
        self.assertEqual(result["severity"], "non_evaluee")
        self.assertEqual(result["severity_basis"], "donnees_insuffisantes")

    def test_regular_windows_blog_post_is_information(self):
        result = severity.classify({"title": "Windows 365 management improvements",
                                    "source": "Microsoft · Windows IT Pro",
                                    "excerpt": "New management tools and deployment options."})
        self.assertEqual(result["severity"], "information")

    def test_cvss_vector_version_is_not_falsely_scored(self):
        result = severity.classify({"title": "Security bulletin", "source": "Ubuntu Security",
                                    "excerpt": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"})
        self.assertEqual(result["severity"], "non_evaluee")

    def test_ai_summary_is_not_treated_as_official_cvss(self):
        result = severity.classify({"title": "USN-9016-1: vulnerabilities",
                                    "source": "Ubuntu Security", "summary_kind": "ia",
                                    "summary_fr": "The model claims CVSS score: 10.0."})
        self.assertEqual(result["severity"], "non_evaluee")
        self.assertIsNone(result["cvss_score"])

    def test_legacy_extracted_rss_text_can_be_backfilled(self):
        result = severity.classify({"title": "Security notice", "source": "Ubuntu Security",
                                    "summary_kind": "extrait",
                                    "summary_fr": "CVSS base score: 7.3"})
        self.assertEqual(result["severity"], "elevee")

    def test_sanitize(self):
        self.assertEqual(collector.clean("<p>CVE &amp; Linux</p>"), "CVE & Linux")

    def test_partition_boundaries(self):
        now = dt.datetime(2026, 11, 10, 12, tzinfo=dt.timezone.utc)
        def ago(days, seconds=0):
            return (now - dt.timedelta(days=days, seconds=seconds)).isoformat()
        articles = [
            item("https://example.org/recent", ago(60)),
            item("https://example.org/archive", ago(60, 1)),
            item("https://example.org/year", ago(365)),
            item("https://example.org/expired", ago(365, 1)),
        ]
        recent, archive = retention.partition_articles(articles, now)
        self.assertEqual([x["url"] for x in recent], ["https://example.org/recent"])
        self.assertEqual([x["url"] for x in archive], ["https://example.org/archive", "https://example.org/year"])
        self.assertEqual(len(recent) + len(archive), 3)

    def test_max_1000_and_url_deduplication(self):
        now = dt.datetime(2026, 11, 10, tzinfo=dt.timezone.utc)
        items = [item(f"https://example.org/{i}", (now-dt.timedelta(days=2)).isoformat()) for i in range(1200)]
        items += [items[0]] * 3
        recent, archive = retention.partition_articles(items, now)
        self.assertEqual(len(recent), 1000)
        self.assertEqual(len(archive), 0)
        self.assertEqual(len({a["url"] for a in recent}), 1000)

    def test_missing_publication_falls_back_to_collection_date(self):
        now = dt.datetime(2026, 11, 10, tzinfo=dt.timezone.utc)
        x = item("https://example.org/missing-date", now.isoformat())
        x["published_at"] = None
        recent, archive = retention.partition_articles([x], now)
        self.assertEqual(len(recent), 1)
        self.assertEqual(archive, [])

    def test_legacy_migration_and_disjoint_files(self):
        now = dt.datetime(2026, 11, 10, tzinfo=dt.timezone.utc)
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            legacy = [
                item("https://example.org/fresh", (now-dt.timedelta(days=4)).isoformat()),
                item("https://example.org/old", (now-dt.timedelta(days=80)).isoformat()),
            ]
            (directory / "articles.json").write_text(json.dumps({"articles":legacy}),encoding="utf-8")
            self.assertEqual(len(retention.load_history(directory)), 2)
            recent, archive = retention.partition_articles(retention.load_history(directory), now)
            payload = {"version":2, "last_successful_sync":now.isoformat(),"recent_count":len(recent),"archive_count":len(archive),"articles":recent}
            retention.save_feeds(directory,payload,archive)
            self.assertEqual(len(retention.read_articles(directory / "recent.json")), 1)
            self.assertEqual(len(retention.read_articles(directory / "archives.json")), 1)
            self.assertEqual(len(retention.read_articles(directory / "articles.json")), 1)
            self.assertEqual(len(retention.load_history(directory)), 2)

    def test_invalid_partial_migration_does_not_delete_data(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            (directory / "articles.json").write_text(json.dumps({"articles":[item("https://example.org/a","2026-11-09T00:00:00Z")]}),encoding="utf-8")
            (directory / "recent.json").write_text(json.dumps({"articles":[]}),encoding="utf-8")
            with self.assertRaises(RuntimeError):
                retention.load_history(directory)
            (directory / "archives.json").write_text("{broken",encoding="utf-8")
            with self.assertRaises(RuntimeError):
                retention.load_history(directory)

    def test_all_sources_unavailable_preserves_previous_files(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            original = json.dumps({"articles":[item("https://example.org/a","2026-11-09T00:00:00Z")]})
            (directory / "articles.json").write_text(original,encoding="utf-8")
            with patch.object(collector, "DATA_DIR", directory), patch.object(collector, "fetch_feed", side_effect=RuntimeError("offline")):
                self.assertEqual(collector.main(), 1)
            self.assertEqual((directory / "articles.json").read_text(encoding="utf-8"), original)
            self.assertFalse((directory / "recent.json").exists())


if __name__ == "__main__":
    unittest.main()
