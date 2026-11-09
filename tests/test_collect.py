import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("collector", Path(__file__).resolve().parents[1] / "scripts" / "collect.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class CollectorTests(unittest.TestCase):
    def test_tracking_cleanup(self):
        self.assertEqual(module.canonical("https://example.org/a?x=1&utm_source=rss#hi"), "https://example.org/a?x=1")
        self.assertIsNone(module.canonical("javascript:alert(1)"))
    def test_rss_and_atom(self):
        rss = b"<rss><channel><item><title>Alerte</title><link>https://a.test/1</link><description>Information</description><pubDate>Mon, 09 Nov 2026 10:00:00 GMT</pubDate></item></channel></rss>"
        atom = b'<feed xmlns="http://www.w3.org/2005/Atom"><entry><title>Linux</title><link rel="alternate" href="https://a.test/2"/><summary>Update</summary><updated>2026-11-09T10:00:00Z</updated></entry></feed>'
        source = ("A", "https://a.test/feed", "Systèmes")
        self.assertEqual(module.parse_feed(rss, source)[0]["title"], "Alerte")
        self.assertEqual(module.parse_feed(atom, source)[0]["url"], "https://a.test/2")
    def test_sanitize(self):
        self.assertEqual(module.clean("<p>CVE &amp; Linux</p>"), "CVE & Linux")

if __name__ == "__main__":
    unittest.main()
