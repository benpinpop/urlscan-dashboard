"""Tests for the analyzer's shared scoring and shaping data.

No network and no API key: the result document comes from
``tests/fixture_result.json`` and the DOM from a literal string. Run with

    python3 -m unittest discover -s tests -v
"""

import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from domain_intel import DomainTable, registrable_domain  # noqa: E402
from keyword_db import KeywordDatabase, band_for, extract_text  # noqa: E402
from result_shaper import shape_files, shape_result, shape_verdicts, summarise  # noqa: E402

FIXTURE = json.loads((ROOT / "tests" / "fixture_result.json").read_text(encoding="utf-8"))

SCAM_PAGE = """
<html><head><title>CloudMine Pro</title>
<style>body{color:#fff}</style>
<script>var password_reset = true; console.log("guaranteed profit");</script></head>
<body>
<h1>Guaranteed Daily Returns</h1>
<p>Earn 3% daily with our AI trading bot. 100% safe and risk-free.
Minimum deposit 100 USDT on TRC20. Withdraw anytime, no lock-in period.</p>
<p>Invite friends for a 10% referral commission. Limited slots remaining, act now!</p>
<p>Our smart contract is audited by CertiK. Licensed and regulated.</p>
<p>Support is on Telegram only. Pay the withdrawal fee to release your balance.</p>
<p>For account help, use the normal password reset form.</p>
</body></html>
"""

BENIGN_PAGE = """
<html><head><title>Ledgerly Accounting</title></head><body>
<h1>Invoicing for small teams</h1>
<p>Ledgerly helps you send invoices, reconcile payments and run payroll.
Our support team can help you with a password reset or a billing question.
Read the documentation, or book a demo with the sales team.</p>
<p>We publish our uptime history and our security practices. Pricing starts at
nine euros a month, billed annually, and you can cancel whenever you like.</p>
</body></html>
"""


class TextExtraction(unittest.TestCase):
    def test_scripts_and_styles_are_dropped(self):
        extracted = extract_text(SCAM_PAGE)
        self.assertNotIn("console.log", extracted["text"])
        self.assertNotIn("color:#fff", extracted["text"])
        self.assertEqual(extracted["title"], "CloudMine Pro")

    def test_whitespace_is_normalised(self):
        extracted = extract_text("<p>a    b\n\n\n\nc</p>")
        self.assertNotIn("    ", extracted["text"])

    def test_attribute_text_is_kept_with_separators(self):
        extracted = extract_text('<button title="act now">Deposit</button>')
        self.assertIn("act now", extracted["text"])
        self.assertIn("Deposit", extracted["text"])

    def test_curly_apostrophes_are_normalised(self):
        extracted = extract_text("<p>don’t miss out</p>")
        self.assertIn("don't miss out", extracted["text"])

    def test_cap_reports_dropped_characters(self):
        extracted = extract_text("<p>" + ("word " * 500) + "</p>", max_chars=100)
        self.assertEqual(len(extracted["text"]), 100)
        self.assertGreater(extracted["truncated_chars"], 0)

    def test_malformed_html_does_not_raise(self):
        extracted = extract_text("<div><p>text<div><span>more")
        self.assertIn("text", extracted["text"])


class Scoring(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.db = KeywordDatabase.load()

    def test_database_loads(self):
        summary = self.db.summary()
        self.assertGreater(summary["keyword_count"], 400)
        self.assertGreater(summary["category_count"], 10)

    def test_scam_page_scores_high(self):
        result = self.db.score_text(extract_text(SCAM_PAGE)["text"])
        self.assertGreaterEqual(result["score"], 70)
        self.assertEqual(result["band"], "high")
        self.assertGreater(result["category_breadth"], 4)
        self.assertGreater(result["signal_points"], 4)

    def test_benign_page_scores_minimal(self):
        result = self.db.score_text(extract_text(BENIGN_PAGE)["text"])
        self.assertLess(result["score"], 15)
        self.assertEqual(result["band"], "minimal")

    def test_word_boundaries_prevent_substring_matches(self):
        result = self.db.score_text("Please use the password reset link to pass the check.")
        matched = {match["keyword"] for match in result["matches"]}
        self.assertNotIn("pass", matched)

    def test_punctuation_keywords_still_match(self):
        result = self.db.score_text("We pay 3% daily and the plan is 100% safe.")
        matched = {match["keyword"] for match in result["matches"]}
        self.assertIn("3% daily", matched)
        self.assertIn("100% safe", matched)

    def test_longest_phrase_wins(self):
        result = self.db.score_text("This is a get rich quick scheme.")
        matched = {match["keyword"] for match in result["matches"]}
        self.assertIn("get rich quick", matched)

    def test_repetition_adds_a_bounded_bonus(self):
        once = self.db.score_text("guaranteed profit " + ("filler " * 200))
        many = self.db.score_text(("guaranteed profit " * 40) + ("filler " * 200))
        self.assertGreater(many["score"], once["score"])
        # One keyword, repeated: worth its tier value plus at most 40% again.
        self.assertLessEqual(many["signal_points"], 1.25 * 1.4 + 0.001)

    def test_score_ignores_page_length(self):
        claim = "Earn 3% daily, guaranteed profit, risk-free. Pay the withdrawal fee to release."
        short = self.db.score_text(claim)
        padded = self.db.score_text(claim + " " + ("ordinary filler wording " * 400))
        self.assertAlmostEqual(short["score"], padded["score"], delta=0.1)

    def test_topic_vocabulary_alone_scores_nothing(self):
        result = self.db.score_text(
            "We support bitcoin, ethereum, USDT, TRC20, ERC20, blockchain and web3 wallets."
        )
        self.assertEqual(result["signal_points"], 0.0)
        self.assertEqual(result["score"], 0.0)
        self.assertGreater(result["context_keywords"], 3)
        self.assertEqual(result["unique_keywords"], 0)

    def test_a_legitimate_crypto_page_stays_out_of_the_high_band(self):
        page = (
            "Buy and hold bitcoin, ethereum and USDC. Our exchange is registered with FinCEN. "
            "Staking rewards are variable and depend on network conditions; the estimated APY "
            "is not guaranteed and digital assets are volatile, so you can lose money. We will "
            "never ask for your password or your seed phrase. Two-factor authentication is "
            "required for withdrawals and fees are published in full."
        )
        result = self.db.score_text(page)
        self.assertLess(result["score"], 40, "a regulated exchange must not read as a scam")

    def test_score_is_bounded(self):
        result = self.db.score_text("guaranteed profit risk-free 100% safe " * 50)
        self.assertLessEqual(result["score"], 100)
        self.assertGreaterEqual(result["score"], 0)

    def test_empty_text_scores_zero(self):
        result = self.db.score_text("")
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["matches"], [])

    def test_matches_carry_locations(self):
        result = self.db.score_text(extract_text(SCAM_PAGE)["text"])
        top = result["matches"][0]
        self.assertTrue(top["locations"])
        self.assertIn("excerpt", top["locations"][0])
        self.assertGreaterEqual(top["locations"][0]["line"], 1)

    def test_bands(self):
        self.assertEqual(band_for(0), "minimal")
        self.assertEqual(band_for(20), "low")
        self.assertEqual(band_for(50), "elevated")
        self.assertEqual(band_for(95), "high")


class DomainClassification(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.table = DomainTable.load()

    def test_table_loads(self):
        self.assertGreater(self.table.size, 100)

    def test_suffix_match_is_anchored_on_a_label(self):
        self.assertEqual(self.table.classify("d1.cloudfront.net")["category"], "cdn")
        self.assertEqual(self.table.classify("notcloudfront.net")["category"], "unknown")

    def test_path_patterns_beat_host_patterns(self):
        verdict = self.table.classify("www.google.com", "/recaptcha/api.js")
        self.assertEqual(verdict["category"], "captcha")

    def test_first_party_wins(self):
        verdict = self.table.classify("shop.example.com", "", apex="example.com")
        self.assertTrue(verdict["is_first_party"])
        self.assertEqual(verdict["category"], "first_party")

    def test_registrable_domain(self):
        self.assertEqual(registrable_domain("a.b.example.com"), "example.com")
        self.assertEqual(registrable_domain("shop.example.co.uk"), "example.co.uk")
        self.assertEqual(registrable_domain("203.0.113.42"), "203.0.113.42")


class ResultShaping(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.table = DomainTable.load()
        cls.payload = shape_result(FIXTURE, cls.table)

    def test_summary_fields(self):
        summary = self.payload["summary"]
        self.assertEqual(summary["domain"], "www.cloudmine-pro.example")
        self.assertEqual(summary["apex_domain"], "cloudmine-pro.example")
        self.assertEqual(summary["ip"], "203.0.113.42")
        self.assertEqual(summary["asn"], "AS64500")
        self.assertEqual(summary["status"], 200)
        self.assertEqual(summary["tls"]["valid_days"], 62)
        self.assertEqual(summary["tls"]["certificate"]["subject"], "*.cloudmine-pro.example")
        self.assertEqual(summary["counts"]["requests"], 6)
        self.assertEqual(summary["counts"]["ips"], 3)
        self.assertIn("Nginx", [tech["name"] for tech in summary["technologies"]])
        self.assertTrue(summary["screenshot_url"].endswith(".png"))

    def test_certificate_prefers_the_scanned_host(self):
        summary = summarise(FIXTURE)
        self.assertEqual(summary["tls"]["certificate"]["issuer"], "R11")

    def test_every_request_becomes_a_file_row(self):
        self.assertEqual(len(self.payload["files"]), 6)

    def test_hashes_are_validated_and_merged(self):
        by_name = {item["filename"]: item for item in self.payload["files"]}

        exe = by_name["Wallet-Setup.exe"]
        algorithms = [h["algorithm"] for h in exe["hashes"]]
        self.assertEqual(algorithms, ["sha256", "sha1", "md5"])
        self.assertTrue(exe["from_download_processor"])

        image = by_name["hero.png"]
        self.assertEqual(image["hashes"], [], "a malformed digest must not be surfaced")

    def test_failed_request_is_marked(self):
        failed = [item for item in self.payload["files"] if item["failed"]]
        self.assertEqual(len(failed), 1)
        self.assertIn("ERR_BLOCKED_BY_CLIENT", failed[0]["error"])

    def test_request_without_a_response_survives(self):
        telegram = [item for item in self.payload["files"] if item["domain"] == "t.me"]
        self.assertEqual(len(telegram), 1)
        self.assertIsNone(telegram[0]["status"])
        self.assertEqual(telegram[0]["category"], "social")

    def test_apex_flag(self):
        first_party = [item for item in self.payload["files"] if item["is_first_party"]]
        domains = {item["domain"] for item in first_party}
        self.assertEqual(domains, {"www.cloudmine-pro.example", "cdn.cloudmine-pro.example"})
        self.assertEqual(self.payload["file_stats"]["first_party"], 2)
        self.assertEqual(self.payload["file_stats"]["third_party"], 4)

    def test_headers_are_ordered_and_capped(self):
        document = self.payload["files"][0]
        self.assertEqual(document["headers"][0]["name"].lower(), "content-type")
        long_value = shape_files(
            {"data": {"requests": [{"response": {"response": {"headers": {"x-long": "a" * 900}}}}]}},
            self.table,
            None,
        )[0]["headers"][0]
        self.assertTrue(long_value["truncated"])
        self.assertLess(len(long_value["value"]), 900)

    def test_domains_are_classified_and_ranked(self):
        domains = {row["domain"]: row for row in self.payload["domains"]}
        self.assertEqual(domains["www.google-analytics.com"]["category"], "analytics")
        self.assertEqual(domains["www.google-analytics.com"]["service"], "Google Analytics")
        self.assertEqual(domains["d33v4339jhl8k0.cloudfront.net"]["country"], "Germany")
        self.assertTrue(domains["www.cloudmine-pro.example"]["is_first_party"])
        counts = [row["requests"] for row in self.payload["domains"]]
        self.assertEqual(counts, sorted(counts, reverse=True))

    def test_verdicts(self):
        verdicts = self.payload["verdicts"]
        self.assertTrue(verdicts["malicious"])
        self.assertEqual(verdicts["band"], "malicious")
        self.assertEqual(verdicts["threat_score"], 85)
        engines = {row["engine"]: row for row in verdicts["engines"]["rows"]}
        self.assertEqual(engines["ExampleEngineA"]["verdict"], "malicious")
        self.assertEqual(engines["ExampleEngineB"]["verdict"], "benign")
        self.assertIn("ExampleEngineC", engines, "name-only engine lists must be picked up")
        self.assertEqual(verdicts["community"]["votes_malicious"], 2)

    def test_empty_document_does_not_raise(self):
        payload = shape_result({}, self.table)
        self.assertEqual(payload["files"], [])
        self.assertEqual(payload["domains"], [])
        self.assertEqual(payload["verdicts"]["threat_score"], 0)
        self.assertEqual(payload["verdicts"]["band"], "clean")

    def test_clean_scan_reads_as_clean(self):
        verdicts = shape_verdicts({"verdicts": {
            "overall": {"score": 0, "malicious": False, "hasVerdicts": 0},
            "engines": {"score": 0, "enginesTotal": 4, "maliciousTotal": 0, "benign": ["A", "B"]},
        }})
        self.assertEqual(verdicts["band"], "clean")
        self.assertFalse(verdicts["malicious"])
        self.assertEqual(verdicts["engines"]["benign_total"], 2)


if __name__ == "__main__":
    unittest.main()
