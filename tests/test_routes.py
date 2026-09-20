"""Endpoint tests for the analyzer routes, with urlscan.io stubbed out.

These exercise validation, error mapping, caching and the JSON contract the
frontend depends on. Nothing here reaches the network.
"""

import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import app as application  # noqa: E402
from urlscan_client import UrlscanAuthError, UrlscanNotFoundError, UrlscanTooLargeError  # noqa: E402

FIXTURE = json.loads((ROOT / "tests" / "fixture_result.json").read_text(encoding="utf-8"))
UUID = "0f8e1c4a-2b3d-4e5f-8a9b-1c2d3e4f5a6b"
KEY = "0123456789abcdef0123456789abcdef"

DOM = """<html><head><title>CloudMine Pro</title></head><body>
<h1>Guaranteed Daily Returns</h1>
<p>Earn 3% daily, 100% safe and risk-free. Minimum deposit 100 USDT on TRC20.
Invite friends for a 10% referral commission. Limited slots remaining, act now.
Pay the withdrawal fee to release your balance. Support on Telegram only.</p>
</body></html>"""


class Stub:
    """Stands in for UrlscanClient, recording calls and replaying answers."""

    def __init__(self):
        self.result_calls = []
        self.dom_calls = []
        self.result_error = None
        self.dom_error = None
        self.dom_body = DOM

    def result(self, api_key, uuid):
        self.result_calls.append((api_key, uuid))
        if self.result_error:
            raise self.result_error
        return FIXTURE

    def dom(self, api_key, uuid, max_bytes=None):
        self.dom_calls.append((api_key, uuid))
        if self.dom_error:
            raise self.dom_error
        return self.dom_body


class RouteTests(unittest.TestCase):
    def setUp(self):
        self.stub = Stub()
        self.real_client = application.client
        application.client = self.stub
        application.RESULT_CACHE.clear()
        # Limiters are process-wide; a fresh one per test keeps them independent.
        application.limiter._hits.clear()
        application.analyze_limiter._hits.clear()
        application.app.config["TESTING"] = True
        self.http = application.app.test_client()

    def tearDown(self):
        application.client = self.real_client

    def get(self, path, key=KEY):
        headers = {"X-URLScan-Key": key} if key else {}
        response = self.http.get(path, headers=headers)
        return response, response.get_json()

    # -- /api/result ------------------------------------------------------

    def test_result_returns_shaped_payload(self):
        response, body = self.get(f"/api/result/{UUID}")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(body["ok"])
        self.assertEqual(body["summary"]["domain"], "www.cloudmine-pro.example")
        self.assertEqual(len(body["files"]), 6)
        self.assertEqual(body["verdicts"]["threat_score"], 85)
        self.assertFalse(body["meta"]["cached"])
        self.assertTrue(body["meta"]["content_analysis_available"])

    def test_result_is_cached_per_key(self):
        self.get(f"/api/result/{UUID}")
        _, body = self.get(f"/api/result/{UUID}")
        self.assertTrue(body["meta"]["cached"])
        self.assertEqual(len(self.stub.result_calls), 1)

        other = "f" * 32
        _, body = self.get(f"/api/result/{UUID}", key=other)
        self.assertFalse(body["meta"]["cached"], "a different key must not read the cache")
        self.assertEqual(len(self.stub.result_calls), 2)

    def test_bad_uuid_is_rejected_before_any_upstream_call(self):
        for bad in ["not-a-uuid", "../../etc/passwd", UUID + "extra", "0f8e1c4a2b3d4e5f8a9b1c2d3e4f5a6b"]:
            response, body = self.get(f"/api/result/{bad}")
            self.assertIn(response.status_code, (400, 404))
            if response.status_code == 400:
                self.assertEqual(body["error"]["code"], "invalid_uuid")
        self.assertEqual(self.stub.result_calls, [])

    def test_missing_key_is_reported(self):
        response, body = self.get(f"/api/result/{UUID}", key=None)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(body["error"]["code"], "missing_api_key")

    def test_malformed_key_is_reported(self):
        response, body = self.get(f"/api/result/{UUID}", key="short")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(body["error"]["code"], "malformed_api_key")

    def test_upstream_404_is_passed_through(self):
        self.stub.result_error = UrlscanNotFoundError("Scan is not finished yet")
        response, body = self.get(f"/api/result/{UUID}")
        self.assertEqual(response.status_code, 404)
        self.assertEqual(body["error"]["code"], "not_found")
        self.assertIn("not finished", body["error"]["message"])

    def test_upstream_401_is_passed_through(self):
        self.stub.result_error = UrlscanAuthError("bad key")
        response, body = self.get(f"/api/result/{UUID}")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(body["error"]["code"], "invalid_api_key")

    def test_api_responses_are_not_cached_by_proxies(self):
        response, _ = self.get(f"/api/result/{UUID}")
        self.assertEqual(response.headers["Cache-Control"], "no-store")

    # -- /api/analyze -----------------------------------------------------

    def test_analyze_scores_the_dom(self):
        response, body = self.get(f"/api/analyze/{UUID}")
        self.assertEqual(response.status_code, 200)
        self.assertFalse(body["empty"])
        self.assertGreater(body["analysis"]["score"], 50)
        self.assertEqual(body["analysis"]["band"], "high")
        self.assertGreater(body["analysis"]["unique_keywords"], 5)
        self.assertTrue(body["analysis"]["categories"])
        self.assertTrue(body["analysis"]["formula"])
        self.assertIn("triage", body["disclaimer"])
        self.assertEqual(body["text"]["title"], "CloudMine Pro")
        self.assertIn("Guaranteed Daily Returns", body["text"]["excerpt"])

    def test_analyze_handles_a_page_with_no_text(self):
        self.stub.dom_body = "<html><head></head><body><script>void 0</script></body></html>"
        response, body = self.get(f"/api/analyze/{UUID}")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(body["empty"])
        self.assertEqual(body["analysis"]["score"], 0)

    def test_analyze_reports_an_oversized_dom(self):
        self.stub.dom_error = UrlscanTooLargeError("too big")
        response, body = self.get(f"/api/analyze/{UUID}")
        self.assertEqual(response.status_code, 413)
        self.assertEqual(body["error"]["code"], "response_too_large")

    def test_analyze_reports_a_missing_dom(self):
        self.stub.dom_error = UrlscanNotFoundError("no dom")
        response, body = self.get(f"/api/analyze/{UUID}")
        self.assertEqual(response.status_code, 404)

    def test_analyze_has_its_own_rate_limit(self):
        limit = application.Config.ANALYZE_LIMIT_PER_MINUTE
        codes = [self.get(f"/api/analyze/{UUID}")[0].status_code for _ in range(limit + 3)]
        self.assertIn(429, codes)
        self.assertEqual(codes[0], 200)

    def test_analyze_rejects_a_bad_uuid(self):
        response, body = self.get("/api/analyze/nope")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(body["error"]["code"], "invalid_uuid")
        self.assertEqual(self.stub.dom_calls, [])

    # -- supporting endpoints --------------------------------------------

    def test_keyword_endpoint_describes_the_database(self):
        response, body = self.get("/api/keywords")
        self.assertEqual(response.status_code, 200)
        self.assertGreater(body["keyword_count"], 400)
        self.assertTrue(body["categories"])

    def test_config_advertises_the_analyzer(self):
        response, body = self.get("/api/config")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(body["analyzer"]["content_analysis_available"])
        self.assertGreater(body["analyzer"]["domain_patterns"], 100)

    def test_index_page_renders(self):
        response = self.http.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"analyzer", response.data.lower())


if __name__ == "__main__":
    unittest.main()
