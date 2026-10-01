"""Scambusters reporter routes, with the Scambusters API stubbed out.

Covers the wallet-check contract the form depends on, local re-validation, the
exact payload forwarded upstream, and that every upstream status and body is
relayed unchanged. Nothing here reaches the network.
"""

import logging
import pathlib
import sys
import unittest
from unittest import mock

import requests

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import app as application  # noqa: E402
import scambusters  # noqa: E402
from scambusters import ScambustersNetworkError, build_submission, site_hostname  # noqa: E402

SB_KEY = "sb_0123456789abcdef0123456789abcdef"
ETH = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
XRP = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"
BTC = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"


class StubScambusters:
    def __init__(self):
        self.calls = []
        self.reply = (201, {"submission_id": "cb48", "submission_key": "2372", "queued_ts_utc": "2026-03-19T16:15:23Z",
                            "site_url": "https://example-scam.com", "wallet_count": 1, "status": "queued"}, None)
        self.error = None

    def submit(self, api_key, payload):
        self.calls.append(("submit", api_key, payload))
        if self.error:
            raise self.error
        return self.reply

    def check(self, api_key, site_url):
        self.calls.append(("check", api_key, site_url))
        if self.error:
            raise self.error
        return self.reply


class ReporterRouteTests(unittest.TestCase):
    def setUp(self):
        self.stub = StubScambusters()
        self.real = application.scambusters_client
        application.scambusters_client = self.stub
        application.scambusters_limiter._hits.clear()
        application.app.config["TESTING"] = True
        self.http = application.app.test_client()

    def tearDown(self):
        application.scambusters_client = self.real

    def submit(self, body, key=SB_KEY):
        headers = {"X-Scambusters-Key": key} if key else {}
        response = self.http.post("/api/scambusters/submit", json=body, headers=headers)
        return response, response.get_json()

    # -- /api/wallets/check ---------------------------------------------------

    def check_wallet(self, address, chain=""):
        return self.http.post("/api/wallets/check", json={"address": address, "chain": chain}).get_json()

    def test_wallet_check_detects_and_defaults_0x_to_eth(self):
        body = self.check_wallet(ETH.lower())
        self.assertTrue(body["valid"])
        self.assertEqual((body["chain"], body["canonical"]), ("eth", ETH))
        self.assertEqual(body["detected"]["candidates"], ["eth", "bsc", "matic", "arb", "avax", "op"])
        self.assertFalse(body["requires_tag"])

    def test_wallet_check_honours_a_compatible_override(self):
        self.assertTrue(self.check_wallet(ETH, "matic")["valid"])

    def test_wallet_check_blocks_an_incompatible_override(self):
        body = self.check_wallet(ETH, "ltc")
        self.assertFalse(body["valid"])
        self.assertIn("looks like a Ethereum", body["error"])

    def test_wallet_check_xrp_requires_a_tag(self):
        body = self.check_wallet(XRP)
        self.assertTrue(body["valid"] and body["requires_tag"])
        self.assertEqual(body["chain"], "xrp")

    def test_wallet_check_unknown_format(self):
        body = self.check_wallet("hello-world")
        self.assertFalse(body["valid"])
        self.assertEqual(body["chain"], "")
        self.assertIn("Unrecognised", body["error"])

    # -- /api/scambusters/submit: local checks -----------------------------------

    def test_missing_or_malformed_key_is_refused_locally(self):
        for key in ("", "not-a-key"):
            response, body = self.submit({"site_url": "scam.example"}, key=key)
            self.assertEqual(response.status_code, 401)
            self.assertEqual(body["source"], "local")
        self.assertEqual(self.stub.calls, [])

    def test_local_validation_errors_use_scambusters_field_paths(self):
        response, body = self.submit({"site_url": "", "wallets": [
            {"address": ETH, "chain": "fakecoin"},
            {"address": BTC[:-1] + "b", "chain": "btc"},
            {"address": XRP, "chain": "xrp"},
            {"address": ETH, "chain": "eth", "xrp_dest_tag": "5"},
            {"address": "=HYPERLINK(1)", "chain": "eth"},
        ]})
        self.assertEqual(response.status_code, 400)
        errors = body["errors"]
        self.assertEqual(errors[0], "site_url is required.")
        self.assertTrue(errors[1].startswith("wallets[0].chain 'fakecoin' is not recognized"))
        self.assertTrue(errors[2].startswith("wallets[1].address") and "checksum" in errors[2])
        self.assertTrue(errors[3].startswith("wallets[2].xrp_dest_tag"))
        self.assertTrue(errors[4].startswith("wallets[3].xrp_dest_tag is only used for XRP"))
        self.assertTrue(errors[5].startswith("wallets[4].address cannot start with"))
        self.assertEqual(self.stub.calls, [])

    def test_more_than_30_wallets_is_refused(self):
        response, body = self.submit({"site_url": "scam.example", "wallets": [{"address": ETH, "chain": "eth"}] * 31})
        self.assertEqual(response.status_code, 400)
        self.assertIn("maximum is 30", body["errors"][-1])

    def test_forwarded_payload_is_exact(self):
        response, body = self.submit({"site_url": "scam.example/login", "wallets": [
            {"address": ETH.lower(), "chain": "eth", "xrp_dest_tag": ""},
            {"address": XRP, "chain": "xrp", "xrp_dest_tag": " 0042 "},
            {"address": "1BpEi6DfDAUFd7GtittLSdBeYJvcoaVggu", "chain": "bch"},
        ]})
        self.assertEqual(response.status_code, 201)
        (_, key, payload), = self.stub.calls
        self.assertEqual(key, SB_KEY)
        self.assertEqual(payload, {"site_url": "scam.example/login", "wallets": [
            {"address": ETH, "chain": "eth"},                                   # checksummed, no tag key
            {"address": XRP, "chain": "xrp", "xrp_dest_tag": "42"},
            {"address": "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a", "chain": "bch"},
        ]})

    def test_site_only_submission_omits_wallets(self):
        self.submit({"site_url": "scam.example", "wallets": []})
        self.assertEqual(self.stub.calls[0][2], {"site_url": "scam.example"})

    # -- upstream statuses are relayed unchanged ----------------------------------

    def test_every_upstream_status_is_relayed(self):
        replies = [
            (200, {"submission_key": "23723be411", "status": "duplicate"}),
            (400, {"errors": ["wallets[0].chain 'fakecoin' is not recognized."]}),
            (401, {"error": "Invalid or revoked API key."}),
            (403, {"error": "Your API key has expired. Use /rotate-api-key in Discord to get a new one."}),
            (403, {"error": "Your API key cannot submit to /api/submit yet. Share your scraper/auto-submit source "
                            "code with Sam for review to get added to the approval list."}),
            (503, {"error": "Submit approval check is temporarily unavailable. Please retry in a moment."}),
            (500, {"error": "Internal server error. Please retry or contact support."}),
        ]
        for status, body in replies:
            with self.subTest(status=status, body=body):
                self.stub.reply = (status, body, None)
                response, got = self.submit({"site_url": "scam.example"})
                self.assertEqual((response.status_code, got), (status, body))

    def test_rate_limit_passes_retry_after_through(self):
        self.stub.reply = (429, {"error": "Rate limit exceeded: 50 submissions per minute."}, "17")
        response, body = self.submit({"site_url": "scam.example"})
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.headers["Retry-After"], "17")

    def test_network_failure_becomes_504(self):
        self.stub.error = ScambustersNetworkError("Scambusters did not answer in time. Please retry.")
        response, body = self.submit({"site_url": "scam.example"})
        self.assertEqual(response.status_code, 504)
        self.assertEqual(body["source"], "proxy")

    def test_key_is_never_echoed(self):
        for status in (201, 401, 500):
            self.stub.reply = (status, {"error": "x"}, None)
            response, _ = self.submit({"site_url": "scam.example"})
            self.assertNotIn(SB_KEY, response.get_data(as_text=True))

    # -- /api/scambusters/check -------------------------------------------------

    def test_check_forwards_and_relays(self):
        self.stub.reply = (200, {"site_url": "https://scamsite.com", "site_key": "scamsite.com", "has_wallets": True,
                                 "latest_wallet_collected_utc": "2026-03-15T12:30:00Z", "stale": False}, None)
        response = self.http.get("/api/scambusters/check?site_url=www.ScamSite.com",
                                 headers={"X-Scambusters-Key": SB_KEY})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["has_wallets"])
        self.assertEqual(self.stub.calls, [("check", SB_KEY, "www.ScamSite.com")])

    def test_check_validates_locally(self):
        for query, message in (("", "required"), ("?site_url=not a url", "not a valid URL")):
            response = self.http.get("/api/scambusters/check" + query, headers={"X-Scambusters-Key": SB_KEY})
            self.assertEqual(response.status_code, 400)
            self.assertIn(message, response.get_json()["error"])
        self.assertEqual(self.stub.calls, [])

    def test_local_limiter_is_separate_from_search_limiter(self):
        application.limiter._hits.clear()
        with mock.patch.object(application.scambusters_limiter, "per_minute", 2):
            codes = [self.submit({"site_url": "scam.example"})[0].status_code for _ in range(3)]
        self.assertEqual(codes, [201, 201, 429])
        self.assertEqual(dict(application.limiter._hits), {})


class HelperTests(unittest.TestCase):
    def test_site_hostname(self):
        for good, host in (("scam.example", "scam.example"), ("https://www.Scam.example/x?y=1", "www.scam.example"),
                           ("http://scäm.example", "scäm.example"), ("scam.example:8443/a", "scam.example")):
            self.assertEqual(site_hostname(good), host)
        for bad in ("", "localhost", "https://", "not a url", "ftp://scam.example", "https://scam..example",
                    "scam.example:99999", "javascript:alert(1)"):
            with self.subTest(bad=bad):
                self.assertIsNone(site_hostname(bad))

    def test_build_submission_rejects_non_objects(self):
        self.assertEqual(build_submission([])[1], ["The request body must be a JSON object."])
        self.assertIn("wallets must be a list.", build_submission({"site_url": "a.example", "wallets": "x"})[1])

    def test_log_scrubber_redacts_scambusters_keys(self):
        record = logging.LogRecord("t", logging.INFO, __file__, 1, "key=%s", (SB_KEY,), None)
        application.ScrubSecrets().filter(record)
        self.assertNotIn(SB_KEY, record.getMessage())


class ClientTests(unittest.TestCase):
    def client_with(self, response=None, error=None):
        client = scambusters.ScambustersClient("https://sb.example/", timeout=3)
        session = mock.Mock()
        if error:
            session.request.side_effect = error
        else:
            session.request.return_value = response
        client._session = session
        return client, session

    @staticmethod
    def response(status, body=None, text_only=False, headers=None):
        r = mock.Mock(status_code=status, headers=headers or {})
        if text_only:
            r.json.side_effect = ValueError("not json")
        else:
            r.json.return_value = body
        return r

    def test_sends_bearer_header_and_exact_request(self):
        client, session = self.client_with(self.response(201, {"status": "queued"}))
        self.assertEqual(client.submit(SB_KEY, {"site_url": "a.example"}), (201, {"status": "queued"}, None))
        args, kwargs = session.request.call_args
        self.assertEqual(args, ("POST", "https://sb.example/api/submit"))
        self.assertEqual(kwargs["headers"], {"Authorization": f"Bearer {SB_KEY}"})
        self.assertEqual(kwargs["json"], {"site_url": "a.example"})
        self.assertFalse(kwargs["allow_redirects"])

    def test_check_uses_query_parameter(self):
        client, session = self.client_with(self.response(200, {"has_wallets": False}))
        client.check(SB_KEY, "a.example")
        args, kwargs = session.request.call_args
        self.assertEqual((args, kwargs["params"]), (("GET", "https://sb.example/api/check"), {"site_url": "a.example"}))

    def test_unreadable_success_becomes_502_but_errors_keep_status(self):
        client, _ = self.client_with(self.response(201, text_only=True))
        self.assertEqual(client.submit(SB_KEY, {})[0], 502)
        client, _ = self.client_with(self.response(503, text_only=True))
        status, body, _ = client.submit(SB_KEY, {})
        self.assertEqual(status, 503)
        self.assertIn("could not read", body["error"])

    def test_timeouts_and_connection_errors(self):
        for error in (requests.Timeout(), requests.ConnectionError()):
            client, _ = self.client_with(error=error)
            with self.assertRaises(ScambustersNetworkError):
                client.submit(SB_KEY, {})


if __name__ == "__main__":
    unittest.main()
