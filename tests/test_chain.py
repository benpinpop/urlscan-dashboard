"""TitanEye on-chain providers and /api/chain routes. No network, dummy keys only."""

import logging
import pathlib
import sys
import unittest

import requests

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import app as application  # noqa: E402
from chain_providers import ProviderError, decimal_string, iso_from_unix  # noqa: E402
from chain_providers.blockchain import BlockchainProvider, address_type  # noqa: E402
from chain_providers.etherscan import EtherscanProvider  # noqa: E402
from chain_providers.tronscan import TronscanProvider  # noqa: E402

ETH_KEY = "A" * 34
TRON_KEY = "11111111-2222-3333-4444-555555555555"
EVM = "0x719DeA9eA99AdCb55b7f03f2FC5CE9858cB13249"
TRX = "TDkAnyGrMH7xfGKdpwoVCzMroCCnbk9um3"
BTC = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"


class FakeResponse:
    def __init__(self, payload=None, status=200, bad_json=False):
        self.status_code = status
        self._payload = payload
        self._bad = bad_json

    def json(self):
        if self._bad:
            raise ValueError("not json")
        return self._payload


class FakeSession:
    """Answers by a function of the query params; records every call."""

    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    def get(self, url, params=None, headers=None, timeout=None, allow_redirects=True):
        self.calls.append({"url": url, "params": dict(params or {}), "headers": dict(headers or {})})
        result = self.handler(url, params or {}, headers or {})
        if isinstance(result, Exception):
            raise result
        return result


def etherscan_handler(contract=False):
    def handle(url, params, headers):
        action = params.get("action")
        if action == "balance":
            return FakeResponse({"status": "1", "message": "OK", "result": "1500000000000000000"})
        if action == "eth_getCode":
            return FakeResponse({"jsonrpc": "2.0", "id": 1, "result": "0x6080" if contract else "0x"})
        if action == "eth_getTransactionCount":
            return FakeResponse({"jsonrpc": "2.0", "id": 1, "result": "0x2a"})
        if action == "txlist":
            stamp = "1689074375" if params["sort"] == "asc" else "1695801083"
            return FakeResponse({"status": "1", "message": "OK", "result": [{"timeStamp": stamp}]})
        if action == "tokentx":
            rows = [
                {"contractAddress": "0xAA", "tokenSymbol": "USDT", "tokenName": "Tether\x07 USD"},
                {"contractAddress": "0xaa", "tokenSymbol": "USDT", "tokenName": "dup"},
                {"contractAddress": "0xBB", "tokenSymbol": "FREE $ CLAIM", "tokenName": "Scam"},
            ]
            return FakeResponse({"status": "1", "message": "OK", "result": rows})
        if action == "getsourcecode":
            return FakeResponse({"status": "1", "message": "OK",
                                 "result": [{"SourceCode": "contract X {}", "ContractName": "Vault"}]})
        raise AssertionError(f"unexpected action {action}")
    return handle


class EtherscanTests(unittest.TestCase):
    def provider(self, handler):
        session = FakeSession(handler)
        return EtherscanProvider("https://etherscan.test/v2/api", session=session, spacing=0), session

    def test_externally_owned_account(self):
        provider, session = self.provider(etherscan_handler())
        data = provider.summary("eth", EVM, ETH_KEY)
        self.assertEqual(data["address_type"], "Externally owned account")
        self.assertEqual(data["balance"], "1.5")
        self.assertEqual(data["native_symbol"], "ETH")
        self.assertEqual(data["sent_tx_count"], 42)
        self.assertEqual(data["first_seen"], "2023-07-11T11:19:35Z")
        self.assertTrue(data["last_seen"] > data["first_seen"])
        self.assertEqual([t["symbol"] for t in data["tokens_seen"]], ["USDT", "FREE $ CLAIM"])
        self.assertNotIn("\x07", data["tokens_seen"][0]["name"])
        self.assertIsNone(data["contract_name"])
        self.assertTrue(data["explorer_url"].endswith(EVM))
        self.assertTrue(all(call["params"]["chainid"] == 1 for call in session.calls))

    def test_contract_reports_name_and_verification(self):
        provider, _ = self.provider(etherscan_handler(contract=True))
        data = provider.summary("eth", EVM, ETH_KEY)
        self.assertEqual(data["address_type"], "Contract")
        self.assertEqual(data["contract_name"], "Vault")
        self.assertTrue(data["contract_verified"])

    def test_chain_ids(self):
        provider, session = self.provider(etherscan_handler())
        provider.summary("arb", EVM, ETH_KEY)
        self.assertEqual(session.calls[0]["params"]["chainid"], 42161)
        with self.assertRaises(ProviderError) as ctx:
            provider.summary("btc", EVM, ETH_KEY)
        self.assertEqual(ctx.exception.code, "provider_unsupported_chain")

    def test_no_records_is_not_an_error(self):
        def handle(url, params, headers):
            if params.get("action") in ("txlist", "tokentx"):
                return FakeResponse({"status": "0", "message": "No transactions found", "result": []})
            return etherscan_handler()(url, params, headers)
        provider, _ = self.provider(handle)
        data = provider.summary("eth", EVM, ETH_KEY)
        self.assertIsNone(data["first_seen"])
        self.assertEqual(data["tokens_seen"], [])

    def test_error_texts_map_to_codes(self):
        cases = {
            "Max rate limit reached": ("provider_rate_limited", 429),
            "Invalid API Key": ("provider_key_invalid", 401),
            "Free API access is not supported for this chain. Please upgrade your api plan": ("provider_plan_unsupported", 403),
            "Something else": ("provider_error", 502),
        }
        for text, (code, status) in cases.items():
            provider, _ = self.provider(lambda u, p, h, t=text: FakeResponse({"status": "0", "message": "NOTOK", "result": t}))
            with self.assertRaises(ProviderError) as ctx:
                provider.summary("eth", EVM, ETH_KEY)
            self.assertEqual((ctx.exception.code, ctx.exception.status), (code, status), text)

    def test_transport_errors_never_leak_the_key(self):
        leaky = requests.exceptions.ConnectionError(f"HTTPSConnectionPool: /v2/api?apikey={ETH_KEY}&address={EVM}")
        provider, _ = self.provider(lambda u, p, h: leaky)
        stream = []

        class Capture(logging.Handler):
            def emit(self, record):
                stream.append(record.getMessage())

        handler = Capture()
        logger = logging.getLogger("urlscan-dashboard")
        logger.addHandler(handler)
        try:
            with self.assertRaises(ProviderError) as ctx:
                provider.summary("eth", EVM, ETH_KEY)
        finally:
            logger.removeHandler(handler)
        self.assertNotIn(ETH_KEY, ctx.exception.message)
        self.assertNotIn(ETH_KEY, " ".join(stream))
        provider, _ = self.provider(lambda u, p, h: requests.exceptions.Timeout(ETH_KEY))
        with self.assertRaises(ProviderError) as ctx:
            provider.summary("eth", EVM, ETH_KEY)
        self.assertEqual(ctx.exception.code, "provider_timeout")
        self.assertNotIn(ETH_KEY, ctx.exception.message)

    def test_http_and_json_failures(self):
        for response, code in ((FakeResponse(status=429), "provider_rate_limited"),
                               (FakeResponse(status=500), "provider_error"),
                               (FakeResponse(bad_json=True), "provider_error"),
                               (FakeResponse(payload=[1, 2]), "provider_error")):
            provider, _ = self.provider(lambda u, p, h, r=response: r)
            with self.assertRaises(ProviderError) as ctx:
                provider.summary("eth", EVM, ETH_KEY)
            self.assertEqual(ctx.exception.code, code)


class BlockchainTests(unittest.TestCase):
    def provider(self, handler):
        session = FakeSession(handler)
        return BlockchainProvider("https://bc.test", session=session), session

    def test_summary_totals_and_first_seen(self):
        def handle(url, params, headers):
            offset = params.get("offset", 0)
            stamp = 1231006505 if offset else 1700000000
            return FakeResponse({"n_tx": 3, "final_balance": 150000000, "total_received": 250000000,
                                 "total_sent": 100000000, "txs": [{"time": stamp}]})
        provider, session = self.provider(handle)
        data = provider.summary("btc", BTC)
        self.assertEqual(data["balance"], "1.5")
        self.assertEqual(data["total_received"], "2.5")
        self.assertEqual(data["total_sent"], "1")
        self.assertEqual(data["tx_count"], 3)
        self.assertEqual(data["first_seen"], "2009-01-03T18:15:05Z")
        self.assertEqual(session.calls[1]["params"]["offset"], 2)
        self.assertNotIn("api_code", session.calls[0]["params"])

    def test_key_sent_as_api_code_only_when_given(self):
        provider, session = self.provider(lambda u, p, h: FakeResponse({"n_tx": 0, "final_balance": 0,
                                                                         "total_received": 0, "total_sent": 0, "txs": []}))
        data = provider.summary("btc", BTC, "abcd1234efgh")
        self.assertEqual(session.calls[0]["params"]["api_code"], "abcd1234efgh")
        self.assertIsNone(data["first_seen"])
        self.assertEqual(len(session.calls), 1)

    def test_errors(self):
        for status, code in ((429, "provider_rate_limited"), (404, "provider_error"), (500, "provider_error")):
            provider, _ = self.provider(lambda u, p, h, s=status: FakeResponse(status=s))
            with self.assertRaises(ProviderError) as ctx:
                provider.summary("btc", BTC)
            self.assertEqual(ctx.exception.code, code)
        provider, _ = self.provider(lambda u, p, h: requests.exceptions.ConnectionError(f"x api_code=SECRETKEY1"))
        with self.assertRaises(ProviderError) as ctx:
            provider.summary("btc", BTC)
        self.assertNotIn("SECRETKEY1", ctx.exception.message)

    def test_address_types(self):
        self.assertEqual(address_type("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"), "Legacy (P2PKH)")
        self.assertEqual(address_type("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"), "P2SH")
        self.assertEqual(address_type("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"), "Native SegWit (P2WPKH)")
        self.assertEqual(address_type("bc1p" + "q" * 58), "Taproot (P2TR)")


class TronscanTests(unittest.TestCase):
    PAYLOAD = {
        "balance": 72028846,
        "totalTransactionCount": 5,
        "transactions_in": 4,
        "transactions_out": 0,
        "date_created": 1692470574000,
        "latest_operation_time": 1752250890000,
        "redTag": "Scam <b>tag</b>",
        "greyTag": "",
        "feedbackRisk": True,
        "withPriceTokens": [
            {"tokenId": "_", "balance": "72028846", "tokenDecimal": 6, "tokenAbbr": "trx"},
            {"tokenId": "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", "balance": "300000000", "tokenDecimal": 6,
             "tokenAbbr": "USDT", "tokenName": "Tether USD", "tokenType": "trc20"},
            {"tokenId": "bad", "balance": "x", "tokenDecimal": 6, "tokenAbbr": "BAD"},
        ],
    }

    def test_summary(self):
        session = FakeSession(lambda u, p, h: FakeResponse(self.PAYLOAD))
        data = TronscanProvider("https://tron.test", session=session).summary("trx", TRX, TRON_KEY)
        self.assertEqual(data["balance"], "72.028846")
        self.assertEqual((data["tx_count"], data["tx_in"], data["tx_out"]), (5, 4, 0))
        self.assertEqual(data["first_seen"], "2023-08-19T18:42:54Z")
        self.assertEqual(data["token_balances"], [{"symbol": "USDT", "name": "Tether USD",
                                                    "contract": "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
                                                    "balance": "300", "type": "trc20"}])
        self.assertIn("Reported as risky on Tronscan", data["tags"])
        self.assertEqual(session.calls[0]["headers"]["TRON-PRO-API-KEY"], TRON_KEY)

    def test_errors_map(self):
        for status, code in ((429, "provider_rate_limited"), (401, "provider_key_invalid"), (500, "provider_error")):
            provider = TronscanProvider("https://tron.test", session=FakeSession(lambda u, p, h, s=status: FakeResponse(status=s)))
            with self.assertRaises(ProviderError) as ctx:
                provider.summary("trx", TRX, TRON_KEY)
            self.assertEqual(ctx.exception.code, code)


class HelperTests(unittest.TestCase):
    def test_decimal_string_has_no_float_rounding(self):
        self.assertEqual(decimal_string(1, 18), "0.000000000000000001")
        self.assertEqual(decimal_string(1500000000000000000, 18), "1.5")
        self.assertEqual(decimal_string(0, 8), "0")
        self.assertEqual(decimal_string(123456789, 8), "1.23456789")

    def test_iso_from_unix_rejects_junk(self):
        self.assertIsNone(iso_from_unix("x"))
        self.assertIsNone(iso_from_unix(None))
        self.assertEqual(iso_from_unix(0), "1970-01-01T00:00:00Z")

    def test_log_scrubber_redacts_key_parameters(self):
        record = logging.LogRecord("x", logging.INFO, "f", 1, f"GET /v2/api?chainid=1&apikey={ETH_KEY}&x=1 api_code=SECRETKEY1", (), None)
        application.ScrubSecrets().filter(record)
        self.assertNotIn(ETH_KEY, record.msg)
        self.assertNotIn("SECRETKEY1", record.msg)


class StubProvider:
    def __init__(self, name, chains, needs_key=False):
        self.name = name
        self.chains = chains
        self.needs_key = needs_key
        self.calls = []
        self.error = None

    def capabilities(self):
        return {"chains": list(self.chains), "needs_key": self.needs_key}

    def summary(self, chain, address, key):
        self.calls.append((chain, address, key))
        if self.error:
            raise self.error
        return {"provider": self.name, "chain": chain, "address": address, "balance": "1"}


class RouteTests(unittest.TestCase):
    def setUp(self):
        self.real = application.CHAIN_PROVIDERS
        self.eth = StubProvider("etherscan", ("eth", "arb"), needs_key=True)
        self.btc = StubProvider("blockchain", ("btc",))
        self.trx = StubProvider("tronscan", ("trx",), needs_key=True)
        application.CHAIN_PROVIDERS = {"etherscan": self.eth, "blockchain": self.btc, "tronscan": self.trx}
        application.CHAIN_CACHE.clear()
        application.chain_limiter._hits.clear()
        application.app.config["TESTING"] = True
        self.http = application.app.test_client()

    def tearDown(self):
        application.CHAIN_PROVIDERS = self.real

    def post(self, body, headers=None):
        response = self.http.post("/api/chain/summary", json=body, headers=headers or {})
        return response, response.get_json()

    def test_providers_listing_has_no_keys(self):
        response = self.http.get("/api/chain/providers")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(set(response.get_json()["providers"]), {"etherscan", "blockchain", "tronscan"})

    def test_etherscan_needs_a_key_and_validates_its_shape(self):
        response, body = self.post({"chain": "eth", "address": EVM})
        self.assertEqual((response.status_code, body["error"]["code"]), (401, "provider_key_missing"))
        response, body = self.post({"chain": "eth", "address": EVM}, {"X-Etherscan-Key": "short key!"})
        self.assertEqual((response.status_code, body["error"]["code"]), (400, "provider_key_invalid"))
        self.assertEqual(self.eth.calls, [])

    def test_key_reaches_the_provider_but_never_the_response_or_cache(self):
        response, body = self.post({"chain": "eth", "address": EVM}, {"X-Etherscan-Key": ETH_KEY})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.eth.calls[0][2], ETH_KEY)
        self.assertNotIn(ETH_KEY, response.get_data(as_text=True))
        self.assertFalse(body["meta"]["cached"])
        for cache_key in application.CHAIN_CACHE:
            self.assertNotIn(ETH_KEY, repr(cache_key))
        # A repeat lookup is served from the cache without calling the provider again.
        response, body = self.post({"chain": "eth", "address": EVM}, {"X-Etherscan-Key": ETH_KEY})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(body["meta"]["cached"])
        self.assertEqual(len(self.eth.calls), 1)

    def test_bitcoin_works_without_a_key(self):
        response, _ = self.post({"chain": "btc", "address": BTC})
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(self.btc.calls[0][2])

    def test_tronscan_needs_a_key(self):
        response, body = self.post({"chain": "trx", "address": TRX})
        self.assertEqual((response.status_code, body["error"]["code"]), (401, "provider_key_missing"))
        response, body = self.post({"chain": "trx", "address": TRX}, {"X-Tronscan-Key": "no"})
        self.assertEqual((response.status_code, body["error"]["code"]), (400, "provider_key_invalid"))
        response, _ = self.post({"chain": "trx", "address": TRX}, {"X-Tronscan-Key": TRON_KEY})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.trx.calls[0][2], TRON_KEY)

    def test_validation_before_any_provider_call(self):
        cases = [
            ({"chain": "nope", "address": EVM}, "unsupported_chain"),
            ({"chain": "eth", "address": "0x123"}, "invalid_wallet"),
            ({"chain": "eth"}, "invalid_body"),
            ({"chain": "ltc", "address": "LaMT348PWRnrqeeWArpwQPbuanpXDZGEUz"}, "provider_unsupported_chain"),
        ]
        for body, code in cases:
            response, data = self.post(body, {"X-Etherscan-Key": ETH_KEY})
            self.assertEqual(data["error"]["code"], code, body)
        self.assertEqual(self.eth.calls, [])

    def test_provider_errors_pass_through_with_retry_after(self):
        self.btc.error = ProviderError("slow down", 429, "provider_rate_limited", retry_after=10)
        response, body = self.post({"chain": "btc", "address": BTC})
        self.assertEqual(response.status_code, 429)
        self.assertEqual(body["error"]["code"], "provider_rate_limited")
        self.assertEqual(body["error"]["retry_after"], 10)
        self.assertEqual(len(application.CHAIN_CACHE), 0)

    def test_local_rate_limit(self):
        original = application.chain_limiter.per_minute
        application.chain_limiter.per_minute = 2
        try:
            codes = [self.post({"chain": "btc", "address": BTC})[0].status_code for _ in range(4)]
        finally:
            application.chain_limiter.per_minute = original
        self.assertEqual(codes[:2], [200, 200])
        self.assertEqual(codes[3], 429)


if __name__ == "__main__":
    unittest.main()
