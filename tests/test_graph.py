"""TitanEye graph builder and /api/graph routes, with urlscan.io stubbed out."""

import copy
import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import app as application  # noqa: E402
import graph_builder as gb  # noqa: E402
from query_terms import QueryTerms  # noqa: E402
from urlscan_client import UrlscanAuthError, UrlscanNotFoundError, normalise_result  # noqa: E402

KEY = "0123456789abcdef0123456789abcdef"
UUID_A = "11111111-2222-3333-4444-555555555555"
UUID_B = "66666666-7777-8888-9999-000000000000"

HITS = [
    {
        "task": {"uuid": UUID_A, "url": "https://a.example.com/", "time": "2025-01-02T00:00:00Z", "domain": "a.example.com"},
        "page": {"domain": "a.example.com", "apexDomain": "example.com", "ip": "203.0.113.5",
                 "asn": "AS64500", "asnname": "TEST-NET", "ptr": "host.test.net", "country": "NL",
                 "server": "nginx", "tlsIssuer": "Test CA", "status": "200"},
        "sort": [1735776000000, "x"],
    },
    {
        "task": {"uuid": UUID_B, "url": "https://b.example.com/", "time": "2025-01-05T00:00:00Z", "domain": "b.example.com"},
        "page": {"domain": "b.example.com", "apexDomain": "example.com", "ip": "203.0.113.5",
                 "asn": "AS64500", "tlsIssuer": "Test CA"},
        "sort": [1736035200000, "y"],
    },
]


class StubClient:
    def __init__(self):
        self.calls = []
        self.error = None
        self.has_more = False

    def search(self, api_key, query, size, search_after=None):
        self.calls.append((api_key, query, size, search_after))
        if self.error:
            raise self.error
        return {"results": HITS, "total": 2, "has_more": self.has_more, "took": 5}


class BuilderTests(unittest.TestCase):
    def test_every_transform_field_exists_in_query_terms(self):
        fields = {t["field"] for t in QueryTerms.load().browser_data()}
        for transform in gb.TRANSFORMS:
            self.assertIn(transform.field, fields, transform.id)

    def test_transform_ids_unique_and_types_known(self):
        ids = [t.id for t in gb.TRANSFORMS]
        self.assertEqual(len(ids), len(set(ids)))
        for transform in gb.TRANSFORMS:
            self.assertIn(transform.node_type, gb.NODE_TYPES)
            self.assertIn(transform.relation, gb.EDGE_TYPES)

    def test_query_built_from_template(self):
        query, transform, value = gb.build_query("ip_sites", "203.0.113.5")
        self.assertEqual(query, "page.ip:203.0.113.5")
        self.assertEqual(transform.id, "ip_sites")
        self.assertEqual(value, "203.0.113.5")

    def test_values_are_canonicalised(self):
        self.assertEqual(gb.build_query("apex_sites", "Example.COM.")[0], "page.apexDomain:example.com")
        self.assertEqual(gb.build_query("asn_sites", "64500")[0], "page.asn:AS64500")
        self.assertEqual(gb.build_query("contact_sites", "@scam_bot")[2], "scam_bot")

    def test_injection_attempts_are_rejected(self):
        cases = [
            ("filename_sites", 'x" OR domain:google.com'),
            ("text_sites", 'a\\" OR b'),
            ("tag_sites", "line\nbreak"),
            ("ip_sites", "1.2.3.4 OR page.ip:5.6.7.8"),
            ("apex_sites", "example.com OR domain:evil.com"),
            ("hash_sites", "abc"),
            ("cidr_sites", "10.0.0.0/8"),
            ("contact_sites", "x/.*|y"),
            ("wallet_sites", "not a wallet"),
        ]
        for transform, value in cases:
            with self.assertRaises(gb.GraphInputError, msg=f"{transform}: {value!r}"):
                gb.build_query(transform, value)

    def test_unknown_transform_and_empty_value(self):
        with self.assertRaises(gb.GraphInputError):
            gb.build_query("nope", "x")
        with self.assertRaises(gb.GraphInputError):
            gb.build_query("ip_sites", "  ")

    def test_free_query_passes_through_but_rejects_control_chars(self):
        query, transform, _ = gb.build_query("query", 'domain:"x.com" AND page.country:NL')
        self.assertIsNone(transform)
        self.assertIn("page.country:NL", query)
        with self.assertRaises(gb.GraphInputError):
            gb.build_query("query", "a\x00b")

    def test_shape_links_infrastructure_and_dedupes(self):
        rows = [normalise_result(h, i + 1) for i, h in enumerate(HITS)]
        query, transform, value = gb.build_query("ip_sites", "203.0.113.5")
        fragment = gb.shape_expansion(rows, query, transform, value)
        ids = {n["id"] for n in fragment["nodes"]}
        self.assertEqual(len(ids), len(fragment["nodes"]))
        for expected in ("site:a.example.com", "site:b.example.com", "apex_domain:example.com",
                         "ip:203.0.113.5", "asn:AS64500", "ptr:host.test.net",
                         "tls_cert:Test CA", "tech:nginx"):
            self.assertIn(expected, ids)
        edge_ids = {e["id"] for e in fragment["edges"]}
        self.assertEqual(len(edge_ids), len(fragment["edges"]))
        self.assertIn("site:a.example.com|resolves_to|ip:203.0.113.5", edge_ids)
        self.assertIn("ip:203.0.113.5|hosted_on|asn:AS64500", edge_ids)
        for edge in fragment["edges"]:
            self.assertIn(edge["source"], ids)
            self.assertIn(edge["target"], ids)
        cert = [e for e in fragment["edges"] if e["id"] == "site:a.example.com|uses_cert|tls_cert:Test CA"]
        self.assertEqual(cert[0]["attrs"]["source"], "urlscan:page.ip:203.0.113.5")

    def test_shape_skips_rows_without_a_usable_host(self):
        rows = [{"domain": None}, {"domain": "bad host!", "uuid": UUID_A}]
        fragment = gb.shape_expansion(rows, "q", None, "q")
        self.assertEqual(fragment["nodes"], [])

    def test_site_keeps_scan_ids_and_time_range(self):
        rows = [
            {"domain": "a.example.com", "uuid": UUID_A, "time": "2025-01-02T00:00:00Z"},
            {"domain": "a.example.com", "uuid": UUID_B, "time": "2025-02-02T00:00:00Z"},
        ]
        site = gb.shape_expansion(rows, "q", None, "q")["nodes"][0]
        self.assertEqual(site["attrs"]["scans"], [UUID_A, UUID_B])
        self.assertEqual(site["attrs"]["first_seen"], "2025-01-02T00:00:00Z")
        self.assertEqual(site["attrs"]["last_seen"], "2025-02-02T00:00:00Z")


class RouteTests(unittest.TestCase):
    def setUp(self):
        self.stub = StubClient()
        self.real_client = application.client
        application.client = self.stub
        application.limiter._hits.clear()
        application.app.config["TESTING"] = True
        self.http = application.app.test_client()

    def tearDown(self):
        application.client = self.real_client

    def post(self, body, key=KEY):
        headers = {"X-URLScan-Key": key} if key else {}
        response = self.http.post("/api/graph/expand", json=body, headers=headers)
        return response, response.get_json()

    def test_transforms_catalog(self):
        response = self.http.get("/api/graph/transforms")
        body = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertTrue(body["ok"])
        self.assertEqual(len(body["transforms"]), len(gb.TRANSFORMS))
        self.assertIn("template", body["transforms"][0])

    def test_expand_returns_nodes_edges_and_meta(self):
        response, body = self.post({"transform": "ip_sites", "value": "203.0.113.5", "size": 25})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(body["ok"])
        self.assertEqual(self.stub.calls[0], (KEY, "page.ip:203.0.113.5", 25, None))
        self.assertEqual(body["meta"]["seed"], "ip:203.0.113.5")
        self.assertEqual(body["meta"]["count"], 2)
        self.assertFalse(body["meta"]["has_more"])
        self.assertTrue(any(n["id"] == "site:a.example.com" for n in body["nodes"]))

    def test_expand_pages_with_cursor(self):
        self.stub.has_more = True
        _, body = self.post({"transform": "apex_sites", "value": "example.com"})
        self.assertTrue(body["meta"]["has_more"])
        cursor = body["meta"]["next_cursor"]
        self.assertTrue(cursor)
        self.post({"transform": "apex_sites", "value": "example.com", "search_after": cursor})
        self.assertEqual(self.stub.calls[-1][3], cursor)

    def test_validation_errors_never_reach_upstream(self):
        bad = [
            ({"transform": "ip_sites", "value": "1.2.3.4 OR 5.6.7.8"}, "invalid_graph_value"),
            ({"transform": "nope", "value": "x"}, "invalid_graph_value"),
            ({"transform": "ip_sites", "value": "1.2.3.4", "size": 7}, "invalid_size"),
            ({"transform": "ip_sites", "value": "1.2.3.4", "size": True}, "invalid_size"),
            ({"transform": "ip_sites", "value": "1.2.3.4", "size": 20000}, "invalid_size"),
            ({"transform": "ip_sites", "value": "1.2.3.4", "search_after": "a b"}, "invalid_cursor"),
            ({"transform": "ip_sites", "value": "1.2.3.4", "search_after": 5}, "invalid_cursor"),
            ({"transform": 5, "value": "x"}, "invalid_body"),
            ({"value": "x"}, "invalid_body"),
        ]
        for body, code in bad:
            response, data = self.post(body)
            self.assertEqual(response.status_code, 400, body)
            self.assertEqual(data["error"]["code"], code, body)
        self.assertEqual(self.stub.calls, [])

    def test_non_json_body_rejected(self):
        response = self.http.post("/api/graph/expand", data="x", headers={"X-URLScan-Key": KEY})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"]["code"], "invalid_body")

    def test_missing_key_and_upstream_errors(self):
        original = application.Config.URLSCAN_API_KEY
        application.Config.URLSCAN_API_KEY = None
        try:
            response, body = self.post({"transform": "ip_sites", "value": "1.2.3.4"}, key=None)
        finally:
            application.Config.URLSCAN_API_KEY = original
        self.assertEqual(response.status_code, 401)
        self.assertEqual(body["error"]["code"], "missing_api_key")

        self.stub.error = UrlscanAuthError("bad key")
        response, body = self.post({"transform": "ip_sites", "value": "1.2.3.4"})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(body["error"]["code"], "invalid_api_key")
        self.assertNotIn(KEY, response.get_data(as_text=True))


class IngestTests(unittest.TestCase):
    def setUp(self):
        application.ingest_limiter._hits.clear()
        application.app.config["TESTING"] = True
        self.http = application.app.test_client()

    def test_site_forms_from_real_datasets(self):
        cases = {
            "https://aegeonglobal.com/": ("aegeonglobal.com", "aegeonglobal.com"),
            "//bitmetadigital.xyz/": ("bitmetadigital.xyz", "bitmetadigital.xyz"),
            "https://www.safepal.com/jp/": ("safepal.com", "safepal.com"),
            "hxxps://evil[.]com/x?y=1": ("evil.com", "evil.com"),
            "http://user:pw@a.b.co.uk:8080/p": ("a.b.co.uk", "b.co.uk"),
            "Example.COM": ("example.com", "example.com"),
        }
        for raw, (host, apex) in cases.items():
            result = gb.normalise_site(raw)
            self.assertEqual((result.get("host"), result.get("apex")), (host, apex), raw)

    def test_www_prefix_is_dropped_from_site_names(self):
        for raw in ("https://www.example.com/x", "WWW.Example.com", "hxxps://www[.]example[.]com"):
            self.assertEqual(gb.normalise_site(raw), {"host": "example.com", "apex": "example.com"}, raw)
        self.assertEqual(gb.normalise_site("https://www.blog.example.com/")["host"], "blog.example.com")
        # Nothing domain-like would be left, so it stays as it is.
        self.assertEqual(gb.strip_www("www.com"), "www.com")
        self.assertEqual(gb.strip_www("wwwx.example.com"), "wwwx.example.com")

    def test_www_and_bare_site_merge_in_expansions(self):
        rows = [{"domain": "www.a.example.com", "uuid": UUID_A, "time": "2025-01-02T00:00:00Z"},
                {"domain": "a.example.com", "uuid": UUID_B, "time": "2025-02-02T00:00:00Z"}]
        nodes = gb.shape_expansion(rows, "q", None, "q")["nodes"]
        self.assertEqual([n["id"] for n in nodes], ["site:a.example.com"])
        self.assertEqual(nodes[0]["attrs"]["scans"], [UUID_A, UUID_B])

    def test_ip_site_has_no_apex_and_junk_is_rejected(self):
        self.assertEqual(gb.normalise_site("http://1.2.3.4/x"), {"host": "1.2.3.4", "apex": None})
        for raw in ("", "   ", "bad host.com", "javascript:alert(1)", "https://", "a" * 3000, None):
            self.assertIn("error", gb.normalise_site(raw), repr(raw)[:30])

    def test_chain_labels(self):
        cases = {
            "eth": "eth",
            "ETH": "eth",
            "Ethereum (ETH) - Ethereum (eth)": "eth",
            "Tether (USDT) - Arbitrum One (arb)": "arb",
            "Tether (USDT) - BNB Smart Chain BEP-20 (bsc)": "bsc",
            "Tron (TRX) - Tron (trx)": "trx",
            "Dogecoin": None,
            "": None,
        }
        for label, chain in cases.items():
            self.assertEqual(gb.chain_from_label(label), chain, label)

    def test_wallets_validate_and_canonicalise(self):
        good = gb.normalise_wallet("0x719DeA9eA99AdCb55b7f03f2FC5CE9858cB13249", "Tether (USDT) - Ethereum ERC-20 (eth)")
        self.assertEqual(good["chain"], "eth")
        self.assertTrue(good["valid"])
        lower = gb.normalise_wallet("0xddae7bc4a8c0f8866c8609355bca368df6d8a513", "ETH")
        self.assertEqual(lower["canonical"], "0xDdAe7bC4a8C0f8866C8609355bcA368df6D8A513")
        tron = gb.normalise_wallet("TDkAnyGrMH7xfGKdpwoVCzMroCCnbk9um3", "Tron (TRX) - Tron (trx)")
        self.assertEqual(tron["chain"], "trx")
        arb = gb.normalise_wallet("0x81c397C37A375d4EadE6949B0fef01Eb27F40353", "Tether (USDT) - Arbitrum One (arb)")
        self.assertEqual(arb["chain"], "arb")

    def test_bad_wallets_are_reported(self):
        for address, label in (("", "eth"), ("junk", "eth"), ("0x719DeA9eA99AdCb55b7f03f2FC5CE9858cB13248", "eth")):
            result = gb.normalise_wallet(address, label)
            self.assertFalse(result["valid"], address)
            self.assertTrue(result["error"])

    def test_wrong_label_falls_back_to_detection(self):
        result = gb.normalise_wallet("TDkAnyGrMH7xfGKdpwoVCzMroCCnbk9um3", "eth")
        self.assertTrue(result["valid"])
        self.assertEqual(result["chain"], "trx")

    def test_route_aligns_results_with_inputs(self):
        body = {
            "sites": ["https://a.example.com/", "bad host"],
            "wallets": [{"address": "TDkAnyGrMH7xfGKdpwoVCzMroCCnbk9um3", "chain": "trx"}, {"address": "x"}, "oops"],
        }
        response = self.http.post("/api/graph/ingest", json=body)
        data = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(data["sites"][0]["host"], "a.example.com")
        self.assertIn("error", data["sites"][1])
        self.assertEqual([w["valid"] for w in data["wallets"]], [True, False, False])

    def test_route_validation(self):
        too_many = {"sites": ["a.example.com"] * (gb.MAX_INGEST_BATCH + 1)}
        cases = [
            (too_many, "batch_too_large"),
            ({"sites": "x"}, "invalid_body"),
            ({"wallets": {"a": 1}}, "invalid_body"),
        ]
        for body, code in cases:
            response = self.http.post("/api/graph/ingest", json=body)
            self.assertEqual(response.status_code, 400)
            self.assertEqual(response.get_json()["error"]["code"], code)
        response = self.http.post("/api/graph/ingest", data="nope")
        self.assertEqual(response.status_code, 400)


def fixture_scan():
    return copy.deepcopy(json.loads((ROOT / "tests" / "fixture_result.json").read_text(encoding="utf-8")))


def by_category(fragment):
    out = {}
    for node in fragment["nodes"]:
        out.setdefault(node["category"], set()).add(node["id"])
    return out


class ScanShapeTests(unittest.TestCase):
    def setUp(self):
        self.doc = fixture_scan()
        self.scan_id = self.doc["task"]["uuid"]

    def test_fixture_maps_every_category(self):
        fragment = gb.shape_scan(self.doc, self.scan_id.upper())
        cats = by_category(fragment)
        self.assertEqual(fragment["meta"]["site"], "site:cloudmine-pro.example")
        self.assertEqual(fragment["meta"]["scan_id"], self.scan_id)
        self.assertEqual(
            cats["core"],
            {"site:cloudmine-pro.example", "apex_domain:cloudmine-pro.example", "ip:203.0.113.42",
             "asn:AS64500", "ptr:vps-42.hosting.example"},
        )
        self.assertIn("tls_cert:R11", cats["cert"])
        self.assertIn("contact:cloudminepro_support", cats["contacts"])
        self.assertEqual(cats["tags"], {"tag:crypto", "tag:hyip"})
        self.assertIn("third_party:js.stripe.com", cats["domains"])
        # first-party sub-hosts are not third parties
        self.assertNotIn("third_party:cdn.cloudmine-pro.example", cats["domains"])
        self.assertIn("filename:Wallet-Setup.exe", cats["filenames"])
        self.assertNotIn("filename:index.html", cats["filenames"])
        self.assertEqual(fragment["meta"]["categories"]["hashes"], len(cats["hashes"]))

    def test_hashes_are_sha256_only_and_downloads_come_first(self):
        fragment = gb.shape_scan(self.doc, self.scan_id)
        hashes = [n for n in fragment["nodes"] if n["category"] == "hashes"]
        for node in hashes:
            self.assertRegex(node["id"].split(":", 1)[1], r"^[0-9a-f]{64}$")
        download = next(n for n in hashes if n["attrs"].get("kind") == "download")
        self.assertEqual(download["attrs"]["filename"], "Wallet-Setup.exe")
        self.assertEqual(fragment["meta"]["skipped"].get("unrecognised_hash"), 1)  # "NOT-A-HASH"

    def test_every_edge_points_at_a_real_node_and_has_a_category(self):
        fragment = gb.shape_scan(self.doc, self.scan_id)
        ids = {n["id"] for n in fragment["nodes"]}
        for edge in fragment["edges"]:
            self.assertIn(edge["source"], ids)
            self.assertIn(edge["target"], ids)
            self.assertTrue(edge["category"])
            self.assertEqual(edge["attrs"]["source"], "urlscan:scan:" + self.scan_id)

    def test_ids_are_stable_between_calls_and_match_search_hits(self):
        first = gb.shape_scan(self.doc, self.scan_id)
        second = gb.shape_scan(fixture_scan(), self.scan_id)
        self.assertEqual({n["id"] for n in first["nodes"]}, {n["id"] for n in second["nodes"]})
        self.assertEqual({e["id"] for e in first["edges"]}, {e["id"] for e in second["edges"]})
        hit = gb.shape_expansion([normalise_result(HITS[0], 1)], "q", None, "q")
        self.assertIn("site:a.example.com", {n["id"] for n in hit["nodes"]})
        # a scan and a search hit for the same page build the same edge ids for core facts
        self.assertIn("site:cloudmine-pro.example|resolves_to|ip:203.0.113.42",
                      {e["id"] for e in first["edges"]})

    def test_wallet_in_a_link_is_validated(self):
        good = "0x719DeA9eA99AdCb55b7f03f2FC5CE9858cB13249"
        bad = "0x719DeA9eA99AdCb55b7f03f2FC5CE9858cB13248"
        self.doc["data"]["links"] = [{"href": "https://pay.example/?to=" + good, "text": "Pay"},
                                     {"href": "https://pay.example/?to=" + bad, "text": "Bad"}]
        fragment = gb.shape_scan(self.doc, self.scan_id)
        self.assertEqual(by_category(fragment)["wallets"], {"wallet:" + good})
        self.assertEqual(fragment["meta"]["skipped"]["wallet_failed_validation"], 1)

    def test_redirect_hops(self):
        self.doc["data"]["requests"].append({
            "request": {"request": {"url": "https://short.example/x"}},
            "response": {"size": 1, "response": {
                "url": "https://short.example/x", "status": 302,
                "headers": {"Location": "https://cloudmine-pro.example/invest"}}},
        })
        fragment = gb.shape_scan(self.doc, self.scan_id)
        self.assertIn("site:short.example|redirects_to|site:cloudmine-pro.example",
                      {e["id"] for e in fragment["edges"]})

    def test_hostile_strings_are_dropped_not_echoed(self):
        self.doc["task"]["tags"] = ['bad"tag', "tag\x00null", "x" * 10000, "fine"]
        self.doc["page"]["title"] = "t" * 10000
        self.doc["page"]["server"] = 'ngi"nx'
        self.doc["lists"]["domains"] = ["evil host.com", "a" * 400 + ".com", "ok.example.net"]
        fragment = gb.shape_scan(self.doc, self.scan_id)
        cats = by_category(fragment)
        self.assertEqual(cats["tags"], {"tag:hyip", "tag:fine"})  # hyip comes from the verdicts
        self.assertEqual(cats["domains"] & {"third_party:ok.example.net"}, {"third_party:ok.example.net"})
        self.assertEqual(sum(1 for n in cats["domains"] if "evil" in n), 0)
        self.assertNotIn("tech:ngi\"nx", cats.get("tech", set()))
        site = next(n for n in fragment["nodes"] if n["type"] == "site")
        self.assertNotIn("title", site["attrs"])
        for node in fragment["nodes"]:
            self.assertLessEqual(len(node["id"]), gb.MAX_VALUE_LENGTH + 40)

    def test_caps(self):
        self.doc["data"]["requests"] = [
            {"request": {"request": {"url": "https://f.example/file%d.js" % i}},
             "response": {"size": i + 1, "hash": "%064x" % (i + 1), "response": {}}}
            for i in range(300)
        ]
        self.doc["lists"]["domains"] = ["d%d.example.net" % i for i in range(300)]
        fragment = gb.shape_scan(self.doc, self.scan_id)
        counts = fragment["meta"]["categories"]
        self.assertLessEqual(counts["hashes"], gb.MAX_SCAN_HASHES)
        self.assertLessEqual(counts["filenames"], gb.MAX_SCAN_FILENAMES)
        self.assertLessEqual(counts["domains"], gb.MAX_SCAN_DOMAINS)
        self.assertIn("hashes_over_cap", fragment["meta"]["skipped"])

    def test_unusable_scans_raise(self):
        for doc in ({}, {"page": {}}, {"page": {"domain": "bad host"}}, []):
            with self.assertRaises(gb.GraphInputError):
                gb.shape_scan(doc, self.scan_id)


class ScanRouteTests(unittest.TestCase):
    UUID = "0f8e1c4a-2b3d-4e5f-8a9b-1c2d3e4f5a7c"

    def setUp(self):
        self.doc = fixture_scan()
        self.calls = []
        outer = self

        class Stub:
            error = None

            def result(self, api_key, uuid):
                outer.calls.append((api_key, uuid))
                if Stub.error:
                    raise Stub.error
                return outer.doc

        self.stub = Stub
        self.real_client = application.client
        application.client = Stub()
        application.limiter._hits.clear()
        application.RESULT_CACHE.clear()
        application.app.config["TESTING"] = True
        self.http = application.app.test_client()

    def tearDown(self):
        application.client = self.real_client
        application.RESULT_CACHE.clear()

    def post(self, body, key=KEY):
        headers = {"X-URLScan-Key": key} if key else {}
        response = self.http.post("/api/graph/site", json=body, headers=headers)
        return response, response.get_json()

    def test_returns_fragment_and_calls_urlscan_once(self):
        response, body = self.post({"scan_id": self.UUID})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(body["ok"])
        self.assertEqual(body["meta"]["site"], "site:cloudmine-pro.example")
        self.assertFalse(body["meta"]["cached"])
        self.assertEqual(self.calls, [(KEY, self.UUID)])
        again, body2 = self.post({"scan_id": self.UUID})
        self.assertTrue(body2["meta"]["cached"])
        self.assertEqual(len(self.calls), 1)

    def test_bad_input_never_reaches_urlscan(self):
        cases = [
            ({"scan_id": "not-a-uuid"}, "invalid_uuid"),
            ({"scan_id": "../../etc/passwd"}, "invalid_uuid"),
            ({"scan_id": 5}, "invalid_body"),
            ({}, "invalid_body"),
        ]
        for body, code in cases:
            response, data = self.post(body)
            self.assertEqual(response.status_code, 400, body)
            self.assertEqual(data["error"]["code"], code)
        response = self.http.post("/api/graph/site", data="nope", headers={"X-URLScan-Key": KEY})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.calls, [])

    def test_missing_key_and_upstream_errors(self):
        response, data = self.post({"scan_id": self.UUID}, key=None)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.calls, [])
        self.stub.error = UrlscanNotFoundError("Scan is not ready yet.")
        response, data = self.post({"scan_id": self.UUID})
        self.assertEqual(response.status_code, 404)
        self.assertEqual(data["error"]["code"], "not_found")

    def test_scan_without_a_site_is_422(self):
        self.doc = {"page": {}, "task": {}}
        response, data = self.post({"scan_id": self.UUID})
        self.assertEqual(response.status_code, 422)
        self.assertEqual(data["error"]["code"], "scan_unusable")


if __name__ == "__main__":
    unittest.main()
