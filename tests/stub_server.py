"""Run the dashboard against a fake urlscan.io, for UI work without an API key.

    python3 tests/stub_server.py [port]

It serves tests/fixture_result.json for every scan ID, a canned DOM for content
analysis, and a small canned corpus for search and hash pivots. Nothing leaves
the machine. Any key-shaped string is accepted in the key field.
"""

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import app as application  # noqa: E402

FIXTURE = json.loads((ROOT / "tests" / "fixture_result.json").read_text(encoding="utf-8"))

DOM = """<!DOCTYPE html><html><head><title>CloudMine Pro — Guaranteed Daily Returns</title>
<style>body{background:#0b1020;color:#eaeaea}</style>
<script>var tracker=1;/* guaranteed profit */</script></head><body>
<header><h1>Guaranteed Daily Returns on Your Crypto</h1>
<p>CloudMine Pro is a licensed and regulated cloud mining platform. Our smart contract is
audited by CertiK and our reserves are fully insured.</p></header>
<section><h2>Investment plans</h2>
<p>Starter plan: earn 1.5% daily for 30 days. Minimum deposit 100 USDT on TRC20.</p>
<p>Pro plan: earn 3% daily with our AI trading bot. Risk-free and 100% guaranteed.</p>
<p>Whale plan: 10% daily, 1000% APY, principal returned after the lock-in period.</p>
<p>Withdraw anytime. Instant withdrawal, no KYC required, anonymous accounts welcome.</p></section>
<section><h2>Why members trust us</h2>
<p>98% win rate, 99.9% uptime and over 120,000 happy investors. As seen on Forbes.
Elon Musk endorsed. Limited slots remaining — act now, don't miss out!</p>
<p>Invite friends and earn a 10% referral commission on every deposit, plus 5% on tier two.</p></section>
<section><h2>Withdrawals</h2>
<p>To release your balance, settle the balance first: pay the withdrawal fee, the network fee
and the tax clearance fee. Insufficient balance to withdraw? Upgrade your plan to unlock.</p>
<p>Support is available on Telegram only. Contact our account manager on WhatsApp.</p></section>
<footer><p>Registered offshore. Not financial advice. Password reset is available in your
account settings, and our normal support hours are listed on the contact page.</p></footer>
</body></html>"""

CORPUS = [
    {
        "task": {"uuid": "0f8e1c4a-2b3d-4e5f-8a9b-1c2d3e4f5a6b", "time": "2026-09-14T09:12:44.000Z",
                 "url": "https://cloudmine-pro.example/invest", "visibility": "public"},
        "page": {"domain": "www.cloudmine-pro.example", "apexDomain": "cloudmine-pro.example",
                 "ip": "203.0.113.42", "asn": "AS64500", "asnname": "EXAMPLE-ANYCAST",
                 "country": "US", "status": 200, "tlsIssuer": "R11", "tlsValidDays": 62,
                 "domainAgeDays": 41, "server": "nginx"},
        "sort": [1757840000000, "a"],
    },
    {
        "task": {"uuid": "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d", "time": "2026-09-11T18:02:10.000Z",
                 "url": "https://miner-vault.example/plans", "visibility": "public"},
        "page": {"domain": "miner-vault.example", "apexDomain": "miner-vault.example",
                 "ip": "203.0.113.77", "asn": "AS64500", "asnname": "EXAMPLE-ANYCAST",
                 "country": "US", "status": 200, "tlsIssuer": "R11", "tlsValidDays": 55,
                 "domainAgeDays": 12, "server": "nginx"},
        "sort": [1757600000000, "b"],
    },
    {
        "task": {"uuid": "2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e", "time": "2026-08-29T04:41:59.000Z",
                 "url": "https://yield-harbor.example/", "visibility": "public"},
        "page": {"domain": "yield-harbor.example", "apexDomain": "yield-harbor.example",
                 "ip": "198.51.100.200", "asn": "AS64511", "asnname": "EXAMPLE-VPS",
                 "country": "DE", "status": 403, "tlsIssuer": "E6", "tlsValidDays": 8,
                 "domainAgeDays": 900, "server": "cloudflare"},
        "sort": [1756440000000, "c"],
    },
]


class StubClient:
    """Same surface as UrlscanClient, backed by the fixtures above."""

    def search(self, api_key, query, size, search_after=None):
        return {"results": CORPUS[:size], "total": len(CORPUS), "has_more": False, "took": 7}

    def quotas(self, api_key):
        return {"limits": {"search": {"day": {"limit": 1000, "used": 12}}}}

    def result(self, api_key, uuid):
        document = json.loads(json.dumps(FIXTURE))
        document["task"]["uuid"] = uuid
        return document

    def dom(self, api_key, uuid, max_bytes=None):
        return DOM


if __name__ == "__main__":
    application.client = StubClient()
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8010
    print(f"Stubbed dashboard on http://127.0.0.1:{port}/ — paste any 16+ character key.")
    application.app.run(host="127.0.0.1", port=port, debug=False)
