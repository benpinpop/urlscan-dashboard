"""Blockchain.com explorer API (blockchain.info ``rawaddr``) for Bitcoin."""

from __future__ import annotations

import logging

import requests

from . import ProviderError, decimal_string, iso_from_unix

log = logging.getLogger("urlscan-dashboard")

EXPLORER = "https://www.blockchain.com/explorer/addresses/btc/"


def address_type(address: str) -> str:
    lowered = address.lower()
    if lowered.startswith("bc1p"):
        return "Taproot (P2TR)"
    if lowered.startswith("bc1q"):
        return "Native SegWit (P2WPKH)" if len(address) == 42 else "Native SegWit (P2WSH)"
    if address.startswith("3"):
        return "P2SH"
    if address.startswith("1"):
        return "Legacy (P2PKH)"
    return "Bitcoin address"


class BlockchainProvider:
    name = "blockchain"
    chains = ("btc",)
    needs_key = False

    def __init__(self, base_url: str, timeout: int = 20, session=None):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._session = session or requests.Session()

    def capabilities(self) -> dict:
        return {
            "chains": list(self.chains),
            "needs_key": False,
            "fields": ["balance", "address_type", "total_received", "total_sent", "tx_count",
                       "first_seen", "last_seen"],
            "note": "Works without a key but is heavily rate limited; a key (api_code) raises the limit.",
        }

    def _get(self, address: str, key: str | None, **params) -> dict:
        query = dict(params)
        if key:
            query["api_code"] = key
        try:
            response = self._session.get(f"{self.base_url}/rawaddr/{address}", params=query,
                                         timeout=self.timeout, allow_redirects=False)
        except requests.exceptions.Timeout:
            raise ProviderError("Blockchain.com did not respond in time.", 504, "provider_timeout")
        except requests.exceptions.RequestException as exc:
            log.info("blockchain.com request failed: %s", type(exc).__name__)
            raise ProviderError("Could not reach Blockchain.com.", 504, "provider_error")

        if response.status_code == 429:
            raise ProviderError("Blockchain.com rate limit reached. Wait about 10 seconds and try again.",
                                429, "provider_rate_limited", retry_after=10)
        if response.status_code in (401, 403) and key:
            raise ProviderError("Blockchain.com rejected the API key.", 401, "provider_key_invalid")
        if response.status_code in (400, 404):
            raise ProviderError("Blockchain.com did not recognise that address.", 404, "provider_error")
        if response.status_code != 200:
            raise ProviderError(f"Blockchain.com returned HTTP {response.status_code}.", 502, "provider_error")
        try:
            data = response.json()
        except ValueError:
            raise ProviderError("Blockchain.com sent a reply that is not JSON.", 502, "provider_error")
        if not isinstance(data, dict):
            raise ProviderError("Blockchain.com sent an unexpected reply.", 502, "provider_error")
        return data

    @staticmethod
    def _time_of(data: dict):
        txs = data.get("txs")
        if isinstance(txs, list) and txs and isinstance(txs[0], dict):
            return iso_from_unix(txs[0].get("time"))
        return None

    def summary(self, chain: str, address: str, key: str | None = None) -> dict:
        if chain != "btc":
            raise ProviderError("Blockchain.com only covers Bitcoin here.", 400, "provider_unsupported_chain")

        latest = self._get(address, key, limit=1)
        try:
            n_tx = int(latest.get("n_tx") or 0)
            final = int(latest.get("final_balance") or 0)
            received = int(latest.get("total_received") or 0)
            sent = int(latest.get("total_sent") or 0)
        except (TypeError, ValueError):
            raise ProviderError("Blockchain.com sent unreadable totals.", 502, "provider_error")

        last_seen = self._time_of(latest)
        first_seen = last_seen if n_tx == 1 else None
        if n_tx > 1:
            try:
                first_seen = self._time_of(self._get(address, key, limit=1, offset=n_tx - 1))
            except ProviderError as exc:
                if exc.code == "provider_rate_limited":
                    raise
                first_seen = None

        return {
            "provider": self.name,
            "chain": chain,
            "address": address,
            "address_type": address_type(address),
            "native_symbol": "BTC",
            "balance": decimal_string(final, 8),
            "total_received": decimal_string(received, 8),
            "total_sent": decimal_string(sent, 8),
            "tx_count": n_tx,
            "sent_tx_count": None,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "is_contract": None,
            "contract_name": None,
            "contract_verified": None,
            "tokens_seen": [],
            "explorer_url": EXPLORER + address,
        }
