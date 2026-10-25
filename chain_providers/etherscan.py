"""Etherscan API V2 (one key, a ``chainid`` per request) for the EVM chains."""

from __future__ import annotations

import logging
import time

import requests

from . import ProviderError, clean_text, decimal_string, iso_from_unix

log = logging.getLogger("urlscan-dashboard")

CHAIN_IDS = {"eth": 1, "bsc": 56, "matic": 137, "arb": 42161, "avax": 43114, "op": 10}
NATIVE_SYMBOL = {"eth": "ETH", "bsc": "BNB", "matic": "POL", "arb": "ETH", "avax": "AVAX", "op": "ETH"}
EXPLORER = {
    "eth": "https://etherscan.io/address/",
    "bsc": "https://bscscan.com/address/",
    "matic": "https://polygonscan.com/address/",
    "arb": "https://arbiscan.io/address/",
    "avax": "https://snowscan.xyz/address/",
    "op": "https://optimistic.etherscan.io/address/",
}

# The free plan allows 3 calls per second, so calls within one lookup are spaced.
CALL_SPACING = 0.36
MAX_TOKENS = 8
TOKEN_SCAN_WINDOW = 100


class EtherscanProvider:
    name = "etherscan"
    chains = tuple(CHAIN_IDS)
    needs_key = True

    def __init__(self, base_url: str, timeout: int = 20, session=None, spacing: float = CALL_SPACING):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.spacing = spacing
        self._session = session or requests.Session()
        self._last_call = 0.0

    def capabilities(self) -> dict:
        return {
            "chains": list(self.chains),
            "needs_key": True,
            "fields": ["balance", "address_type", "sent_tx_count", "first_seen", "last_seen",
                       "contract", "tokens_seen"],
            "note": "Free keys cover only some chains; unsupported chains report a plan error.",
        }

    # -- transport ------------------------------------------------------------

    def _call(self, chain: str, key: str, **params) -> dict:
        wait = self.spacing - (time.monotonic() - self._last_call)
        if wait > 0:
            time.sleep(wait)
        query = dict(params, chainid=CHAIN_IDS[chain], apikey=key)
        try:
            response = self._session.get(self.base_url, params=query, timeout=self.timeout,
                                         allow_redirects=False)
        except requests.exceptions.Timeout:
            raise ProviderError("Etherscan did not respond in time.", 504, "provider_timeout")
        except requests.exceptions.RequestException as exc:
            # The exception text embeds the request URL, key included: log the type only.
            log.info("etherscan request failed: %s", type(exc).__name__)
            raise ProviderError("Could not reach Etherscan.", 504, "provider_error")
        finally:
            self._last_call = time.monotonic()

        if response.status_code == 429:
            raise ProviderError("Etherscan rate limit reached. Wait a moment and try again.",
                                429, "provider_rate_limited", retry_after=2)
        if response.status_code != 200:
            raise ProviderError(f"Etherscan returned HTTP {response.status_code}.", 502, "provider_error")
        try:
            data = response.json()
        except ValueError:
            raise ProviderError("Etherscan sent a reply that is not JSON.", 502, "provider_error")
        if not isinstance(data, dict):
            raise ProviderError("Etherscan sent an unexpected reply.", 502, "provider_error")
        return data

    @staticmethod
    def _raise_for_text(text: str) -> None:
        lowered = text.lower()
        if "rate limit" in lowered:
            raise ProviderError("Etherscan rate limit reached. Wait a moment and try again.",
                                429, "provider_rate_limited", retry_after=2)
        if "api key" in lowered or "apikey" in lowered:
            raise ProviderError("Etherscan rejected the API key.", 401, "provider_key_invalid")
        if "upgrade" in lowered or "not supported" in lowered or "free api access" in lowered:
            raise ProviderError("Your Etherscan plan does not cover this chain.", 403, "provider_plan_unsupported")
        raise ProviderError("Etherscan could not answer that request.", 502, "provider_error")

    def _result(self, data: dict):
        """The ``result`` of an account/contract call; ``[]`` when there are no records."""
        status = str(data.get("status", ""))
        result = data.get("result")
        if status == "1":
            return result
        message = str(data.get("message", ""))
        if isinstance(result, list) and not result:
            return result
        if "no transactions found" in message.lower() or "no records found" in message.lower():
            return []
        self._raise_for_text(result if isinstance(result, str) else message)

    def _rpc(self, data: dict) -> str:
        """The ``result`` of a proxy (JSON-RPC style) call."""
        if "result" in data and isinstance(data["result"], str) and data.get("status") != "0":
            return data["result"]
        text = data.get("result") if isinstance(data.get("result"), str) else str(data.get("message", ""))
        self._raise_for_text(text)
        return ""

    # -- public ---------------------------------------------------------------

    def summary(self, chain: str, address: str, key: str) -> dict:
        if chain not in CHAIN_IDS:
            raise ProviderError("Etherscan does not cover that chain.", 400, "provider_unsupported_chain")

        balance_raw = int(self._result(self._call(chain, key, module="account", action="balance",
                                                  address=address, tag="latest")) or 0)
        code = self._rpc(self._call(chain, key, module="proxy", action="eth_getCode",
                                    address=address, tag="latest"))
        is_contract = code not in ("", "0x")
        nonce_hex = self._rpc(self._call(chain, key, module="proxy", action="eth_getTransactionCount",
                                         address=address, tag="latest"))
        try:
            sent_count = int(nonce_hex, 16)
        except ValueError:
            sent_count = None

        def one(sort: str):
            rows = self._result(self._call(chain, key, module="account", action="txlist", address=address,
                                           startblock=0, endblock=99999999, page=1, offset=1, sort=sort))
            if isinstance(rows, list) and rows and isinstance(rows[0], dict):
                return iso_from_unix(rows[0].get("timeStamp"))
            return None

        first_seen = one("asc")
        last_seen = one("desc")

        tokens = []
        seen = set()
        rows = self._result(self._call(chain, key, module="account", action="tokentx", address=address,
                                       page=1, offset=TOKEN_SCAN_WINDOW, sort="desc"))
        for row in rows if isinstance(rows, list) else []:
            if not isinstance(row, dict):
                continue
            contract = clean_text(row.get("contractAddress"), 66).lower()
            if not contract or contract in seen:
                continue
            seen.add(contract)
            tokens.append({"symbol": clean_text(row.get("tokenSymbol"), 20),
                           "name": clean_text(row.get("tokenName"), 60), "contract": contract})
            if len(tokens) >= MAX_TOKENS:
                break

        contract_name = None
        verified = None
        if is_contract:
            rows = self._result(self._call(chain, key, module="contract", action="getsourcecode", address=address))
            first = rows[0] if isinstance(rows, list) and rows and isinstance(rows[0], dict) else {}
            verified = bool(str(first.get("SourceCode") or "").strip())
            contract_name = clean_text(first.get("ContractName"), 80) or None

        return {
            "provider": self.name,
            "chain": chain,
            "address": address,
            "address_type": "Contract" if is_contract else "Externally owned account",
            "native_symbol": NATIVE_SYMBOL[chain],
            "balance": decimal_string(balance_raw, 18),
            "total_received": None,
            "total_sent": None,
            "tx_count": None,
            "sent_tx_count": sent_count,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "is_contract": is_contract,
            "contract_name": contract_name,
            "contract_verified": verified,
            "tokens_seen": tokens,
            "explorer_url": EXPLORER[chain] + address,
        }
