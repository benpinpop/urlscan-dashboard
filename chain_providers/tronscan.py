"""Tronscan API (``accountv2``) for Tron wallets."""

from __future__ import annotations

import logging

import requests

from . import ProviderError, clean_text, decimal_string, iso_from_unix

log = logging.getLogger("urlscan-dashboard")

EXPLORER = "https://tronscan.org/#/address/"
MAX_TOKENS = 8


def _unix_ms(value):
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return iso_from_unix(number // 1000) if number > 0 else None


def _int(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


class TronscanProvider:
    name = "tronscan"
    chains = ("trx",)
    needs_key = True

    def __init__(self, base_url: str, timeout: int = 20, session=None):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._session = session or requests.Session()

    def capabilities(self) -> dict:
        return {
            "chains": list(self.chains),
            "needs_key": True,
            "fields": ["balance", "tx_count", "first_seen", "last_seen", "token_balances", "tags"],
            "note": "Tronscan answers 401 without a key.",
        }

    def summary(self, chain: str, address: str, key: str) -> dict:
        if chain != "trx":
            raise ProviderError("Tronscan only covers Tron.", 400, "provider_unsupported_chain")

        headers = {"TRON-PRO-API-KEY": key}
        try:
            response = self._session.get(f"{self.base_url}/api/accountv2", params={"address": address},
                                         headers=headers, timeout=self.timeout, allow_redirects=False)
        except requests.exceptions.Timeout:
            raise ProviderError("Tronscan did not respond in time.", 504, "provider_timeout")
        except requests.exceptions.RequestException as exc:
            log.info("tronscan request failed: %s", type(exc).__name__)
            raise ProviderError("Could not reach Tronscan.", 504, "provider_error")

        if response.status_code == 429:
            raise ProviderError("Tronscan rate limit reached. Wait a moment and try again.",
                                429, "provider_rate_limited", retry_after=3)
        if response.status_code in (401, 403):
            raise ProviderError("Tronscan rejected the API key.", 401, "provider_key_invalid")
        if response.status_code != 200:
            raise ProviderError(f"Tronscan returned HTTP {response.status_code}.", 502, "provider_error")
        try:
            data = response.json()
        except ValueError:
            raise ProviderError("Tronscan sent a reply that is not JSON.", 502, "provider_error")
        if not isinstance(data, dict):
            raise ProviderError("Tronscan sent an unexpected reply.", 502, "provider_error")

        balance = _int(data.get("balance")) or 0
        tokens = []
        for token in data.get("withPriceTokens") or []:
            if not isinstance(token, dict) or str(token.get("tokenId")) == "_":
                continue  # the native TRX row repeats the balance above
            raw = _int(token.get("balance"))
            decimals = _int(token.get("tokenDecimal"))
            if raw is None or decimals is None or not 0 <= decimals <= 36:
                continue
            tokens.append({
                "symbol": clean_text(token.get("tokenAbbr"), 20),
                "name": clean_text(token.get("tokenName"), 60),
                "contract": clean_text(token.get("tokenId"), 66),
                "balance": decimal_string(raw, decimals),
                "type": clean_text(token.get("tokenType"), 12),
            })
            if len(tokens) >= MAX_TOKENS:
                break

        tags = []
        for field in ("redTag", "greyTag", "blueTag"):
            text = clean_text(data.get(field), 60)
            if text:
                tags.append(text)
        if data.get("feedbackRisk") is True:
            tags.append("Reported as risky on Tronscan")

        total = _int(data.get("totalTransactionCount"))
        return {
            "provider": self.name,
            "chain": chain,
            "address": address,
            "address_type": "Account",
            "native_symbol": "TRX",
            "balance": decimal_string(balance, 6),
            "total_received": None,
            "total_sent": None,
            "tx_count": total,
            "tx_in": _int(data.get("transactions_in")),
            "tx_out": _int(data.get("transactions_out")),
            "sent_tx_count": None,
            "first_seen": _unix_ms(data.get("date_created")),
            "last_seen": _unix_ms(data.get("latest_operation_time")),
            "is_contract": None,
            "contract_name": None,
            "contract_verified": None,
            "tokens_seen": [],
            "token_balances": tokens,
            "tags": tags,
            "explorer_url": EXPLORER + address,
        }
