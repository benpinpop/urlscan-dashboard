"""Wallet chain detection and checksum validation (stdlib only).

``detect_chain(address)`` suggests a chain from the address format; the user
may override it. ``validate_wallet(chain, address)`` is the hard gate: the
address must decode, pass its chain's checksum and match the chain's
version bytes / prefix. The same code backs the live check in the submit
form (via /api/wallets/check) and the server-side re-validation.

Per-chain rules
  btc   Base58Check P2PKH (0x00, "1…") / P2SH (0x05, "3…"); segwit bc1q (Bech32) / bc1p (Bech32m)
  eth, bsc, matic, arb, op, avax (C-Chain)
        0x + 40 hex; EIP-55 checksum enforced when mixed-case
  avax  also X-Chain "X-avax1…" (Bech32, 20-byte payload)
  trx   Base58Check, version 0x41, 34 chars, "T…"
  ltc   Base58Check 0x30 ("L…") / 0x32 ("M…"); segwit ltc1…
  doge  Base58Check 0x1E ("D…")
  dash  Base58Check 0x4C ("X…")
  bch   CashAddr (bitcoincash:q…/p… or bare q…/p…), or legacy 1…/3… (converted to CashAddr)
  ada   Shelley Bech32 "addr1…" (mainnet; base, pointer or enterprise address)
  xrp   [XRP ADDITION] classic "r…" address: Base58Check over the XRP Ledger
        alphabet, version 0x00 + 20-byte account ID; X-addresses are refused
        (enter the r… address and the destination tag separately). A destination
        tag is REQUIRED alongside XRP addresses; see validate_xrp_dest_tag().

Ported from scamhunt-ctf backend/scamhunt/validation/wallets.py. Everything
outside the blocks marked "XRP ADDITION" is unchanged from the CTF copy.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field

from .codecs import (
    B58_ALPHABET,
    DecodeError,
    b58check_decode,
    bech32_decode,
    cashaddr_decode,
    cashaddr_encode,
    convertbits,
    eip55_checksum,
    segwit_decode,
)

CHAINS: dict[str, str] = {
    "eth": "Ethereum",
    "bsc": "BNB Smart Chain",
    "matic": "Polygon",
    "arb": "Arbitrum",
    "avax": "Avalanche",
    "op": "Optimism",
    "btc": "Bitcoin",
    "trx": "Tron (TRC-20)",
    "ltc": "Litecoin",
    "doge": "Dogecoin",
    "bch": "Bitcoin Cash",
    "ada": "Cardano",
    "dash": "Dash",
    "xrp": "XRP Ledger",  # XRP ADDITION
}
EVM_CHAINS = ("eth", "bsc", "matic", "arb", "avax", "op")  # ETH first = default for 0x
OTHER_CHAINS = ("btc", "trx", "ltc", "doge", "bch", "ada", "dash", "xrp")  # XRP ADDITION: "xrp"

# --- XRP ADDITION ------------------------------------------------------------
# XRP Ledger addresses are Base58Check with a different alphabet ('r' = 0), so
# they are translated onto the Bitcoin alphabet and decoded by the unchanged
# codecs.b58check_decode. Destination tags are unsigned 32-bit integers.
XRP_ALPHABET = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"
_XRP_TO_B58 = str.maketrans(XRP_ALPHABET, B58_ALPHABET)
_XRP_CLASSIC_RE = re.compile(f"^r[{re.escape(XRP_ALPHABET)}]{{24,34}}$")
_XRP_X_ADDRESS_RE = re.compile(f"^[XT][{re.escape(XRP_ALPHABET)}]{{46}}$")
XRP_DEST_TAG_MAX = 2**32 - 1
# ------------------------------------------------------------ end XRP ADDITION

_EVM_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_B58_RE = re.compile(f"^[{re.escape(B58_ALPHABET)}]+$")
_BARE_CASHADDR_RE = re.compile(r"^[qp][qpzry9x8gf2tvdw0s3jn54khce6mua7l]{41}$")

# Base58Check version byte -> (chain, format)
_B58_VERSIONS = {
    0x00: ("btc", "P2PKH (legacy)"),
    0x05: ("btc", "P2SH"),
    0x41: ("trx", "Base58Check"),
    0x30: ("ltc", "P2PKH (L…)"),
    0x32: ("ltc", "P2SH (M…)"),
    0x1E: ("doge", "P2PKH (D…)"),
    0x4C: ("dash", "P2PKH (X…)"),
}
_B58_FIRST_CHAR = {"1": "btc", "3": "btc", "T": "trx", "L": "ltc", "M": "ltc", "D": "doge", "X": "dash"}


@dataclass(frozen=True)
class Detection:
    chain: str | None               # best guess, pre-selected in the dropdown
    candidates: tuple[str, ...]     # chains the format is compatible with
    note: str = ""

    def as_dict(self) -> dict:
        return {"chain": self.chain, "candidates": list(self.candidates), "note": self.note}


@dataclass
class WalletCheck:
    chain: str
    input: str
    valid: bool
    canonical: str | None = None     # display form (EIP-55, lowercase bech32, CashAddr…)
    key: str | None = None           # dedup identity "<chain>:<address>"
    format: str | None = None
    errors: list[str] = field(default_factory=list)
    detected: Detection | None = None

    def detail(self) -> dict:
        """JSON-able record stored in submission_wallets.validation_detail."""
        data = asdict(self)
        data["detected"] = self.detected.as_dict() if self.detected else None
        return data


def clean_address(raw: str | None) -> str:
    return (raw or "").strip()


def chain_label(code: str) -> str:
    return CHAINS.get(code, code)


# ------------------------------------------------------------------ detection

def detect_chain(raw: str | None) -> Detection:
    address = clean_address(raw)
    if not address:
        return Detection(None, ())
    if _EVM_RE.match(address):
        return Detection(
            "eth", EVM_CHAINS,
            "0x addresses look identical on every EVM chain — pick the network the site actually uses.",
        )
    lower = address.lower()
    if lower.startswith("x-avax1"):
        return Detection("avax", ("avax",), "Avalanche X-Chain address")
    if lower.startswith("bc1"):
        return Detection("btc", ("btc",))
    if lower.startswith("ltc1"):
        return Detection("ltc", ("ltc",))
    if lower.startswith("addr1"):
        return Detection("ada", ("ada",))
    if lower.startswith("bitcoincash:") or _BARE_CASHADDR_RE.match(lower):
        return Detection("bch", ("bch",))
    # --- XRP ADDITION: no other supported chain starts with "r", and no other
    # supported format is 47 Base58 characters starting with X/T.
    if _XRP_CLASSIC_RE.match(address):
        return Detection("xrp", ("xrp",), "XRP Ledger address — a destination tag is required.")
    if _XRP_X_ADDRESS_RE.match(address):
        return Detection("xrp", ("xrp",), "XRP X-address — enter the classic r… address and the tag instead.")
    # --- end XRP ADDITION
    if _B58_RE.match(address):
        try:
            payload = b58check_decode(address)
            match = _B58_VERSIONS.get(payload[0]) if len(payload) == 21 else None
        except DecodeError:
            match = None
        chain = match[0] if match else _B58_FIRST_CHAR.get(address[0])
        if chain == "btc":
            # Legacy 1…/3… addresses are also valid Bitcoin Cash legacy addresses.
            return Detection("btc", ("btc", "bch"), "Legacy format is shared by Bitcoin and Bitcoin Cash.")
        if chain:
            return Detection(chain, (chain,))
    return Detection(None, ())


# ----------------------------------------------------------------- validation

def validate_wallet(chain: str, raw: str | None) -> WalletCheck:
    address = clean_address(raw)
    detection = detect_chain(address)
    check = WalletCheck(chain=chain, input=address, valid=False, detected=detection)
    if chain not in CHAINS:
        check.errors.append(f"Unsupported chain {chain!r}.")
        return check
    if not address:
        check.errors.append("Enter a wallet address.")
        return check
    if any(ch.isspace() for ch in address):
        check.errors.append("The address contains spaces.")
        return check
    if len(address) > 128:
        check.errors.append("That is too long to be a wallet address.")
        return check

    try:
        if chain == "avax" and address.lower().startswith("x-"):
            canonical, fmt, key_form = _validate_avax_x(address)
        elif chain in EVM_CHAINS:
            canonical, fmt, key_form = _validate_evm(address)
        else:
            canonical, fmt, key_form = _VALIDATORS[chain](address)
    except DecodeError as exc:
        check.errors.append(_friendly_error(chain, detection, str(exc)))
        return check

    check.valid = True
    check.canonical = canonical
    check.format = fmt
    check.key = f"{chain}:{key_form}"
    return check


def _friendly_error(chain: str, detection: Detection, reason: str) -> str:
    message = f"Not a valid {chain_label(chain)} address: {reason}."
    if detection.chain and chain not in detection.candidates:
        message += f" It looks like a {chain_label(detection.chain)} address."
    return message


def _validate_evm(address: str) -> tuple[str, str, str]:
    if not _EVM_RE.match(address):
        raise DecodeError("expected 0x followed by 40 hexadecimal characters")
    body = address[2:]
    checksummed = eip55_checksum(body)
    if body.lower() == body or body.upper() == body:
        fmt = "EVM (no checksum casing)"
    elif address == checksummed:
        fmt = "EVM (EIP-55 checksum verified)"
    else:
        raise DecodeError("EIP-55 checksum mismatch — check for a typo in the mixed-case address")
    return checksummed, fmt, "0x" + body.lower()


def _validate_avax_x(address: str) -> tuple[str, str, str]:
    if not address.lower().startswith("x-"):
        raise DecodeError("expected an 0x C-Chain address or an X-avax1… X-Chain address")
    hrp, data, spec = bech32_decode(address[2:])
    program = convertbits(data, 5, 8, False)
    if hrp != "avax" or spec != "bech32" or program is None or len(program) != 20:
        raise DecodeError("invalid X-Chain address")
    canonical = "X-" + address[2:].lower()
    return canonical, "Avalanche X-Chain (Bech32)", canonical.lower()


def _base58_versions(address: str, allowed: dict[int, str], prefix_hint: str) -> tuple[str, str, str]:
    if not _B58_RE.match(address):
        raise DecodeError(f"expected a Base58 address starting with {prefix_hint}")
    payload = b58check_decode(address)
    if len(payload) != 21 or payload[0] not in allowed:
        raise DecodeError(f"wrong version byte — expected an address starting with {prefix_hint}")
    return address, allowed[payload[0]], address  # Base58 is case-sensitive: key keeps case


def _validate_btc(address: str) -> tuple[str, str, str]:
    if address.lower().startswith("bc1"):
        version, _ = segwit_decode("bc", address)
        fmt = "SegWit v0 (Bech32)" if version == 0 else ("Taproot (Bech32m)" if version == 1 else f"SegWit v{version}")
        return address.lower(), fmt, address.lower()
    return _base58_versions(address, {0x00: "P2PKH (legacy)", 0x05: "P2SH"}, "1, 3 or bc1")


def _validate_ltc(address: str) -> tuple[str, str, str]:
    if address.lower().startswith("ltc1"):
        version, _ = segwit_decode("ltc", address)
        return address.lower(), "SegWit (Bech32)" if version == 0 else f"SegWit v{version}", address.lower()
    return _base58_versions(address, {0x30: "P2PKH (L…)", 0x32: "P2SH (M…)"}, "L, M or ltc1")


def _validate_trx(address: str) -> tuple[str, str, str]:
    if len(address) != 34 or not address.startswith("T"):
        raise DecodeError("expected 34 characters starting with T")
    return _base58_versions(address, {0x41: "Base58Check"}, "T")


def _validate_doge(address: str) -> tuple[str, str, str]:
    return _base58_versions(address, {0x1E: "P2PKH (D…)"}, "D")


def _validate_dash(address: str) -> tuple[str, str, str]:
    return _base58_versions(address, {0x4C: "P2PKH (X…)"}, "X")


def _validate_bch(address: str) -> tuple[str, str, str]:
    lower = address.lower()
    if lower.startswith("bitcoincash:") or _BARE_CASHADDR_RE.match(lower):
        prefix, addr_type, hash_bytes = cashaddr_decode(address)
        if prefix != "bitcoincash":
            raise DecodeError("expected the bitcoincash: prefix")
        if addr_type not in (0, 1):
            raise DecodeError("unknown CashAddr type")
        canonical = cashaddr_encode("bitcoincash", addr_type, hash_bytes)
        return canonical, "CashAddr " + ("P2PKH" if addr_type == 0 else "P2SH"), canonical
    if _B58_RE.match(address) and address[0] in "13":
        payload = b58check_decode(address)
        if len(payload) != 21 or payload[0] not in (0x00, 0x05):
            raise DecodeError("wrong version byte for a legacy address")
        addr_type = 0 if payload[0] == 0x00 else 1
        canonical = cashaddr_encode("bitcoincash", addr_type, payload[1:])
        return canonical, "Legacy (converted to CashAddr)", canonical
    raise DecodeError("expected bitcoincash:q…/p…, a bare q…/p… CashAddr, or a legacy 1…/3… address")


def _validate_ada(address: str) -> tuple[str, str, str]:
    if not address.lower().startswith("addr1"):
        raise DecodeError("expected a mainnet Shelley address starting with addr1")
    hrp, data, spec = bech32_decode(address, max_length=1023)  # Cardano exceeds Bech32's 90-char limit
    payload = convertbits(data, 5, 8, False)
    if hrp != "addr" or spec != "bech32" or not payload:
        raise DecodeError("invalid Bech32 payload")
    header = payload[0]
    addr_type, network = header >> 4, header & 0x0F
    if network != 1:
        raise DecodeError("not a mainnet address")
    expected = {0: 57, 1: 57, 2: 57, 3: 57, 6: 29, 7: 29}
    if addr_type in expected and len(payload) != expected[addr_type]:
        raise DecodeError("wrong length for its address type")
    if addr_type in (4, 5) and len(payload) < 32:
        raise DecodeError("pointer address too short")
    if addr_type > 7:
        raise DecodeError("not a payment address")
    kinds = {0: "base", 1: "base", 2: "base", 3: "base", 4: "pointer", 5: "pointer", 6: "enterprise", 7: "enterprise"}
    return address.lower(), f"Shelley {kinds[addr_type]} address", address.lower()


# --- XRP ADDITION ------------------------------------------------------------

def _validate_xrp(address: str) -> tuple[str, str, str]:
    if _XRP_X_ADDRESS_RE.match(address):
        raise DecodeError("X-addresses aren't accepted — enter the classic r… address and put the "
                          "destination tag in its own field")
    if not _XRP_CLASSIC_RE.match(address):
        raise DecodeError("expected a classic XRP Ledger address starting with r")
    payload = b58check_decode(address.translate(_XRP_TO_B58))
    if len(payload) != 21 or payload[0] != 0x00:
        raise DecodeError("wrong version byte — expected an account address starting with r")
    return address, "XRP Ledger classic address (Base58Check)", address  # case-sensitive, like Base58


def validate_xrp_dest_tag(raw: str | None) -> tuple[str | None, str | None]:
    """A destination tag is required for XRP: returns (normalized, error)."""
    tag = (raw or "").strip()
    if not tag:
        return None, "Enter the destination tag (memo) shown with this XRP address."
    if not tag.isascii() or not tag.isdigit():
        return None, "A destination tag is a whole number (digits only)."
    value = int(tag)
    if value > XRP_DEST_TAG_MAX:
        return None, f"A destination tag is at most {XRP_DEST_TAG_MAX}."
    return str(value), None

# ------------------------------------------------------------ end XRP ADDITION


_VALIDATORS = {
    "btc": _validate_btc,
    "ltc": _validate_ltc,
    "trx": _validate_trx,
    "doge": _validate_doge,
    "dash": _validate_dash,
    "bch": _validate_bch,
    "ada": _validate_ada,
    "xrp": _validate_xrp,  # XRP ADDITION
}
