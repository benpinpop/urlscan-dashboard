"""Wallet chain detection and checksum validation, ported from the ScamHunt CTF.

Provenance
  codecs.py   byte-identical copy of scamhunt-ctf backend/scamhunt/validation/codecs.py
  wallets.py  copy of scamhunt-ctf backend/scamhunt/validation/wallets.py; the ONLY
              changes are the blocks marked "XRP ADDITION" (classic r… addresses
              and destination tags, added for the Scambusters reporter).

Stdlib only: no Flask imports, so it can be unit-tested in isolation. Keccak-256
uses pycryptodome when installed and a verified pure-Python fallback otherwise.
"""
from .wallets import (
    CHAINS,
    EVM_CHAINS,
    OTHER_CHAINS,
    XRP_DEST_TAG_MAX,
    Detection,
    WalletCheck,
    detect_chain,
    validate_wallet,
    validate_xrp_dest_tag,
)

__all__ = [
    "CHAINS", "EVM_CHAINS", "OTHER_CHAINS", "XRP_DEST_TAG_MAX", "Detection", "WalletCheck",
    "detect_chain", "validate_wallet", "validate_xrp_dest_tag",
]
