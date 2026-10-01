"""Address encodings used by the supported chains (stdlib only).

* Base58 / Base58Check        Bitcoin wiki; double-SHA256 checksum
* Bech32 / Bech32m            BIP-173 / BIP-350 reference algorithm (P. Wuille)
* CashAddr                    Bitcoin Cash address spec (40-bit BCH checksum)
* Keccak-256                  as used by Ethereum (NOT NIST SHA3-256); uses
                              pycryptodome when installed, else the pure-Python
                              permutation below (verified against the same
                              test vectors in tests/unit/test_codecs.py)

These are direct transcriptions of the published reference code, kept here
so validation has no network-installed moving parts and can be tested in
isolation.
"""
from __future__ import annotations

import hashlib

# ----------------------------------------------------------------- Base58

B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(B58_ALPHABET)}


class DecodeError(ValueError):
    """The string is not a valid encoding (bad characters, length or checksum)."""


def b58decode(text: str) -> bytes:
    n = 0
    for ch in text:
        try:
            n = n * 58 + _B58_INDEX[ch]
        except KeyError as exc:
            raise DecodeError(f"invalid Base58 character {ch!r}") from exc
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    leading_zeros = len(text) - len(text.lstrip("1"))
    return b"\x00" * leading_zeros + body


def b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = []
    while n:
        n, rem = divmod(n, 58)
        out.append(B58_ALPHABET[rem])
    leading_zeros = len(data) - len(data.lstrip(b"\x00"))
    return "1" * leading_zeros + "".join(reversed(out))


def _double_sha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def b58check_decode(text: str) -> bytes:
    """Return version+payload after verifying the 4-byte checksum."""
    raw = b58decode(text)
    if len(raw) < 5:
        raise DecodeError("too short for Base58Check")
    payload, checksum = raw[:-4], raw[-4:]
    if _double_sha256(payload)[:4] != checksum:
        raise DecodeError("Base58Check checksum mismatch")
    return payload


def b58check_encode(payload: bytes) -> str:
    return b58encode(payload + _double_sha256(payload)[:4])


# ----------------------------------------------------- Bech32 / Bech32m

BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32_CONST = 1
BECH32M_CONST = 0x2BC830A3


def _bech32_polymod(values) -> int:
    generator = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp: str) -> list[int]:
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_create_checksum(hrp: str, data: list[int], spec: str) -> list[int]:
    const = BECH32M_CONST if spec == "bech32m" else BECH32_CONST
    polymod = _bech32_polymod(_bech32_hrp_expand(hrp) + data + [0] * 6) ^ const
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def bech32_encode(hrp: str, data: list[int], spec: str = "bech32") -> str:
    combined = data + bech32_create_checksum(hrp, data, spec)
    return hrp + "1" + "".join(BECH32_CHARSET[d] for d in combined)


def bech32_decode(text: str, max_length: int = 90) -> tuple[str, list[int], str]:
    """Return (hrp, data-without-checksum, "bech32" | "bech32m")."""
    if any(ord(ch) < 33 or ord(ch) > 126 for ch in text):
        raise DecodeError("invalid character")
    if text.lower() != text and text.upper() != text:
        raise DecodeError("mixed upper and lower case")
    text = text.lower()
    pos = text.rfind("1")
    if pos < 1 or pos + 7 > len(text) or len(text) > max_length:
        raise DecodeError("invalid Bech32 length or separator")
    if not all(ch in BECH32_CHARSET for ch in text[pos + 1:]):
        raise DecodeError("invalid Bech32 character")
    hrp = text[:pos]
    data = [BECH32_CHARSET.find(ch) for ch in text[pos + 1:]]
    const = _bech32_polymod(_bech32_hrp_expand(hrp) + data)
    if const == BECH32_CONST:
        spec = "bech32"
    elif const == BECH32M_CONST:
        spec = "bech32m"
    else:
        raise DecodeError("Bech32 checksum mismatch")
    return hrp, data[:-6], spec


def convertbits(data, frombits: int, tobits: int, pad: bool = True) -> list[int] | None:
    acc = 0
    bits = 0
    ret: list[int] = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def segwit_decode(hrp: str, address: str) -> tuple[int, bytes]:
    """BIP-173/350 segwit address -> (witness version, witness program)."""
    hrp_got, data, spec = bech32_decode(address)
    if hrp_got != hrp:
        raise DecodeError(f"expected prefix {hrp}1, got {hrp_got}1")
    if not data:
        raise DecodeError("empty witness data")
    program = convertbits(data[1:], 5, 8, False)
    if program is None or not 2 <= len(program) <= 40:
        raise DecodeError("invalid witness program length")
    version = data[0]
    if version > 16:
        raise DecodeError("invalid witness version")
    if version == 0 and len(program) not in (20, 32):
        raise DecodeError("invalid v0 witness program length")
    if (version == 0 and spec != "bech32") or (version != 0 and spec != "bech32m"):
        raise DecodeError("wrong checksum variant for this witness version (Bech32 vs Bech32m)")
    return version, bytes(program)


def segwit_encode(hrp: str, version: int, program: bytes) -> str:
    spec = "bech32" if version == 0 else "bech32m"
    return bech32_encode(hrp, [version] + convertbits(program, 8, 5), spec)


# ---------------------------------------------------------------- CashAddr

_CASHADDR_SIZES = (20, 24, 28, 32, 40, 48, 56, 64)


def _cashaddr_polymod(values) -> int:
    c = 1
    for d in values:
        c0 = c >> 35
        c = ((c & 0x07FFFFFFFF) << 5) ^ d
        if c0 & 0x01:
            c ^= 0x98F2BC8E61
        if c0 & 0x02:
            c ^= 0x79B76D99E2
        if c0 & 0x04:
            c ^= 0xF33E5FB3C4
        if c0 & 0x08:
            c ^= 0xAE2EABE2A8
        if c0 & 0x10:
            c ^= 0x1E4F43E470
    return c ^ 1


def _cashaddr_prefix_expand(prefix: str) -> list[int]:
    return [ord(x) & 0x1F for x in prefix] + [0]


def cashaddr_decode(address: str, default_prefix: str = "bitcoincash") -> tuple[str, int, bytes]:
    """Return (prefix, type, hash) where type 0 = P2PKH, 1 = P2SH."""
    if address.lower() != address and address.upper() != address:
        raise DecodeError("mixed upper and lower case")
    address = address.lower()
    prefix, sep, payload = address.rpartition(":")
    if not sep:
        prefix, payload = default_prefix, address
    if not payload or any(ch not in BECH32_CHARSET for ch in payload):
        raise DecodeError("invalid CashAddr character")
    data = [BECH32_CHARSET.find(ch) for ch in payload]
    if len(data) < 9 or _cashaddr_polymod(_cashaddr_prefix_expand(prefix) + data) != 0:
        raise DecodeError("CashAddr checksum mismatch")
    decoded = convertbits(data[:-8], 5, 8, False)
    if not decoded:
        raise DecodeError("invalid CashAddr padding")
    version, hash_bytes = decoded[0], bytes(decoded[1:])
    if version & 0x80:
        raise DecodeError("invalid CashAddr version byte")
    addr_type = (version >> 3) & 0x0F
    if _CASHADDR_SIZES[version & 0x07] != len(hash_bytes):
        raise DecodeError("CashAddr hash length does not match its version byte")
    return prefix, addr_type, hash_bytes


def cashaddr_encode(prefix: str, addr_type: int, hash_bytes: bytes) -> str:
    version = (addr_type << 3) | _CASHADDR_SIZES.index(len(hash_bytes))
    payload = convertbits([version] + list(hash_bytes), 8, 5, True)
    checksum = _cashaddr_polymod(_cashaddr_prefix_expand(prefix) + payload + [0] * 8)
    payload += [(checksum >> 5 * (7 - i)) & 0x1F for i in range(8)]
    return prefix + ":" + "".join(BECH32_CHARSET[d] for d in payload)


# -------------------------------------------------------------- Keccak-256

_RC = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)
# Rotation offsets r[x][y]
_ROT = ((0, 36, 3, 41, 18), (1, 44, 10, 45, 2), (62, 6, 43, 15, 61), (28, 55, 25, 21, 56), (27, 20, 39, 8, 14))
_MASK64 = (1 << 64) - 1


def _rol64(value: int, shift: int) -> int:
    return ((value << shift) | (value >> (64 - shift))) & _MASK64 if shift else value


def _keccak_f1600(state: list[list[int]]) -> list[list[int]]:
    a = state
    for rc in _RC:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol64(c[(x + 1) % 5], 1) for x in range(5)]
        a = [[a[x][y] ^ d[x] for y in range(5)] for x in range(5)]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rol64(a[x][y], _ROT[x][y])
        a = [[b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y]) for y in range(5)] for x in range(5)]
        a[0][0] ^= rc
    return a


def _keccak256_pure(data: bytes) -> bytes:
    rate = 136  # bytes, for a 256-bit output
    padded = bytearray(data)
    padded.append(0x01)  # Keccak domain padding (SHA3 would use 0x06)
    while len(padded) % rate:
        padded.append(0)
    padded[-1] |= 0x80
    state = [[0] * 5 for _ in range(5)]
    for offset in range(0, len(padded), rate):
        block = padded[offset:offset + rate]
        for i in range(rate // 8):
            state[i % 5][i // 5] ^= int.from_bytes(block[8 * i:8 * i + 8], "little")
        state = _keccak_f1600(state)
    return b"".join(state[i % 5][i // 5].to_bytes(8, "little") for i in range(4))


try:  # prefer the well-tested C implementation when available
    from Crypto.Hash import keccak as _pycryptodome_keccak  # type: ignore[import-not-found]

    def keccak256(data: bytes) -> bytes:
        return _pycryptodome_keccak.new(digest_bits=256, data=data).digest()

    KECCAK_BACKEND = "pycryptodome"
except ImportError:  # pragma: no cover - exercised where pycryptodome is absent
    keccak256 = _keccak256_pure
    KECCAK_BACKEND = "pure-python"


def eip55_checksum(address_hex40: str) -> str:
    """'0x' + EIP-55 mixed-case checksum encoding of 40 hex characters."""
    lower = address_hex40.lower()
    digest = keccak256(lower.encode("ascii")).hex()
    return "0x" + "".join(ch.upper() if ch.isalpha() and int(digest[i], 16) >= 8 else ch for i, ch in enumerate(lower))
