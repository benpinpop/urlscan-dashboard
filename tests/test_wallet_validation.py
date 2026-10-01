"""Wallet validation, ported from the ScamHunt CTF.

Everything above the XRP section is the CTF's own test data and assertions
(tests/unit/test_wallets.py and test_codecs.py there), rewritten from pytest
into unittest to match this repo. Passing them shows the port behaves the same.
Nothing here reaches the network.
"""

import json
import pathlib
import random
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from wallet_validation import codecs  # noqa: E402
from wallet_validation.codecs import (  # noqa: E402
    B58_ALPHABET,
    DecodeError,
    b58check_decode,
    b58check_encode,
    bech32_decode,
    bech32_encode,
    cashaddr_decode,
    cashaddr_encode,
    convertbits,
    eip55_checksum,
    segwit_decode,
    segwit_encode,
)
from wallet_validation.wallets import (  # noqa: E402
    CHAINS,
    EVM_CHAINS,
    XRP_ALPHABET,
    detect_chain,
    validate_wallet,
    validate_xrp_dest_tag,
)

RNG = random.Random(1337)


def _hash20():
    return bytes(RNG.randrange(256) for _ in range(20))


def b58(version):
    return b58check_encode(bytes([version]) + _hash20())


VALID = {
    "btc": ["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"],
    "eth": ["0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "0xde709f2102306220921060314715629080e2fb77",
            "0x52908400098527886E0F7030069857D2E4169EE7"],
    "trx": ["TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", b58(0x41)],
    "ltc": [b58(0x30), b58(0x32), segwit_encode("ltc", 0, _hash20())],
    "doge": [b58(0x1E)],
    "dash": [b58(0x4C)],
    "bch": ["bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a", "qr95sy3j9xwd2ap32xkykttr4cvcu7as4y0qverfuy",
            "BITCOINCASH:QPM2QSZNHKS23Z7629MMS6S4CWEF74VCWVY22GDX6A", "1BpEi6DfDAUFd7GtittLSdBeYJvcoaVggu"],
    "ada": ["addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x",
            "addr1vx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzers66hrl8"],
    "avax": ["0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
             "X-" + bech32_encode("avax", convertbits(_hash20(), 8, 5), "bech32")],
}

INVALID = [
    ("btc", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb", "checksum"),
    ("btc", "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", "looks like a Tron"),
    ("trx", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "34 characters"),
    ("trx", b58(0x00)[:33] + "1", ""),
    ("ltc", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "version"),
    ("doge", b58(0x1E)[:-1] + "x", ""),
    ("eth", "0x123", "40 hexadecimal"),
    ("eth", "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", "looks like a Tron"),
    ("bch", "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6q", "checksum"),
    ("bch", "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6b", "character"),
    ("ada", "addr1vx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzers66hrl9", "checksum"),
    ("ada", "addr_test1vz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzerspjrlsz", ""),
    ("avax", "X-avax1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq", ""),
    ("btc", "", "Enter a wallet"),
    ("btc", "1A1zP1eP5QGefi2DMPT fTL5SLmv7DivfNa", "spaces"),
    ("xmr", "4abc", "Unsupported"),
]

DETECTION = [
    ("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "eth", EVM_CHAINS),
    ("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "btc", ("btc", "bch")),
    ("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "btc", ("btc",)),
    ("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", "trx", ("trx",)),
    (b58(0x30), "ltc", ("ltc",)),
    ("ltc1qw508d6qejxtdg4y5r3zarvary0c5xw7kgmn4n9", "ltc", ("ltc",)),
    (b58(0x1E), "doge", ("doge",)),
    (b58(0x4C), "dash", ("dash",)),
    ("qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a", "bch", ("bch",)),
    ("bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a", "bch", ("bch",)),
    ("addr1vx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzers66hrl8", "ada", ("ada",)),
    ("X-avax1abc", "avax", ("avax",)),
    ("hello", None, ()),
    ("", None, ()),
]


class PortedWalletTests(unittest.TestCase):
    """The CTF's tests/unit/test_wallets.py."""

    def test_valid_addresses(self):
        for chain, addresses in VALID.items():
            for address in addresses:
                with self.subTest(chain=chain, address=address):
                    check = validate_wallet(chain, address)
                    self.assertTrue(check.valid, check.errors)
                    self.assertTrue(check.key.startswith(chain + ":"))

    def test_every_evm_chain_accepts_0x(self):
        for chain in EVM_CHAINS:
            with self.subTest(chain=chain):
                self.assertTrue(validate_wallet(chain, "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed").valid)

    def test_evm_checksum_typo_rejected(self):
        check = validate_wallet("eth", "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD")  # last char case flipped
        self.assertFalse(check.valid)
        self.assertIn("EIP-55", check.errors[0])

    def test_evm_canonical_and_per_chain_keys(self):
        lower = "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"
        eth, bsc = validate_wallet("eth", lower), validate_wallet("bsc", lower.upper().replace("0X", "0x"))
        self.assertEqual(eth.canonical, "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed")
        self.assertEqual((eth.key, bsc.key), ("eth:" + lower, "bsc:" + lower))

    def test_bch_legacy_and_cashaddr_share_a_key(self):
        legacy = validate_wallet("bch", "1BpEi6DfDAUFd7GtittLSdBeYJvcoaVggu")
        cash = validate_wallet("bch", "qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a")
        self.assertEqual(legacy.canonical, "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a")
        self.assertEqual(legacy.canonical, cash.canonical)
        self.assertEqual(legacy.key, cash.key)

    def test_base58_keys_are_case_sensitive_bech32_keys_are_not(self):
        self.assertEqual(validate_wallet("btc", "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4").key,
                         "btc:bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
        self.assertEqual(validate_wallet("btc", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").key,
                         "btc:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")

    def test_invalid_addresses(self):
        for chain, address, fragment in INVALID:
            with self.subTest(chain=chain, address=address):
                check = validate_wallet(chain, address)
                self.assertFalse(check.valid)
                self.assertIn(fragment, " ".join(check.errors))

    def test_every_generated_version_byte_starts_with_documented_letter(self):
        for _ in range(50):
            for version, letter in ((0x41, "T"), (0x30, "L"), (0x32, "M"), (0x1E, "D"), (0x4C, "X"),
                                    (0x00, "1"), (0x05, "3")):
                self.assertTrue(b58(version).startswith(letter))

    def test_detection(self):
        for address, chain, candidates in DETECTION:
            with self.subTest(address=address):
                detection = detect_chain(address)
                self.assertEqual(detection.chain, chain)
                self.assertEqual(tuple(detection.candidates), tuple(candidates))

    def test_evm_detection_explains_ambiguity(self):
        self.assertIn("every EVM chain", detect_chain("0x" + "ab" * 20).note)

    def test_detail_is_json_serializable(self):
        json.dumps(validate_wallet("eth", "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed").detail())


class PortedCodecTests(unittest.TestCase):
    """The CTF's tests/unit/test_codecs.py (published test vectors)."""

    def test_keccak256_vectors(self):
        for impl in {codecs.keccak256, codecs._keccak256_pure}:
            self.assertEqual(impl(b"").hex(), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
            self.assertEqual(impl(b"abc").hex(), "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")

    def test_keccak_pure_matches_backend_across_block_boundaries(self):
        data = bytes(range(256)) * 4
        for length in (0, 1, 134, 135, 136, 137, 271, 272, 1000):
            self.assertEqual(codecs._keccak256_pure(data[:length]), codecs.keccak256(data[:length]))

    def test_eip55_vectors(self):
        for address in ("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
                        "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB", "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"):
            self.assertEqual(eip55_checksum(address[2:]), address)
            self.assertEqual(eip55_checksum(address[2:].lower()), address)

    def test_base58check_vectors(self):
        for address, version in (("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", 0x00), ("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", 0x00),
                                 ("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", 0x05), ("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", 0x41)):
            payload = b58check_decode(address)
            self.assertEqual((payload[0], len(payload)), (version, 21))
            self.assertEqual(b58check_encode(payload), address)

    def test_base58check_rejects_typo(self):
        for text in ("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb", "0OIl"):
            with self.assertRaises(DecodeError):
                b58check_decode(text)

    def test_segwit_vectors(self):
        for address, version, prefix in (
            ("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", 0, "751e76e8"),
            ("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3", 0, "1863143c"),
            ("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", 1, "79be667e"),
        ):
            got_version, program = segwit_decode("bc", address)
            self.assertEqual(got_version, version)
            self.assertTrue(program.hex().startswith(prefix))
            self.assertEqual(segwit_encode("bc", got_version, program), address.lower())

    def test_segwit_rejections(self):
        for address in ("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd",
                        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
                        "bc1Qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
                        "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"):
            with self.assertRaises(DecodeError):
                segwit_decode("bc", address)

    def test_cashaddr_vectors(self):
        for legacy, cashaddr in (
            ("1BpEi6DfDAUFd7GtittLSdBeYJvcoaVggu", "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a"),
            ("1KXrWXciRDZUpQwQmuM1DbwsKDLYAYsVLR", "bitcoincash:qr95sy3j9xwd2ap32xkykttr4cvcu7as4y0qverfuy"),
            ("3CWFddi6m4ndiGyKqzYvsFYagqDLPVMTzC", "bitcoincash:ppm2qsznhks23z7629mms6s4cwef74vcwvn0h829pq"),
        ):
            payload = b58check_decode(legacy)
            addr_type = 0 if payload[0] == 0x00 else 1
            self.assertEqual(cashaddr_encode("bitcoincash", addr_type, payload[1:]), cashaddr)
            self.assertEqual(cashaddr_decode(cashaddr), ("bitcoincash", addr_type, payload[1:]))
            self.assertEqual(cashaddr_decode(cashaddr.split(":")[1]), ("bitcoincash", addr_type, payload[1:]))
            with self.assertRaises(DecodeError):
                cashaddr_decode(cashaddr[:-1] + ("q" if cashaddr[-1] != "q" else "p"))

    def test_cardano_bech32_vectors(self):
        for address, header, length in (
            ("addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x", 0x01, 57),
            ("addr1vx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzers66hrl8", 0x61, 29),
        ):
            hrp, data, spec = bech32_decode(address, max_length=1023)
            payload = bytes(convertbits(data, 5, 8, False))
            self.assertEqual((hrp, spec, payload[0], len(payload)), ("addr", "bech32", header, length))


# ----------------------------------------------------------------- XRP ADDITION

XRP_VALID = [
    "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",   # genesis account
    "rrrrrrrrrrrrrrrrrrrrrhoLvTp",          # ACCOUNT_ZERO
    "rrrrrrrrrrrrrrrrrrrrBZbvji",           # ACCOUNT_ONE
    "rrrrrrrrrrrrrrrrrNAMEtxvNvQ",          # name-reservation black hole
    "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe",   # XRPL documentation examples
    "rf1BiGeXwwQoi8Z2ueFYTEXSwuJYfV2Jpn",
]


class XrpTests(unittest.TestCase):
    def test_encoding_reproduces_the_published_special_accounts(self):
        to_xrp = str.maketrans(B58_ALPHABET, XRP_ALPHABET)
        self.assertEqual(b58check_encode(bytes(21)).translate(to_xrp), "rrrrrrrrrrrrrrrrrrrrrhoLvTp")
        self.assertEqual(b58check_encode(bytes(20) + b"\x01").translate(to_xrp), "rrrrrrrrrrrrrrrrrrrrBZbvji")

    def test_valid_addresses_are_detected_and_accepted(self):
        for address in XRP_VALID:
            with self.subTest(address=address):
                check = validate_wallet("xrp", address)
                self.assertTrue(check.valid, check.errors)
                self.assertEqual((check.canonical, check.key), (address, "xrp:" + address))
                self.assertEqual(detect_chain(address).chain, "xrp")
                self.assertIn("destination tag", detect_chain(address).note)

    def test_rejections(self):
        cases = [
            ("rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTi", "checksum"),                      # last char changed
            ("X7AcgcsBL6XDcUb289X4mJ8djcdyKaB5hJDWMArnXr61cqZ", "X-addresses"),   # tag-embedding format
            ("rHb9CJAWyB4rj91VRWn96Dk", "starting with r"),                          # too short
            ("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "looks like a Ethereum"),
        ]
        for address, fragment in cases:
            with self.subTest(address=address):
                check = validate_wallet("xrp", address)
                self.assertFalse(check.valid)
                self.assertIn(fragment, " ".join(check.errors))

    def test_xrp_address_on_another_chain_is_blocked(self):
        check = validate_wallet("btc", "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh")
        self.assertFalse(check.valid)
        self.assertIn("looks like a XRP Ledger", check.errors[0])

    def test_dash_and_tron_are_not_mistaken_for_x_addresses(self):
        self.assertEqual(detect_chain(b58(0x4C)).chain, "dash")
        self.assertEqual(detect_chain("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t").chain, "trx")

    def test_destination_tag_is_required_and_bounded(self):
        self.assertEqual(validate_xrp_dest_tag("12345"), ("12345", None))
        self.assertEqual(validate_xrp_dest_tag(" 007 "), ("7", None))
        self.assertEqual(validate_xrp_dest_tag("4294967295"), ("4294967295", None))
        for bad in ("", "   ", "-1", "1.5", "abc", "4294967296", "１２"):
            with self.subTest(tag=bad):
                value, error = validate_xrp_dest_tag(bad)
                self.assertIsNone(value)
                self.assertTrue(error)

    def test_chain_list(self):
        self.assertEqual(set(CHAINS), {"btc", "eth", "trx", "xrp", "bsc", "ltc", "doge", "bch", "ada", "dash",
                                       "matic", "arb", "avax", "op"})


if __name__ == "__main__":
    unittest.main()
