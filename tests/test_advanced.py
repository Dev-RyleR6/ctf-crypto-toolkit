from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import crypto_advanced as advanced
import crypto_toolkit as crypto


ROOT = Path(crypto.__file__).resolve().parent
HAS_AES = importlib.util.find_spec("cryptography") is not None


class CliMixin:
    def invoke(self, *args):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            code = crypto.main(list(args))
        return code, output.getvalue(), errors.getvalue()


class LfsrTests(CliMixin, unittest.TestCase):
    def test_manual_four_bit_sequence_and_packing(self):
        state = [1, 0, 0, 1]
        bits = advanced.lfsr_bits(state, [0, 3], 8)
        self.assertEqual(bits, [1, 0, 0, 1, 0, 0, 0, 1])
        self.assertEqual(advanced.pack_bits(bits), b"\x91")
        self.assertEqual(advanced.pack_bits(bits, "lsb"), b"\x89")
        self.assertEqual(state, [1, 0, 0, 1])

    def test_output_bit_and_skip(self):
        self.assertEqual(advanced.lfsr_bits([1, 0, 0, 1], [0, 3], 8, output_bit="feedback"),
                         [0, 0, 0, 1, 1, 1, 1, 0])
        self.assertEqual(advanced.lfsr_bits([1, 0, 0, 1], [0, 3], 8, output_bit="last"),
                         [1, 0, 0, 0, 1, 1, 1, 1])
        self.assertEqual(advanced.lfsr_bits([1, 0, 0, 1], [0, 3], 4, skip=4), [0, 0, 0, 1])

    def test_tap_conventions_and_right_shift(self):
        self.assertEqual(advanced.lfsr_bits([1, 0, 0, 1], [1, 4], 8, tap_base=1),
                         [1, 0, 0, 1, 0, 0, 0, 1])
        state = [1, 0, 1, 1]
        expected = advanced.lfsr_bits(state, [0, 1], 32)
        self.assertEqual(advanced.lfsr_bits(state, [3, 2], 32, tap_origin="right"), expected)
        self.assertEqual(advanced.lfsr_bits(state[::-1], [3, 2], 32, shift="right", output_bit="last"), expected)

    def test_independent_integer_reference_key(self):
        state, taps, _ = advanced.read_lfsr_output(ROOT / "examples" / "lfsr_aes_demo.txt")
        self.assertEqual(advanced.pack_bits(advanced.lfsr_bits(state, taps, 128)).hex(),
                         "9a2561cdf44ac39be8958737d12b0e6f")

    def test_invalid_states_taps_and_lengths(self):
        for value in ("", "012", "[]", "[true, 0]", '["1", 0]', "[0, 2]", "[0,"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                advanced.parse_state(value)
        for value in ("", "[0, 0]", "[true]", "[0,", "a,1", "[1.5]"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                advanced.parse_taps(value)
        for taps, count, options in (([4], 8, {}), ([-1], 8, {}), ([0], 0, {}),
                                     ([0], 8, {"skip": -1}), ([0], 8, {"tap_base": 1})):
            with self.assertRaises(ValueError):
                advanced.lfsr_bits([1, 0, 0, 1], taps, count, **options)
        with self.assertRaises(ValueError):
            advanced.pack_bits([1, 0, 1])

    def test_state_parsing_preserves_leading_zeros(self):
        self.assertEqual(advanced.parse_state("0010"), [0, 0, 1, 0])
        self.assertEqual(advanced.parse_state("[0, 0, 1, 0]"), [0, 0, 1, 0])

    def test_lfsr_cli_formats(self):
        prefix = ("lfsr", "--state", "1001", "--taps", "0,3")
        self.assertEqual(self.invoke(*prefix, "--bits", "8")[1].strip(), "91")
        self.assertEqual(self.invoke(*prefix, "--bits", "8", "--format", "base64")[1].strip(), "kQ==")
        self.assertEqual(self.invoke(*prefix, "--bits", "5", "--format", "bits")[1].strip(), "10010")
        self.assertEqual(self.invoke(*prefix, "--bits", "5")[0], 1)
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "key.hex"
            self.assertEqual(self.invoke(*prefix, "--bits", "8", "--out", str(output))[0], 0)
            self.assertEqual(output.read_bytes(), b"91")
            self.assertEqual(self.invoke(*prefix, "--bits", "8", "--out", str(output))[0], 1)

    def test_parser_rejects_executable_or_extra_content(self):
        good = (ROOT / "examples" / "lfsr_aes_demo.txt").read_text()
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "input.txt"
            for content in ("", good + "\nUnexpected extra field", good.replace("[7, 5, 4, 3]", "[__import__('os')]"),
                            good.replace("[7, 5, 4, 3]", "[true]"), good.replace("6704", "xyz")):
                path.write_text(content, encoding="utf-8")
                with self.assertRaises(ValueError):
                    advanced.read_lfsr_output(path)
            path.write_text(good.replace("[7, 5, 4, 3]", "[7,\n5, 4, 3]"), encoding="utf-8-sig")
            self.assertEqual(advanced.read_lfsr_output(path)[1], [7, 5, 4, 3])


class DocumentationTests(CliMixin, unittest.TestCase):
    def test_topics_and_export(self):
        for topic in crypto.DOC_TOPICS + ("all",):
            with self.subTest(topic=topic):
                code, out, err = self.invoke("docs", topic)
                self.assertEqual(code, 0, err)
                self.assertIn("ctf-crypto", out)
        self.assertIn("lfsr-aes", self.invoke("docs", "--list")[1])
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "guide.md"
            self.assertEqual(self.invoke("docs", "all", "--out", str(target))[0], 0)
            content = target.read_text(encoding="utf-8")
            self.assertIn("# AES decryption", content)
            self.assertEqual(self.invoke("docs", "all", "--out", str(target))[0], 1)
            self.assertEqual(target.read_text(encoding="utf-8"), content)

    def test_base_commands_work_without_site_packages(self):
        for args in (("docs", "aes"), ("lfsr", "--state", "1001", "--taps", "0,3", "--bits", "8"),
                     ("decode", "--from", "hex", "--text", "4869")):
            result = subprocess.run([sys.executable, "-S", str(ROOT / "crypto_toolkit.py"), *args],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
        result = subprocess.run([sys.executable, "-S", str(ROOT / "crypto_toolkit.py"), "aes",
                                 "--mode", "ecb", "--key", "00" * 16, "--text", "00" * 16,
                                 "--input-format", "hex", "--padding", "none"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("pip install cryptography", result.stderr)
        self.assertNotIn("Traceback", result.stderr)


@unittest.skipUnless(HAS_AES, "Optional cryptography package not installed")
class AesTests(CliMixin, unittest.TestCase):
    KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    PLAIN = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
    ECB = bytes.fromhex("3ad77bb40d7a3660a89ecaf32466ef97")
    CBC = bytes.fromhex("7649abac8119b246cee98e9b12e9197d")
    IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

    def test_nist_ecb_key_sizes(self):
        vectors = ((self.KEY, self.ECB),
                   (bytes.fromhex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"),
                    bytes.fromhex("bd334f1d6e45f25ff712a214571fa5cc")),
                   (bytes.fromhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
                    bytes.fromhex("f3eed1bdb5d2a03c064b5a7e3db181f8")))
        for key, ciphertext in vectors:
            self.assertEqual(advanced.aes_decrypt(ciphertext, key, mode="ecb", padding="none"), self.PLAIN)

    def test_nist_cbc_and_prefixed_iv(self):
        self.assertEqual(advanced.aes_decrypt(self.CBC, self.KEY, mode="cbc", iv=self.IV, padding="none"), self.PLAIN)
        self.assertEqual(advanced.aes_decrypt(self.IV + self.CBC, self.KEY, mode="cbc", iv_prefix=True, padding="none"), self.PLAIN)

    def test_padding_and_invalid_parameters(self):
        cases = ((self.ECB, self.KEY, {"mode": "ecb"}),
                 (self.ECB, b"short", {"mode": "ecb"}),
                 (self.ECB, self.KEY, {"mode": "cbc"}),
                 (self.ECB, self.KEY, {"mode": "cbc", "iv": b"short"}),
                 (self.ECB, self.KEY, {"mode": "ecb", "iv": self.IV}),
                 (self.ECB, self.KEY, {"mode": "ecb", "iv_prefix": True}),
                 (self.ECB, self.KEY, {"mode": "cbc", "iv_prefix": True}),
                 (self.CBC, self.KEY, {"mode": "cbc", "iv": self.IV, "iv_prefix": True}),
                 (b"", self.KEY, {"mode": "ecb"}), (b"short", self.KEY, {"mode": "ecb"}))
        for data, key, kwargs in cases:
            with self.subTest(kwargs=kwargs, length=len(data)), self.assertRaises(ValueError):
                advanced.aes_decrypt(data, key, **kwargs)

    def test_combined_fixture_and_file_output(self):
        fixture = ROOT / "examples" / "lfsr_aes_demo.txt"
        code, out, err = self.invoke("lfsr-aes", "--file", str(fixture), "--mode", "ecb")
        self.assertEqual(code, 0, err)
        self.assertIn("9a2561cdf44ac39be8958737d12b0e6f", out)
        self.assertIn("UTF-8: flag{lfsr_aes_demo}", out)
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "plaintext.bin"
            self.assertEqual(self.invoke("lfsr-aes", "--file", str(fixture), "--mode", "ecb", "--out", str(target))[0], 0)
            self.assertEqual(target.read_bytes(), b"flag{lfsr_aes_demo}")
            self.assertEqual(self.invoke("lfsr-aes", "--file", str(fixture), "--mode", "ecb", "--out", str(target))[0], 1)
            self.assertEqual(target.read_bytes(), b"flag{lfsr_aes_demo}")

    def test_no_output_on_padding_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "plaintext.bin"
            code, _, err = self.invoke("aes", "--mode", "ecb", "--key", self.KEY.hex(), "--text", self.ECB.hex(),
                                       "--input-format", "hex", "--out", str(target))
            self.assertEqual(code, 1)
            self.assertIn("PKCS#7", err)
            self.assertFalse(target.exists())

    def test_aes_cli_text_key_base64_and_raw_file(self):
        import base64
        with tempfile.TemporaryDirectory() as folder:
            ciphertext = Path(folder) / "cipher.bin"
            ciphertext.write_bytes(self.ECB)
            code, out, err = self.invoke("aes", "--mode", "ecb", "--key", base64.b64encode(self.KEY).decode(),
                                         "--key-format", "base64", "--file", str(ciphertext), "--padding", "none")
            self.assertEqual(code, 0, err)
            self.assertIn(self.PLAIN.hex(), out)
        code, out, err = self.invoke("aes", "--mode", "ecb", "--key", self.KEY.hex(),
                                     "--text", base64.b64encode(self.ECB).decode(), "--input-format", "base64", "--padding", "none")
        self.assertEqual(code, 0, err)
        self.assertIn(self.PLAIN.hex(), out)


if __name__ == "__main__":
    unittest.main()
