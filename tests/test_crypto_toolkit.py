import base64
from contextlib import redirect_stderr, redirect_stdout
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import crypto_toolkit as crypto


class CryptoTests(unittest.TestCase):
    def test_known_encodings(self):
        cases = {"hex": "4869", "base64": "SGk=", "base32": "JBUQ====",
                 "binary": "01001000 01101001", "url": "Hi"}
        for fmt, encoded in cases.items():
            with self.subTest(fmt=fmt):
                self.assertEqual(crypto.encode(b"Hi", fmt), encoded)
                self.assertEqual(crypto.decode(encoded, fmt), b"Hi")
        self.assertEqual(crypto.decode("a+b%20c", "url"), b"a+b c")

    def test_arbitrary_binary_roundtrip(self):
        for data in (b"", bytes(range(256)), "hello 世界".encode()):
            for fmt in crypto.FORMATS:
                with self.subTest(fmt=fmt, length=len(data)):
                    self.assertEqual(crypto.decode(crypto.encode(data, fmt), fmt), data)

    def test_invalid_encodings(self):
        for value, fmt in (("xyz", "hex"), ("QQ$=", "base64"), ("A", "base64"),
                           ("!", "base32"), ("101", "binary"), ("00000002", "binary"),
                           ("%zz", "url"), ("%2", "url")):
            with self.subTest(value=value, fmt=fmt), self.assertRaises(ValueError):
                crypto.decode(value, fmt)

    def test_caesar_known_vector(self):
        self.assertEqual(crypto.caesar("Attack at Dawn! Zz 世", 3), "Dwwdfn dw Gdzq! Cc 世")
        self.assertEqual(crypto.caesar("Dwwdfn", -3), "Attack")
        self.assertEqual(crypto.caesar("synt{ebg13}", 13), "flag{rot13}")

    def test_repeating_xor_known_vector(self):
        # Cryptopals challenge 5 known-answer vector.
        plain = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
        expected = ("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272"
                    "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")
        self.assertEqual(crypto.xor_bytes(plain, b"ICE").hex(), expected)
        self.assertEqual(crypto.xor_bytes(bytes.fromhex(expected), b"ICE"), plain)
        with self.assertRaises(ValueError):
            crypto.xor_bytes(b"abc", b"")

    def test_single_byte_xor_known_vector(self):
        ciphertext = bytes.fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
        _, key, plain = crypto.crack_single_byte_xor(ciphertext, 1)[0]
        self.assertEqual(key, 0x58)
        self.assertEqual(plain, b"Cooking MC's like a pound of bacon")
        self.assertEqual(len(crypto.crack_single_byte_xor(b"abc", 256)), 256)
        with self.assertRaises(ValueError):
            crypto.crack_single_byte_xor(b"")

    def test_rsa_known_vector_and_validation(self):
        self.assertEqual(crypto.rsa_decrypt(3233, 2753, 2790), (65, b"A"))
        self.assertEqual(crypto.rsa_decrypt(3233, 2753, 0), (0, b"\0"))
        for n, d, c in ((1, 1, 0), (3233, 0, 1), (3233, 2753, 3233), (3233, 2753, -1)):
            with self.assertRaises(ValueError):
                crypto.rsa_decrypt(n, d, c)

    def invoke(self, *args):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            code = crypto.main(list(args))
        return code, output.getvalue(), errors.getvalue()

    def test_cli_hash_inverse_frequency(self):
        self.assertEqual(self.invoke("hash", "--text", "abc")[1].strip(),
                         "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        self.assertEqual(self.invoke("inverse", "17", "3120")[1].strip(), "2753")
        self.assertEqual(self.invoke("inverse", "6", "12")[0], 1)
        self.assertIn("ASCII letters: 0", self.invoke("frequency", "--text", "123")[1])
        self.assertEqual(self.invoke("xor-crack", "--text", "abc", "--top", "0")[0], 1)

    def test_file_roundtrip_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as folder:
            source, dest = Path(folder) / "input.txt", Path(folder) / "out.bin"
            data = bytes(range(256))
            source.write_bytes(base64.b64encode(data))
            args = ("decode", "--from", "base64", "--file", str(source), "--out", str(dest))
            self.assertEqual(self.invoke(*args)[0], 0)
            self.assertEqual(dest.read_bytes(), data)
            self.assertEqual(self.invoke(*args)[0], 1)
            self.assertEqual(dest.read_bytes(), data)

    def test_preview_escapes_control_codes(self):
        _, out, _ = self.invoke("decode", "--from", "hex", "--text", "1b5b326a")
        self.assertNotIn("\x1b", out)

    def test_guide_exercises(self):
        self.assertEqual(crypto.decode("666c61677b7761726d75707d", "hex"), b"flag{warmup}")
        self.assertEqual(crypto.caesar("iodj{fdhvdu}", 23), "flag{caesar}")
        self.assertEqual(crypto.decode("ZmxhZ3t0d29fc3RlcHN9", "base64"), b"flag{two_steps}")
        self.assertEqual(crypto.xor_bytes(bytes.fromhex("2c262b2d3132253837"), b"J"), b"flag{xor}")

    def test_process_entrypoint_and_arg_errors(self):
        script = Path(crypto.__file__)
        result = subprocess.run([sys.executable, str(script), "decode", "--from", "base64",
                                 "--text", "SGVsbG8="], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("UTF-8: Hello", result.stdout)
        result = subprocess.run([sys.executable, str(script), "decode"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
