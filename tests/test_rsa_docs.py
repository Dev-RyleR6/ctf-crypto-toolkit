"""Private-key interoperability, CLI failure cases, and offline guide exports."""

import base64
from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import crypto_docs
import crypto_rsa
import crypto_toolkit


ROOT = Path(crypto_toolkit.__file__).parent
HAS_CRYPTO = importlib.util.find_spec("cryptography") is not None


def cli(*args):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = crypto_toolkit.main(list(args))
    return code, out.getvalue(), err.getvalue()


@unittest.skipUnless(HAS_CRYPTO, "Optional cryptography dependency not installed")
class RsaKeyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
        cls.s, cls.h, cls.p = serialization, hashes, padding
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.plain = b"flag{private_key_demo}\x00\xff"
        cls.oaep = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        cls.cipher = cls.key.public_key().encrypt(cls.plain, cls.oaep)
        cls.pem = cls.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())

    def test_pem_der_pkcs8_pkcs1_and_outer_encodings(self):
        for encoding in (self.s.Encoding.PEM, self.s.Encoding.DER):
            for fmt in (self.s.PrivateFormat.PKCS8, self.s.PrivateFormat.TraditionalOpenSSL):
                key_data = self.key.private_bytes(encoding, fmt, self.s.NoEncryption())
                for outer, data in (("raw", key_data), ("hex", key_data.hex().encode()), ("base64", base64.b64encode(key_data))):
                    with self.subTest(encoding=encoding, fmt=fmt, outer=outer):
                        loaded = crypto_rsa.load_key(data, outer)
                        self.assertEqual(crypto_rsa.decrypt(loaded, self.cipher, "oaep"), self.plain)

    def test_oaep_hash_mgf_and_label(self):
        for name, algorithm in (("sha1", self.h.SHA1), ("sha256", self.h.SHA256), ("sha384", self.h.SHA384), ("sha512", self.h.SHA512)):
            scheme = self.p.OAEP(mgf=self.p.MGF1(self.h.SHA1()), algorithm=algorithm(), label=b"ctf")
            ciphertext = self.key.public_key().encrypt(self.plain, scheme)
            self.assertEqual(crypto_rsa.decrypt(self.key, ciphertext, "oaep", name, "sha1", b"ctf"), self.plain)
            with self.assertRaisesRegex(ValueError, "decryption failed"):
                crypto_rsa.decrypt(self.key, ciphertext, "oaep", name, "sha1", b"wrong")

    def test_pkcs1v15_and_raw_preserve_bytes(self):
        ciphertext = self.key.public_key().encrypt(self.plain, self.p.PKCS1v15())
        self.assertEqual(crypto_rsa.decrypt(self.key, ciphertext, "pkcs1v15"), self.plain)
        n = self.key.private_numbers().public_numbers.n
        raw = pow(65, 65537, n).to_bytes(256, "big")
        self.assertEqual(crypto_rsa.decrypt(self.key, raw, "raw"), bytes(255) + b"A")
        with self.assertRaisesRegex(ValueError, "require --padding oaep"):
            crypto_rsa.decrypt(self.key, raw, "raw", "sha1")

    def test_encrypted_key_passwords_and_non_rsa(self):
        encrypted = self.key.private_bytes(self.s.Encoding.PEM, self.s.PrivateFormat.PKCS8, self.s.BestAvailableEncryption(b"demo"))
        self.assertEqual(crypto_rsa.load_key(encrypted, password=b"demo").key_size, 2048)
        for password in (None, b"wrong"):
            with self.assertRaisesRegex(ValueError, "Cannot load"):
                crypto_rsa.load_key(encrypted, password=password)
        from cryptography.hazmat.primitives.asymmetric import ec
        ec_key = ec.generate_private_key(ec.SECP256R1()).private_bytes(self.s.Encoding.PEM, self.s.PrivateFormat.PKCS8, self.s.NoEncryption())
        with self.assertRaisesRegex(ValueError, "requires an RSA"):
            crypto_rsa.load_key(ec_key)
        for data, encoding in ((b"nonsense", "raw"), (b"not hex", "hex"), (b"$$$", "base64"), (b"\xff", "hex")):
            with self.assertRaises(ValueError):
                crypto_rsa.load_key(data, encoding)

    def test_cli_hex_key_file_and_all_cipher_encodings(self):
        with tempfile.TemporaryDirectory() as folder:
            key_path = Path(folder) / "private.hex"
            # Same outer structure as the user's example, but generated test material only.
            key_path.write_text("\ufeff" + "\n".join(self.pem.hex()[i:i+80] for i in range(0, len(self.pem.hex()), 80)), encoding="utf-8")
            for fmt, content in (("raw", self.cipher), ("hex", self.cipher.hex().encode()), ("base64", base64.b64encode(self.cipher))):
                source, target = Path(folder) / (fmt + ".in"), Path(folder) / (fmt + ".out")
                source.write_bytes(content)
                args = ("rsa-key", "--key-file", str(key_path), "--key-encoding", "hex", "--file", str(source), "--input-format", fmt, "--padding", "oaep", "--out", str(target))
                result = cli(*args)
                self.assertEqual(result[0], 0, result)
                self.assertEqual(target.read_bytes(), self.plain)
                self.assertEqual(cli(*args)[0], 1)
                self.assertEqual(target.read_bytes(), self.plain)

    def test_cli_password_prompt_and_error_no_output(self):
        with tempfile.TemporaryDirectory() as folder:
            key_path, target = Path(folder) / "encrypted.pem", Path(folder) / "out.bin"
            key_path.write_bytes(self.key.private_bytes(self.s.Encoding.PEM, self.s.PrivateFormat.PKCS8, self.s.BestAvailableEncryption(b"demo")))
            args = ("rsa-key", "--key-file", str(key_path), "--ask-password", "--text", self.cipher.hex(), "--input-format", "hex", "--padding", "oaep")
            with patch("crypto_rsa.getpass.getpass", return_value="demo"):
                code, out, err = cli(*args)
                self.assertEqual(code, 0, err)
                self.assertIn(self.plain.hex(), out)
                self.assertNotIn("BEGIN PRIVATE", out)
                code, out, err = cli(*args, "--label-hex", "01", "--out", str(target))
                self.assertEqual(code, 1)
                self.assertFalse(target.exists())
            with patch("crypto_rsa.getpass.getpass", side_effect=EOFError):
                self.assertIn("cancelled", cli(*args)[2])

    def test_cipher_length_range_and_wrong_key(self):
        for data in (b"", self.cipher[:-1], self.cipher + b"\x00", b"\xff" * 256):
            with self.assertRaises(ValueError):
                crypto_rsa.decrypt(self.key, data, "oaep")
        from cryptography.hazmat.primitives.asymmetric import rsa
        wrong = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with self.assertRaises(ValueError):
            crypto_rsa.decrypt(wrong, self.cipher, "oaep")


class VisualDocsTests(unittest.TestCase):
    def test_terminal_and_markdown_formats(self):
        code, out, err = cli("docs", "rsa")
        self.assertEqual(code, 0, err)
        self.assertIn("RSA private-key decryption\n=", out)
        self.assertNotIn("```", out)
        self.assertNotIn("**", out)
        self.assertIn("# RSA private-key decryption", cli("docs", "rsa", "--format", "markdown")[1])

    def test_html_export_complete_and_exclusive(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "guide.html"
            result = cli("docs", "rsa", "--out", str(path))
            self.assertEqual(result[0], 0, result)
            content = path.read_text(encoding="utf-8")
            for topic in crypto_docs.TOPICS:
                self.assertIn('id="' + topic + '"', content)
            self.assertIn('data-start="rsa"', content)
            self.assertIn('class="copy"', content)
            self.assertNotIn("{{", content)
            self.assertNotIn('<script src=', content)
            self.assertEqual(cli("docs", "--out", str(path))[0], 1)
            self.assertEqual(path.read_text(encoding="utf-8"), content)

    def test_browser_open_and_incompatible_format(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "guide.html"
            with patch("crypto_docs.webbrowser.open", return_value=True) as browser:
                result = cli("docs", "rsa", "--open", "--out", str(path))
                self.assertEqual(result[0], 0, result)
                browser.assert_called_once_with(path.as_uri() + "#rsa")
            with patch("crypto_docs.webbrowser.open") as browser:
                self.assertEqual(cli("docs", "--open", "--format", "text")[0], 1)
                browser.assert_not_called()

    def test_markdown_escapes_html_and_unsafe_links(self):
        content = crypto_docs.blocks('# Title\n\n<script>alert(1)</script>\n\n[x](javascript:bad)\n\n```sh\n<x>&\n```')
        self.assertNotIn("<script>", content)
        self.assertNotIn("javascript:", content)
        self.assertIn("&lt;x&gt;&amp;", content)
        self.assertIn('href="#rsa"', crypto_docs.inline("[RSA](rsa.md)"))

    def test_docs_work_without_dependencies_and_rsa_reports_missing(self):
        result = subprocess.run([sys.executable, "-S", str(ROOT / "crypto_toolkit.py"), "docs", "--format", "html"], capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("RSA private-key decryption", result.stdout)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "key.pem"
            path.write_bytes(b"placeholder")
            result = subprocess.run([sys.executable, "-S", str(ROOT / "crypto_toolkit.py"), "rsa-key", "--key-file", str(path), "--text", "00", "--padding", "oaep"], capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertIn("pip install cryptography", result.stderr)
            self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
