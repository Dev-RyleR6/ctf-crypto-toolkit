import hashlib
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("build_release", ROOT / "scripts" / "build_release.py")
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class DistributionTests(unittest.TestCase):
    def test_downloads_outside_source_directory(self):
        with tempfile.TemporaryDirectory() as folder:
            destination = Path(folder)
            artifacts = release.build(destination)
            source_zip, portable, checksums = artifacts
            with zipfile.ZipFile(source_zip) as archive:
                prefix = "ctf-crypto-toolkit-" + release.version() + "/"
                self.assertEqual(set(archive.namelist()), {prefix + name for name in release.SOURCE_FILES})
                archive.extractall(destination / "extracted")
            with zipfile.ZipFile(portable) as archive:
                self.assertEqual(set(archive.namelist()), set(release.PORTABLE_FILES) | {"__main__.py"})
            practice = destination / "practice"
            result = subprocess.run([sys.executable, str(destination / "extracted" / prefix / "examples" / "create_misc_demo.py"),
                                     "--out-dir", str(practice)], cwd=folder, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            for executable in (portable, destination / "extracted" / prefix / "crypto_toolkit.py"):
                result = subprocess.run([sys.executable, str(executable), "decode", "--from", "hex",
                                         "--text", "666c61677b6865787d"], cwd=folder,
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("UTF-8: flag{hex}", result.stdout)
                result = subprocess.run([sys.executable, str(executable), "--version"], cwd=folder,
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(release.version(), result.stdout)
                result = subprocess.run([sys.executable, "-S", str(executable), "docs", "all"], cwd=folder,
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("LFSR + AES challenge workflow", result.stdout)
                self.assertIn("Miscellaneous file-analysis workflow", result.stdout)
                html_path = destination / (executable.name + "-guide.html")
                result = subprocess.run([sys.executable, "-S", str(executable), "docs", "rsa", "--out", str(html_path)],
                                        cwd=folder, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('data-start="rsa"', html_path.read_text(encoding="utf-8"))
                self.assertIn('class="copy"', html_path.read_text(encoding="utf-8"))
                result = subprocess.run([sys.executable, "-S", str(executable), "strings", "--file", str(practice / "mystery.bin")],
                                        cwd=folder, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("flag{strings_demo}", result.stdout)
                if importlib.util.find_spec("PIL") is not None:
                    result = subprocess.run([sys.executable, str(executable), "lsb", "--file", str(practice / "picture.png"),
                                             "--bytes", "16"], cwd=folder, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("flag{pixel_bits}", result.stdout)
                if importlib.util.find_spec("cryptography") is not None:
                    from cryptography.hazmat.primitives import hashes, serialization
                    from cryptography.hazmat.primitives.asymmetric import padding, rsa
                    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                    key_path = destination / "synthetic.hex"
                    key_path.write_text(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                         serialization.NoEncryption()).hex())
                    encrypted = key.public_key().encrypt(b"flag{rsa_package}", padding.OAEP(
                        mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
                    result = subprocess.run([sys.executable, str(executable), "rsa-key", "--key-file", str(key_path),
                                             "--key-encoding", "hex", "--text", encrypted.hex(), "--input-format", "hex",
                                             "--padding", "oaep"], cwd=folder, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("flag{rsa_package}", result.stdout)
                    fixture = destination / "extracted" / prefix / "examples" / "lfsr_aes_demo.txt"
                    result = subprocess.run([sys.executable, str(executable), "lfsr-aes", "--file", str(fixture),
                                             "--mode", "ecb"], cwd=folder, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("flag{lfsr_aes_demo}", result.stdout)
            result = subprocess.run([sys.executable, str(portable), "decode", "--from", "hex",
                                     "--text", "not-hex"], cwd=folder, capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertIn("Error:", result.stderr)
            for line in checksums.read_text().splitlines():
                digest, name = line.split("  ", 1)
                self.assertEqual(digest, hashlib.sha256((destination / name).read_bytes()).hexdigest())

    def test_release_archives_are_repeatable(self):
        with tempfile.TemporaryDirectory() as folder:
            artifacts = release.build(Path(folder))
            before = {path.name: path.read_bytes() for path in artifacts}
            release.build(Path(folder))
            self.assertEqual(before, {path.name: path.read_bytes() for path in artifacts})


if __name__ == "__main__":
    unittest.main()
