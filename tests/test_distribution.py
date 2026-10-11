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
