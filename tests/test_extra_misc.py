from contextlib import redirect_stderr, redirect_stdout
import hashlib
import importlib.util
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import crypto_extra as extra
import crypto_toolkit as crypto
import ctf_misc as misc


ROOT = Path(crypto.__file__).resolve().parent
spec = importlib.util.spec_from_file_location("create_misc_demo", ROOT / "examples" / "create_misc_demo.py")
demo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(demo)
HAS_IMAGES = importlib.util.find_spec("PIL") is not None
TEXT = ("The morning sun shone through the windows of the library as the students gathered around the table. "
        "They were learning how to read the evidence carefully and compare each result with their original question. "
        "A clear explanation should describe what happened and why the available information supports that conclusion. "
        "When a problem appears difficult, work through a small example and write down the steps that led to the answer. "
        "There are many different ways to represent a message, but the meaning must remain the same when it is decoded. ") * 8


class ExtraTests(unittest.TestCase):
    def test_known_vigenere_vector_and_nonletters(self):
        self.assertEqual(extra.vigenere("ATTACKATDAWN", "LEMON", True), "LXFOPVEFRNHR")
        self.assertEqual(extra.vigenere("Lxfopv ef rnhr!", "LEMON"), "Attack at dawn!")
        self.assertEqual(extra.vigenere("A-世A", "BC", True), "B-世C")
        for key in ("", "123", "A B", "é"):
            with self.assertRaises(ValueError):
                extra.vigenere("test", key)

    def test_vigenere_key_recovery(self):
        ciphertext = extra.vigenere(TEXT, "LEMON", True)
        candidate = extra.crack_vigenere(ciphertext, fixed=5)[0]
        self.assertEqual(candidate[1:], ("LEMON", TEXT))

    def test_hamming_vector_and_repeating_xor(self):
        self.assertEqual(extra.hamming(b"this is a test", b"wokka wokka!!!"), 37)
        with self.assertRaises(ValueError):
            extra.hamming(b"a", b"bb")
        data = TEXT.encode()
        ciphertext = bytes(byte ^ b"ICE"[i % 3] for i, byte in enumerate(data))
        self.assertEqual(extra.crack_repeating_xor(ciphertext, fixed=3)[0][1:3], (b"ICE", data))
        self.assertIn(b"ICE", [entry[1] for entry in extra.crack_repeating_xor(ciphertext)])

    def test_analysis_bounds_and_repeating_key_reduction(self):
        self.assertEqual(extra.minimal_key(b"ICEICE"), b"ICE")
        for args in ((b"a",), (b"a" * 20, 0, 4), (b"a" * 20, 1, 129), (b"a" * 20, 1, 4, 100)):
            with self.assertRaises(ValueError):
                extra.crack_repeating_xor(*args)
        with self.assertRaises(ValueError):
            extra.crack_vigenere("0123")

    def test_hash_wordlist_bytes_bounds_and_no_match(self):
        with tempfile.TemporaryDirectory() as folder:
            words = Path(folder) / "words.txt"
            words.write_bytes(b"wrong\r\n abc \r\n\xff\n\n")
            target = hashlib.sha256(b" abc ").hexdigest()
            self.assertEqual(extra.check_hash(target, words), (b" abc ", 2, False))
            self.assertEqual(extra.check_hash(target, words, max_words=1), (None, 1, True))
            self.assertEqual(extra.check_hash(hashlib.sha256(b"missing").hexdigest(), words), (None, 4, False))
            self.assertEqual(extra.check_hash(hashlib.md5(b"\xff").hexdigest(), words, "md5")[0], b"\xff")
            self.assertEqual(extra.check_hash(hashlib.sha256(b"").hexdigest(), words)[0], b"")
            with self.assertRaises(ValueError):
                extra.check_hash("zz", words)


class MiscTests(unittest.TestCase):
    def invoke(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = crypto.main(list(args))
        return code, out.getvalue(), err.getvalue()

    def test_signatures_and_entropy(self):
        self.assertEqual(misc.entropy(b""), 0)
        self.assertEqual(misc.entropy(b"aaaa"), 0)
        self.assertEqual(misc.entropy(bytes(range(256))), 8)
        self.assertIn((4, "PNG"), misc.signatures(b"junk\x89PNG\r\n\x1a\ntrailer"))
        self.assertEqual(len(misc.signatures(b"MZ" * 100, limit=3)), 3)

    def test_ascii_and_utf16_offsets(self):
        # A nonzero delimiter prevents the ASCII tail 'o\0' from joining the UTF-16 run.
        data = b"\x00hello\x00\x01" + "world".encode("utf-16-le") + b"\x01" + "secret".encode("utf-16-be")
        self.assertIn((1, "ascii", "hello"), misc.extract_strings(data))
        self.assertIn((8, "utf16le", "world"), misc.extract_strings(data, encoding="utf16le"))
        self.assertIn((19, "utf16be", "secret"), misc.extract_strings(data, encoding="utf16be"))
        self.assertEqual(len(misc.extract_strings(data, encoding="all", limit=1)), 1)
        with self.assertRaises(ValueError):
            misc.extract_strings(data, minimum=0)

    def test_ranges_output_preservation_and_file_limit(self):
        with tempfile.TemporaryDirectory() as folder:
            source, target = Path(folder) / "input.bin", Path(folder) / "out.bin"
            source.write_bytes(bytes(range(32)))
            self.assertEqual(misc.read_range(source, 4, 3), bytes([4, 5, 6]))
            for offset, length in ((-1, 1), (0, 0), (32, 1)):
                with self.assertRaises(ValueError):
                    misc.read_range(source, offset, length)
            self.assertEqual(self.invoke("carve", "--file", str(source), "--offset", "0x4", "--length", "3", "--out", str(target))[0], 0)
            self.assertEqual(target.read_bytes(), bytes([4, 5, 6]))
            self.assertEqual(self.invoke("carve", "--file", str(source), "--length", "2", "--out", str(target))[0], 1)
            self.assertEqual(target.read_bytes(), bytes([4, 5, 6]))
            with patch.object(misc, "MAX_FILE_BYTES", 16), self.assertRaises(ValueError):
                misc.bounded_file(source)
            self.assertIn("00000010", self.invoke("hexdump", "--file", str(source))[1])

    def test_zip_members_comments_limits_and_explicit_output(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "input.zip"
            with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("../../escape.txt", b"flag{zip}")
                archive.writestr("large.txt", b"A" * 10000)
                archive.comment = b"hint"
            comment, count, entries = misc.zip_summary(path)
            self.assertEqual((comment, count), (b"hint", 2))
            self.assertEqual(entries[0][0], "../../escape.txt")
            self.assertEqual(misc.zip_read(path, "../../escape.txt"), b"flag{zip}")
            self.assertFalse((Path(folder) / "escape.txt").exists())
            for member, size in (("missing", 100), ("large.txt", 10)):
                with self.assertRaises(ValueError):
                    misc.zip_read(path, member, size)
            output = Path(folder) / "chosen.bin"
            code, _, err = self.invoke("zip-read", "--file", str(path), "--member", "../../escape.txt", "--out", str(output))
            self.assertEqual(code, 0, err)
            self.assertEqual(output.read_bytes(), b"flag{zip}")
            self.assertEqual(self.invoke("zip-read", "--file", str(path), "--member", "large.txt", "--out", str(output))[0], 1)
            self.assertEqual(output.read_bytes(), b"flag{zip}")
            malformed = Path(folder) / "broken.zip"
            malformed.write_bytes(b"not a zip")
            with self.assertRaises(ValueError):
                misc.zip_summary(malformed)

    def test_practice_generator_and_file_workflow(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder) / "practice"
            instructions = demo.create_demo(directory)
            self.assertIn("LSB byte count: 16", instructions)
            output = self.invoke("file-info", "--file", str(directory / "mystery.bin"), "--scan")
            self.assertEqual(output[0], 0, output[2])
            self.assertIn("PNG signature candidate", output[1])
            self.assertIn("flag{strings_demo}", self.invoke("strings", "--file", str(directory / "mystery.bin"))[1])
            self.assertIn("flag{zip_comment}", self.invoke("zip-info", "--file", str(directory / "notes.zip"))[1])
            with self.assertRaises(FileExistsError):
                demo.create_demo(directory)

    def test_base_cli_and_missing_image_dependency(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder) / "practice"
            demo.create_demo(directory)
            for args in (("docs", "misc"), ("vigenere", "--text", "LXFOPVEFRNHR", "--key", "LEMON"),
                         ("strings", "--file", str(directory / "mystery.bin"))):
                result = subprocess.run([sys.executable, "-S", str(ROOT / "crypto_toolkit.py"), *args],
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([sys.executable, "-S", str(ROOT / "crypto_toolkit.py"), "image-info",
                                     "--file", str(directory / "picture.png")], capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertIn("pip install Pillow", result.stderr)
            self.assertNotIn("Traceback", result.stderr)


@unittest.skipUnless(HAS_IMAGES, "Optional Pillow dependency not installed")
class ImageTests(unittest.TestCase):
    def test_metadata_and_known_lsb_message(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder) / "practice"
            demo.create_demo(directory)
            picture = directory / "picture.png"
            metadata = misc.image_metadata(picture)
            self.assertEqual(metadata["size"], (32, 8))
            self.assertEqual(metadata["info.Comment"], "flag{metadata_demo}")
            self.assertEqual(misc.extract_lsb(picture, 16), b"flag{pixel_bits}")
            self.assertEqual(misc.extract_lsb(picture, 4, offset=8), b"lag{")
            for kwargs in ({"count": 1000}, {"count": 1, "channels": "a"}, {"count": 1, "plane": 8},
                           {"count": 1, "channels": "rr"}, {"count": 1, "offset": -1}):
                with self.assertRaises(ValueError):
                    misc.extract_lsb(picture, **kwargs)

    def test_channel_order_plane_and_little_bit_order(self):
        from PIL import Image
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "custom.png"
            # Encode 0x96 LSB-first into bit 2 of blue channel only.
            values = [(0, 0, ((0x96 >> index) & 1) << 2, 255) for index in range(8)]
            image = Image.new("RGBA", (8, 1))
            image.putdata(values)
            image.save(path)
            self.assertEqual(misc.extract_lsb(path, 1, channels="b", plane=2, order="lsb"), b"\x96")
            self.assertEqual(misc.extract_lsb(path, 1, channels="a"), b"\xff")
            gray = Path(folder) / "gray.png"
            Image.new("L", (8, 8)).save(gray)
            with self.assertRaises(ValueError):
                misc.extract_lsb(gray, 1)


if __name__ == "__main__":
    unittest.main()
