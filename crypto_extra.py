"""Bounded classical-cipher analysis and local dictionary hash checks."""

from collections import Counter
import hashlib
import math
from pathlib import Path


COMMANDS = {"vigenere", "vigenere-crack", "xor-repeat-crack", "hash-check"}
FREQUENCIES = (8.17, 1.49, 2.78, 4.25, 12.70, 2.23, 2.02, 6.09, 6.97,
               0.15, 0.77, 4.03, 2.41, 6.75, 7.51, 1.93, 0.10, 5.99,
               6.33, 9.06, 2.76, 0.98, 2.36, 0.15, 1.97, 0.07)
BYTE_SCORES = tuple(math.log(FREQUENCIES[ord(chr(b).lower()) - 97] / 100)
                    if 97 <= ord(chr(b).lower()) <= 122 else
                    math.log(0.18) if b == 32 else
                    math.log(0.005) if b in (9, 10, 13) or 33 <= b <= 126 else -18
                    for b in range(256))


def english_score(data):
    return sum(BYTE_SCORES[b] for b in data) / max(1, len(data))


def vigenere(text, key, encrypt=False):
    if not key or any(not ("A" <= c <= "Z" or "a" <= c <= "z") for c in key):
        raise ValueError("Vigenere key must contain only ASCII letters A-Z.")
    shifts = [ord(c.lower()) - 97 for c in key]
    index, result = 0, []
    for char in text:
        if "A" <= char <= "Z" or "a" <= char <= "z":
            base = 65 if char.isupper() else 97
            shift = shifts[index % len(shifts)] * (1 if encrypt else -1)
            result.append(chr((ord(char) - base + shift) % 26 + base))
            index += 1
        else:
            result.append(char)
    return "".join(result)


def minimal_key(key):
    for size in range(1, len(key) + 1):
        if len(key) % size == 0 and key == key[:size] * (len(key) // size):
            return key[:size]
    return key


def key_sizes(length, minimum, maximum, fixed):
    if not 1 <= minimum <= maximum <= 128:
        raise ValueError("Key-size range must satisfy 1 <= min-key <= max-key <= 128.")
    if fixed is not None:
        if not 1 <= fixed <= 128 or length < fixed * 4:
            raise ValueError("A fixed key size must be 1-128 with at least four input bytes/letters per position.")
        return [fixed]
    sizes = list(range(minimum, min(maximum, length // 4) + 1))
    if not sizes:
        raise ValueError("Input is too short for the requested key-size range.")
    return sizes


def hamming(a, b):
    if len(a) != len(b):
        raise ValueError("Hamming distance requires equal-length byte strings.")
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def crack_repeating_xor(data, minimum=2, maximum=40, fixed=None, top=5):
    if not 1 <= top <= 20:
        raise ValueError("--top must be between 1 and 20.")
    sizes = key_sizes(len(data), minimum, maximum, fixed)
    distances = {}
    for size in sizes:
        blocks = [data[i:i + size] for i in range(0, min(len(data) // size, 8) * size, size)]
        distances[size] = sum(hamming(a, b) / size for a, b in zip(blocks, blocks[1:])) / (len(blocks) - 1)
    # Try only the eight most promising sizes when size is unknown.
    sizes = sorted(sizes, key=lambda size: distances[size])[:8]
    candidates = {}
    for size in sizes:
        key = bytearray()
        for index in range(size):
            counts = Counter(data[index::size])
            key.append(max(range(256), key=lambda candidate: sum(
                count * BYTE_SCORES[byte ^ candidate] for byte, count in counts.items())))
        key = minimal_key(bytes(key))
        plain = bytes(byte ^ key[i % len(key)] for i, byte in enumerate(data))
        score = english_score(plain) - 0.02 * len(key)
        candidates[key] = (score, key, plain, distances[size])
    return sorted(candidates.values(), reverse=True)[:top]


def crack_vigenere(text, minimum=1, maximum=20, fixed=None, top=5):
    if not 1 <= top <= 20:
        raise ValueError("--top must be between 1 and 20.")
    letters = [ord(c.lower()) - 97 for c in text if c.isascii() and c.isalpha()]
    sizes = key_sizes(len(letters), minimum, maximum, fixed)
    candidates = {}
    for size in sizes:
        key = []
        for index in range(size):
            column = letters[index::size]
            counts = Counter(column)
            def chi_square(shift):
                return sum((counts[(letter + shift) % 26] - len(column) * FREQUENCIES[letter] / 100) ** 2 /
                           (len(column) * FREQUENCIES[letter] / 100) for letter in range(26))
            key.append(chr(65 + min(range(26), key=chi_square)))
        key = minimal_key("".join(key))
        plain = vigenere(text, key)
        score = english_score(plain.encode("utf-8")) - 0.02 * len(key)
        candidates[key] = (score, key, plain)
    return sorted(candidates.values(), reverse=True)[:top]


def check_hash(digest, wordlist, algorithm="sha256", max_words=100000):
    expected_length = hashlib.new(algorithm).digest_size * 2
    if len(digest) != expected_length or any(c not in "0123456789abcdefABCDEF" for c in digest):
        raise ValueError("Digest must contain exactly {} hex digits for {}.".format(expected_length, algorithm))
    if not 1 <= max_words <= 10000000:
        raise ValueError("--max-words must be between 1 and 10000000.")
    checked = 0
    with Path(wordlist).open("rb") as handle:
        while checked < max_words:
            line = handle.readline(1024 * 1024 + 1)
            if not line:
                return None, checked, False
            if len(line) > 1024 * 1024:
                raise ValueError("A wordlist line exceeds the 1 MiB limit.")
            # Remove one line ending, preserving spaces and all password bytes.
            candidate = line[:-1] if line.endswith(b"\n") else line
            if line.endswith(b"\r\n"):
                candidate = candidate[:-1]
            checked += 1
            if hashlib.new(algorithm, candidate).hexdigest() == digest.lower():
                return candidate, checked, False
        return None, checked, bool(handle.read(1))


def add_commands(commands, add_source, add_output):
    p = commands.add_parser("vigenere", help="Encrypt/decrypt a Vigenere cipher with a known alphabetic key")
    add_source(p)
    p.add_argument("--key", required=True)
    p.add_argument("--encrypt", action="store_true", help="Encrypt instead of decrypt")
    add_output(p)
    for name, help_text in (("vigenere-crack", "Guess Vigenere keys using English letter frequencies"),
                            ("xor-repeat-crack", "Guess repeating XOR keys using Hamming distance and English scores")):
        p = commands.add_parser(name, help=help_text)
        add_source(p)
        p.add_argument("--min-key", type=int, default=1 if name == "vigenere-crack" else 2)
        p.add_argument("--max-key", type=int, default=20 if name == "vigenere-crack" else 40)
        p.add_argument("--key-size", type=int, help="Known key length; overrides the search range")
        p.add_argument("--top", type=int, default=5)
        if name == "xor-repeat-crack":
            p.add_argument("--input-format", choices=("raw", "hex", "base64"), default="raw")
    p = commands.add_parser("hash-check", help="Check a bounded local wordlist against an unsalted hash")
    p.add_argument("--digest", required=True)
    p.add_argument("--wordlist", required=True)
    p.add_argument("--algorithm", choices=("md5", "sha1", "sha256", "sha512"), default="sha256")
    p.add_argument("--max-words", type=int, default=100000)


def run(args, read_input, decode, show_bytes, safe_text):
    if args.command == "hash-check":
        match, checked, limited = check_hash(args.digest, args.wordlist, args.algorithm, args.max_words)
        print("Candidates checked:", checked)
        print("Match: " + repr(match) if match is not None else "No match" + (" (limit reached; more candidates remain)." if limited else "."))
        return
    raw = read_input(args)
    if args.command == "vigenere":
        result = vigenere(raw.decode("utf-8"), args.key, args.encrypt)
        if args.out:
            show_bytes(result.encode("utf-8"), args.out)
        else:
            print(safe_text(result))
        return
    print("Heuristic English candidates, not proven solutions. Analysis uses a bounded sample.")
    if args.command == "vigenere-crack":
        text = raw.decode("utf-8")[:8192]
        print("Characters analyzed:", len(text))
        for score, key, plain in crack_vigenere(text, args.min_key, args.max_key, args.key_size, args.top):
            print("key={} score={:.3f} preview={}".format(key, score, repr(plain[:240])))
    else:
        data = raw if args.input_format == "raw" else decode(raw.decode("utf-8"), args.input_format)
        sample = data[:4096]
        print("Bytes analyzed:", len(sample))
        for score, key, plain, distance in crack_repeating_xor(sample, args.min_key, args.max_key, args.key_size, args.top):
            print("key_hex={} key={} score={:.3f} distance={:.3f} preview={}".format(
                key.hex(), repr(key), score, distance, repr(plain[:240])))
