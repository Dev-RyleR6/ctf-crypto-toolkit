#!/usr/bin/env python3
"""Offline CTF helpers. Python 3.9+, standard library only."""

import argparse
import base64
from collections import Counter
import hashlib
import math
from pathlib import Path
import re
import sys
from urllib.parse import quote_from_bytes, unquote_to_bytes


__version__ = "0.1.0"

FORMATS = ("hex", "base64", "base32", "binary", "url")
LETTER_FREQUENCIES = dict(zip(
    "abcdefghijklmnopqrstuvwxyz",
    (8.17, 1.49, 2.78, 4.25, 12.70, 2.23, 2.02, 6.09, 6.97,
     0.15, 0.77, 4.03, 2.41, 6.75, 7.51, 1.93, 0.10, 5.99,
     6.33, 9.06, 2.76, 0.98, 2.36, 0.15, 1.97, 0.07),
))


def encode(data, fmt):
    if fmt == "hex":
        return data.hex()
    if fmt == "base64":
        return base64.b64encode(data).decode("ascii")
    if fmt == "base32":
        return base64.b32encode(data).decode("ascii")
    if fmt == "binary":
        return " ".join(format(byte, "08b") for byte in data)
    if fmt == "url":
        return quote_from_bytes(data, safe="")
    raise ValueError("Unsupported encoding: " + fmt)


def decode(text, fmt):
    if fmt == "text":
        return text.encode("utf-8")
    if fmt == "hex":
        return bytes.fromhex(text)
    if fmt == "base64":
        return base64.b64decode("".join(text.split()), validate=True)
    if fmt == "base32":
        return base64.b32decode("".join(text.split()), casefold=True)
    if fmt == "binary":
        bits = "".join(text.split())
        if re.search("[^01]", bits) or len(bits) % 8:
            raise ValueError("Binary input must contain complete 8-bit bytes of 0s and 1s.")
        return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))
    if fmt == "url":
        if re.search(r"%(?![0-9a-fA-F]{2})", text):
            raise ValueError("Invalid URL percent escape; expected % followed by two hex digits.")
        return unquote_to_bytes(text)
    raise ValueError("Unsupported encoding: " + fmt)


def caesar(text, shift):
    result = []
    for char in text:
        if "A" <= char <= "Z":
            result.append(chr((ord(char) - 65 + shift) % 26 + 65))
        elif "a" <= char <= "z":
            result.append(chr((ord(char) - 97 + shift) % 26 + 97))
        else:
            result.append(char)
    return "".join(result)


def xor_bytes(data, key):
    if not key:
        raise ValueError("The XOR key must not be empty.")
    return bytes(byte ^ key[i % len(key)] for i, byte in enumerate(data))


def english_score(data):
    """Heuristic for English ASCII, not a probability or proof of decryption."""
    if not data:
        return float("-inf")
    score = 0.0
    for byte in data:
        char = chr(byte).lower()
        if char in LETTER_FREQUENCIES:
            score += math.log(LETTER_FREQUENCIES[char] / 100)
        elif byte == 32:
            score += math.log(0.18)
        elif byte in (9, 10, 13) or 33 <= byte <= 126:
            score += math.log(0.005)
        else:
            score -= 18
    return score / len(data)


def crack_single_byte_xor(data, top=10):
    if not data:
        raise ValueError("Provide at least one byte to analyze.")
    results = []
    for key in range(256):
        candidate = xor_bytes(data, bytes([key]))
        results.append((english_score(candidate), key, candidate))
    return sorted(results, reverse=True)[:top]


def rsa_decrypt(n, d, c):
    if n <= 1 or d <= 0 or not 0 <= c < n:
        raise ValueError("RSA requires n > 1, d > 0, and 0 <= c < n.")
    message = pow(c, d, n)
    return message, message.to_bytes(max(1, (message.bit_length() + 7) // 8), "big")


def read_input(args):
    return Path(args.file).read_bytes() if args.file is not None else args.text.encode("utf-8")


def text_input(args):
    return read_input(args).decode("utf-8")


def safe_text(text):
    # Avoid printing terminal control sequences from untrusted challenge files.
    return "".join(c if c.isprintable() or c in "\n\r\t" else ascii(c)[1:-1] for c in text)


def show_bytes(data, output=None):
    if output:
        # Exclusive creation avoids overwriting a challenge file accidentally.
        with Path(output).open("xb") as handle:
            handle.write(data)
        print("Saved {} bytes to {}".format(len(data), output))
        return
    print("Hex: " + data.hex())
    try:
        print("UTF-8: " + safe_text(data.decode("utf-8")))
    except UnicodeDecodeError:
        print("Bytes: " + repr(data))


def add_source(parser):
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--text", help="Input text; quote it in your shell")
    group.add_argument("--file", help="Read input from a file (raw bytes unless otherwise specified)")


def add_output(parser):
    parser.add_argument("--out", help="Write result bytes to a NEW file instead of displaying them")


def integer(value):
    try:
        return int(value, 16) if value.lower().startswith("0x") else int(value, 10)
    except ValueError:
        raise argparse.ArgumentTypeError("Use a decimal integer or a hexadecimal integer starting with 0x.")


def build_parser():
    parser = argparse.ArgumentParser(
        description="Offline CTF cryptography toolkit; no AI, network calls, or dependencies.",
        epilog="Start: python -m crypto_toolkit decode --from base64 --text SGVsbG8=\n"
               "Each command has --help. See CRYPTO_GUIDE.md for practice and examples.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version="CTF Crypto Toolkit " + __version__)
    commands = parser.add_subparsers(dest="command")

    p = commands.add_parser("encode", help="Encode raw bytes as hex, Base64, Base32, binary, or URL text")
    add_source(p)
    p.add_argument("--to", choices=FORMATS, required=True, dest="format")
    add_output(p)

    p = commands.add_parser("decode", help="Decode encoded UTF-8 text into bytes")
    add_source(p)
    p.add_argument("--from", choices=FORMATS, required=True, dest="format")
    add_output(p)

    p = commands.add_parser("caesar", help="Shift ASCII letters, or display all 26 shifts")
    add_source(p)
    p.add_argument("--shift", type=int, help="Forward shift; use a negative number to reverse it")

    p = commands.add_parser("xor", help="Apply a known single-byte or repeating XOR key")
    add_source(p)
    p.add_argument("--input-format", choices=("raw",) + FORMATS, default="raw")
    p.add_argument("--key", required=True, help="Key text, or encoded key with --key-format")
    p.add_argument("--key-format", choices=("text",) + FORMATS, default="text")
    add_output(p)

    p = commands.add_parser("xor-crack", help="Rank all 256 single-byte XOR keys by English likeness")
    add_source(p)
    p.add_argument("--input-format", choices=("raw",) + FORMATS, default="raw")
    p.add_argument("--top", type=int, default=10, help="Number of candidates, 1–256 (default: 10)")

    p = commands.add_parser("frequency", help="Count ASCII letters for substitution-cipher clues")
    add_source(p)

    p = commands.add_parser("hash", help="Calculate a digest; does not decrypt or crack hashes")
    add_source(p)
    p.add_argument("--algorithm", choices=("md5", "sha1", "sha256", "sha512"), default="sha256")

    p = commands.add_parser("inverse", help="Calculate a modular inverse (useful for toy RSA)")
    p.add_argument("a", type=integer)
    p.add_argument("modulus", type=integer)

    p = commands.add_parser("rsa", help="Textbook RSA decryption when n and private exponent d are known")
    p.add_argument("--n", type=integer, required=True)
    p.add_argument("--d", type=integer, required=True)
    p.add_argument("--c", type=integer, required=True)
    add_output(p)
    return parser


def run(args):
    if args.command == "encode":
        result = encode(read_input(args), args.format)
        if args.out:
            show_bytes(result.encode("ascii"), args.out)
        else:
            print(result)
    elif args.command == "decode":
        show_bytes(decode(text_input(args), args.format), args.out)
    elif args.command == "caesar":
        source = text_input(args)
        if args.shift is not None:
            print(safe_text(caesar(source, args.shift)))
        else:
            for shift in range(26):
                print("{:2d}: {}".format(shift, safe_text(caesar(source, shift))))
    elif args.command in ("xor", "xor-crack"):
        source = read_input(args)
        data = source if args.input_format == "raw" else decode(source.decode("utf-8"), args.input_format)
        if args.command == "xor":
            show_bytes(xor_bytes(data, decode(args.key, args.key_format)), args.out)
        else:
            if not 1 <= args.top <= 256:
                raise ValueError("--top must be between 1 and 256.")
            print("English-ranked candidates; scores are heuristics, not confidence percentages.")
            for score, key, candidate in crack_single_byte_xor(data, args.top):
                print("key=0x{:02x} score={:.3f} {}".format(key, score, repr(candidate)))
    elif args.command == "frequency":
        counts = Counter(c.lower() for c in text_input(args) if c.isascii() and c.isalpha())
        total = sum(counts.values())
        print("ASCII letters: {}".format(total))
        for char, count in sorted(counts.items(), key=lambda pair: (-pair[1], pair[0])):
            print("{} {:6d} {:6.2f}%".format(char, count, count / total * 100))
    elif args.command == "hash":
        print(hashlib.new(args.algorithm, read_input(args)).hexdigest())
    elif args.command == "inverse":
        if args.modulus <= 1:
            raise ValueError("The modulus must be greater than 1.")
        if math.gcd(args.a, args.modulus) != 1:
            raise ValueError("No inverse exists: a and modulus are not coprime.")
        print(pow(args.a, -1, args.modulus))
    elif args.command == "rsa":
        message, data = rsa_decrypt(args.n, args.d, args.c)
        print("Message integer: {}".format(message))
        show_bytes(data, args.out)


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    try:
        run(args)
    except (ValueError, OSError) as error:
        print("Error: {}".format(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
