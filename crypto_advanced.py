"""Explicit Fibonacci LFSR conventions and optional AES decryption."""

import json
from pathlib import Path
import re


def parse_state(value):
    value = value.strip()
    if value.startswith("["):
        try:
            state = json.loads(value)
        except json.JSONDecodeError as error:
            raise ValueError("State must be a JSON list of 0/1 integers or a bit string.") from error
    else:
        compact = "".join(value.split())
        if not re.fullmatch("[01]+", compact):
            raise ValueError("State must contain only 0 and 1, or be a JSON list of bits.")
        state = [int(bit) for bit in compact]
    validate_state(state)
    return state


def validate_state(state):
    if not isinstance(state, list) or not state or any(type(bit) is not int or bit not in (0, 1) for bit in state):
        raise ValueError("The state must be a nonempty list of integer bits (0 or 1).")


def parse_taps(value):
    try:
        if value.strip().startswith("["):
            taps = json.loads(value)
        else:
            taps = [int(part.strip()) for part in value.split(",")]
    except (ValueError, json.JSONDecodeError) as error:
        raise ValueError("Taps must be comma-separated integers or a JSON list.") from error
    if not isinstance(taps, list) or not taps or any(type(tap) is not int for tap in taps):
        raise ValueError("Taps must be a nonempty list of integers.")
    if len(set(taps)) != len(taps):
        raise ValueError("Duplicate taps are not supported; each XOR input must appear once.")
    return taps


def lfsr_bits(state, taps, count, *, shift="left", output_bit="first", tap_base=0,
              tap_origin="left", skip=0):
    """Output from the pre-shift state; XOR selected taps and insert feedback."""
    validate_state(state)
    if type(count) is not int or count <= 0 or type(skip) is not int or skip < 0:
        raise ValueError("Bit count must be positive and skip must be nonnegative.")
    if shift not in ("left", "right") or output_bit not in ("first", "last", "feedback"):
        raise ValueError("Invalid shift direction or output bit selection.")
    if tap_base not in (0, 1) or tap_origin not in ("left", "right"):
        raise ValueError("Invalid tap base or origin.")
    if not isinstance(taps, list) or not taps or any(type(tap) is not int for tap in taps):
        raise ValueError("Taps must be a nonempty list of integers.")
    if len(set(taps)) != len(taps):
        raise ValueError("Duplicate taps are not supported.")
    indices = [tap - tap_base for tap in taps]
    if any(not 0 <= index < len(state) for index in indices):
        raise ValueError("Tap index is outside the state for the selected --tap-base.")
    if tap_origin == "right":
        indices = [len(state) - 1 - index for index in indices]
    register = state.copy()
    bits = []
    for step in range(skip + count):
        feedback = 0
        for index in indices:
            feedback ^= register[index]
        bit = {"first": register[0], "last": register[-1], "feedback": feedback}[output_bit]
        if step >= skip:
            bits.append(bit)
        register = register[1:] + [feedback] if shift == "left" else [feedback] + register[:-1]
    return bits


def pack_bits(bits, byte_order="msb"):
    if len(bits) % 8 or any(type(bit) is not int or bit not in (0, 1) for bit in bits):
        raise ValueError("Packing requires a multiple of eight valid bits; use --format bits for other lengths.")
    if byte_order not in ("msb", "lsb"):
        raise ValueError("Byte bit order must be msb or lsb.")
    order = 1 if byte_order == "msb" else -1
    return bytes(int("".join(map(str, bits[i:i + 8][::order])), 2) for i in range(0, len(bits), 8))


def read_lfsr_output(path):
    """Read the documented three-field format; never evaluate input as code."""
    text = Path(path).read_text(encoding="utf-8-sig")
    match = re.fullmatch(
        r"\s*LFSR Initial State:\s*(\[[^\]]*\])\s*"
        r"LFSR Taps:\s*(\[[^\]]*\])\s*"
        r"Encrypted Flag:\s*([0-9a-fA-F\s]+)\s*", text)
    if not match:
        raise ValueError("Expected exactly LFSR Initial State, LFSR Taps, and Encrypted Flag (hex); see docs lfsr-aes.")
    ciphertext = bytes.fromhex(match[3])
    if not ciphertext:
        raise ValueError("Encrypted Flag must contain ciphertext bytes.")
    return parse_state(match[1]), parse_taps(match[2]), ciphertext


def load_aes_backend():
    try:
        from cryptography.hazmat.primitives import padding
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as error:
        raise ValueError("AES requires the optional cryptography package. Install with: "
                         "python -m pip install cryptography (or install this source folder with \".[aes]\").") from error
    return Cipher, algorithms, modes, padding


def aes_decrypt(ciphertext, key, *, mode, iv=None, iv_prefix=False, padding="pkcs7"):
    if len(key) not in (16, 24, 32):
        raise ValueError("AES keys must be exactly 16, 24, or 32 bytes.")
    if mode not in ("ecb", "cbc"):
        raise ValueError("Supported AES modes are ecb and cbc.")
    if padding not in ("pkcs7", "none"):
        raise ValueError("Supported padding choices are pkcs7 and none.")
    if mode == "ecb" and (iv is not None or iv_prefix):
        raise ValueError("ECB does not use an IV; remove --iv/--iv-prefix.")
    if iv is not None and iv_prefix:
        raise ValueError("Use either an explicit IV or a prefixed IV, not both.")
    if iv_prefix:
        if len(ciphertext) < 32:
            raise ValueError("A prefixed-IV input needs 16 IV bytes plus at least one ciphertext block.")
        iv, ciphertext = ciphertext[:16], ciphertext[16:]
    if mode == "cbc" and (iv is None or len(iv) != 16):
        raise ValueError("CBC requires a 16-byte --iv (hex), or --iv-prefix.")
    if not ciphertext or len(ciphertext) % 16:
        raise ValueError("AES-ECB/CBC ciphertext must be nonempty and a multiple of 16 bytes after removing any IV.")
    Cipher, algorithms, modes, pad_module = load_aes_backend()
    cipher_mode = modes.ECB() if mode == "ecb" else modes.CBC(iv)
    decryptor = Cipher(algorithms.AES(key), cipher_mode).decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    if padding == "pkcs7":
        unpadder = pad_module.PKCS7(128).unpadder()
        try:
            plaintext = unpadder.update(plaintext) + unpadder.finalize()
        except ValueError as error:
            raise ValueError("Invalid PKCS#7 padding. Check the key, LFSR conventions, mode, IV, and padding choice. "
                             "Use --padding none only when the challenge uses no padding.") from error
    return plaintext
