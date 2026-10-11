"""Local RSA private-key loading and single-block CTF decryption."""

import base64
import getpass
from pathlib import Path


HASHES = ("sha1", "sha256", "sha384", "sha512")


def backend():
    try:
        from cryptography.exceptions import UnsupportedAlgorithm
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
    except ImportError:
        raise ValueError("RSA key files require cryptography: python -m pip install cryptography") from None
    return serialization, rsa, padding, hashes, UnsupportedAlgorithm


def load_key(data, encoding="raw", password=None):
    serialization, rsa, _, _, unsupported = backend()
    if encoding != "raw":
        try:
            text = data.decode("utf-8-sig")
            data = bytes.fromhex(text) if encoding == "hex" else base64.b64decode("".join(text.split()), validate=True)
        except (ValueError, UnicodeError):
            raise ValueError("Invalid key encoding. Save only the key value and select raw, hex, or base64.") from None
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    # Whitespace is legal around PEM; preserve every DER byte.
    loader = serialization.load_pem_private_key if data.lstrip().startswith(b"-----BEGIN ") else serialization.load_der_private_key
    try:
        key = loader(data.lstrip() if loader == serialization.load_pem_private_key else data, password=password)
    except (ValueError, TypeError, unsupported):
        raise ValueError("Cannot load private key. Check PEM/DER content, --key-encoding, and --ask-password for encrypted keys.") from None
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("This command requires an RSA private key; EC, Ed25519, DSA, and other key types are not supported.")
    return key


def decrypt(key, ciphertext, padding_name, oaep_hash=None, mgf_hash=None, label=None):
    _, _, padding, hashes, _ = backend()
    size = (key.key_size + 7) // 8
    if len(ciphertext) != size:
        raise ValueError("RSA ciphertext must be exactly {} bytes for this {}-bit key; check --input-format.".format(size, key.key_size))
    if int.from_bytes(ciphertext, "big") >= key.private_numbers().public_numbers.n:
        raise ValueError("RSA ciphertext integer must be smaller than the key modulus.")
    if padding_name != "oaep" and any(value is not None for value in (oaep_hash, mgf_hash, label)):
        raise ValueError("--oaep-hash, --mgf-hash, and --label-hex require --padding oaep.")
    if padding_name == "raw":
        numbers = key.private_numbers()
        return pow(int.from_bytes(ciphertext, "big"), numbers.d, numbers.public_numbers.n).to_bytes(size, "big")
    if padding_name == "oaep":
        algorithms = {"sha1": hashes.SHA1, "sha256": hashes.SHA256, "sha384": hashes.SHA384, "sha512": hashes.SHA512}
        selected = oaep_hash or "sha256"
        scheme = padding.OAEP(mgf=padding.MGF1(algorithms[mgf_hash or selected]()), algorithm=algorithms[selected](), label=label)
    elif padding_name == "pkcs1v15":
        scheme = padding.PKCS1v15()
    else:
        raise ValueError("RSA padding must be oaep, pkcs1v15, or raw.")
    try:
        return key.decrypt(ciphertext, scheme)
    except ValueError:
        raise ValueError("RSA decryption failed. Check the matching key, ciphertext, padding, and OAEP hash/MGF/label.") from None


def add_commands(commands, add_source, add_output):
    p = commands.add_parser("rsa-key", help="Decrypt RSA using a PEM/DER private key, including hex-encoded keys")
    p.add_argument("--key-file", required=True, help="Path to RSA private key (PEM or DER)")
    p.add_argument("--key-encoding", choices=("raw", "hex", "base64"), default="raw", help="Outer encoding of the complete key file (default: raw)")
    p.add_argument("--ask-password", action="store_true", help="Prompt privately for an encrypted key's password")
    add_source(p)
    p.add_argument("--input-format", choices=("raw", "hex", "base64"), default="raw")
    p.add_argument("--padding", choices=("oaep", "pkcs1v15", "raw"), required=True, help="Match the challenge's encryption padding; raw preserves leading zero bytes")
    p.add_argument("--oaep-hash", choices=HASHES, help="OAEP digest (default: sha256)")
    p.add_argument("--mgf-hash", choices=HASHES, help="MGF1 digest (default: same as OAEP digest)")
    p.add_argument("--label-hex", help="OAEP label as hex (default: empty)")
    add_output(p)


def run(args, read_input, decode, show_bytes):
    path = Path(args.key_file)
    with path.open("rb") as handle:
        data = handle.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024:
        raise ValueError("Private key file must be at most 1 MiB.")
    password = None
    if args.ask_password:
        try:
            password = getpass.getpass("Private-key password: ").encode("utf-8")
        except (EOFError, KeyboardInterrupt):
            raise ValueError("Private-key password entry cancelled.") from None
    key = load_key(data, args.key_encoding, password)
    source = read_input(args)
    ciphertext = source if args.input_format == "raw" else decode(source.decode("utf-8-sig"), args.input_format)
    plaintext = decrypt(key, ciphertext, args.padding, args.oaep_hash, args.mgf_hash,
                        bytes.fromhex(args.label_hex) if args.label_hex is not None else None)
    show_bytes(plaintext, args.out)
