# CTF Crypto Toolkit

**Find the clue. Choose a command. Recover the data.**

An offline Python toolkit for common CTF cryptography and miscellaneous file challenges. Decode text, decrypt RSA/AES with known keys, investigate archives and images, and learn through a searchable visual guide.

**Python 3.9+ · Windows / macOS / Linux · No AI or network calls from tool commands**

## Start in 30 seconds

Download this repository with **Code → Download ZIP**, extract it, and open a terminal in the folder containing `crypto_toolkit.py`.

```sh
python crypto_toolkit.py decode --from base64 --text "ZmxhZ3twcmFjdGljZX0="
```

You should see:

```text
Hex: 666c61677b70726163746963657d
UTF-8: flag{practice}
```

Open the visual documentation:

```sh
python crypto_toolkit.py docs --open
```

The guide works offline and includes topic navigation, search, copy buttons, expected results, and troubleshooting. No documentation dependencies are needed.

## Install the command for use anywhere

From this source folder:

```sh
python -m pip install --user pipx
python -m pipx ensurepath
python -m pipx install ".[all]"
```

Restart your terminal after `ensurepath`, then run:

```sh
ctf-crypto --version
ctf-crypto docs --open
```

Already using pipx? After pulling/downloading an update, run `python -m pipx install --force ".[all]"` from the updated source folder. See the [pipx installation guide](https://pipx.pypa.io/stable/how-to/install-pipx.html) if pipx itself needs setup.

Prefer an existing virtual environment? Activate it and run `python -m pip install ".[all]"`. To run directly from source with AES/RSA/image support, install `python -m pip install cryptography Pillow` in the same Python environment.

| Install | Features |
|---|---|
| `python -m pip install .` | Base encodings, classical ciphers, numeric RSA, LFSR, file/ZIP tools, docs |
| `python -m pip install ".[rsa]"` | Base + RSA key files and AES (same dependency) |
| `python -m pip install ".[images]"` | Base + image metadata and LSB |
| `python -m pip install ".[all]"` | Everything above |

`.[aes]` remains available. Installation may need internet; commands work offline afterward. If `ctf-crypto` is not found, use `python -m crypto_toolkit` with the Python environment where you installed it. Windows can also use `py`; macOS/Linux may use `python3`.

## What do you have?

| Challenge clue | Tools | Step-by-step guide |
|---|---|---|
| A private key and ciphertext | `rsa-key` (PEM, DER, hex/Base64 wrapped keys) | [RSA private keys](ctf_crypto_docs/rsa.md) |
| Numbers `n`, `d`, `c` | `rsa`, `inverse` | [RSA private keys](ctf_crypto_docs/rsa.md) |
| AES key / IV / ciphertext | `aes` (ECB, CBC) | [AES](ctf_crypto_docs/aes.md) |
| LFSR state and taps | `lfsr`, `lfsr-aes` | [LFSR + AES](ctf_crypto_docs/lfsr-aes.md) |
| Encoded or scrambled text | `encode`, `decode`, `caesar`, `vigenere`, `frequency` | [Classical crypto](ctf_crypto_docs/classical.md) |
| Unknown XOR or Vigenere key | `xor-crack`, `xor-repeat-crack`, `vigenere-crack` | [Classical crypto](ctf_crypto_docs/classical.md) |
| Known XOR key | `xor` | [Command reference](ctf_crypto_docs/reference.md) |
| Digest or simple hash + wordlist | `hash`, `hash-check` | [Classical crypto](ctf_crypto_docs/classical.md) |
| Mystery file | `file-info`, `strings`, `hexdump`, `carve` | [File analysis](ctf_crypto_docs/misc.md) |
| ZIP archive | `zip-info`, `zip-read` | [File analysis](ctf_crypto_docs/misc.md) |
| Image with hidden data | `image-info`, `lsb` | [File analysis](ctf_crypto_docs/misc.md) |

Every command supports `--help`. Read the [full command reference](ctf_crypto_docs/reference.md) for examples.

## RSA private-key example

For a PEM key and binary ciphertext encrypted with OAEP/SHA-256:

```sh
ctf-crypto rsa-key --key-file private.pem --file encrypted.bin --padding oaep --oaep-hash sha256
```

For a key stored as hex (starting with `2d2d2d2d2d424547494e...`), add `--key-encoding hex`:

```sh
ctf-crypto rsa-key --key-file private.hex --key-encoding hex --file encrypted.bin --padding oaep --oaep-hash sha256
```

These are templates: supply your own files and match the challenge's padding. Supported choices are `oaep`, `pkcs1v15`, and unpadded `raw`. Encrypted key file? Add `--ask-password`. Ciphertext stored as hex/Base64? Add `--input-format hex` or `--input-format base64`. [Read the RSA recipe](ctf_crypto_docs/rsa.md).

## Documentation, without the clutter

| Want to... | Run |
|---|---|
| Open the visual guide | `ctf-crypto docs --open` |
| Open directly to RSA | `ctf-crypto docs rsa --open` |
| Read one topic in the terminal | `ctf-crypto docs rsa` |
| See all topics | `ctf-crypto docs --list` |
| Save a complete offline HTML guide | `ctf-crypto docs --out guide.html` |
| Export all topics as Markdown | `ctf-crypto docs all --out guide.md` |

HTML includes all topics; the selected topic opens first. Text/Markdown exports include the selected topic or `all`. Exports and decrypted output files must be new: existing files are never overwritten.

## Practice with included challenges

LFSR + AES (requires cryptography):

```sh
ctf-crypto lfsr-aes --file examples/lfsr_aes_demo.txt --mode ecb
```

Expected plaintext: `flag{lfsr_aes_demo}`. The [LFSR guide](ctf_crypto_docs/lfsr-aes.md) explains the state/tap conventions.

File and image practice (LSB requires Pillow):

```sh
python examples/create_misc_demo.py --out-dir practice
ctf-crypto strings --file practice/mystery.bin --encoding all
ctf-crypto zip-info --file practice/notes.zip
ctf-crypto lsb --file practice/picture.png --bytes 16
```

The last command recovers `flag{pixel_bits}`. The generator requires a new output directory. [Follow the complete walkthrough](ctf_crypto_docs/misc.md).

## Know the limits

- RSA key-file decryption supports one RSA block with known padding; it does not decrypt every private-key format, factor arbitrary keys, or handle PGP/SSH containers. Numeric `rsa` performs textbook RSA without removing padding.
- AES supports ECB/CBC with PKCS#7 or no padding. CTR/GCM, authentication tags, and password-derived keys are not supported. LFSR conventions must match the challenge; states/taps are not inferred.
- Cipher cracking ranks English-looking guesses. A high score or valid padding does not prove the result is correct. Hash checks use your wordlist and simple unsalted digests.
- File signatures and entropy are clues. Image extraction supports RGB/RGBA PNG/BMP with explicit channels, bit-plane, offset, and length. This is not a complete steganography, PCAP, or forensics suite.
- Most file-analysis inputs are capped at 64 MiB and image decoding at 16 million pixels. These are local CTF helpers, not a production encryption library.

## Develop and build downloads

```sh
python -m unittest discover -s tests -v
python scripts/build_release.py
```

Install `.[all]` to exercise optional AES/RSA/image tests; unavailable dependencies cause their tests to skip. The release builder creates an allowlisted source ZIP, a portable Python `.pyz`, and SHA-256 checksums in `dist/`.

Optional installable wheel:

```sh
python -m pip wheel --no-deps --wheel-dir dist .
python scripts/build_release.py
```

For a GitHub release tagged `v0.4.0`, attach the matching `.pyz`, source `.zip`, optional `.whl`, and `SHA256SUMS.txt`. Generated downloads are Git-ignored. The `.pyz` includes docs, requires Python, and uses optional dependencies from that Python environment. It is not a standalone executable. Source remains downloadable through **Code → Download ZIP**; no PyPI publication is assumed.

[MIT license](LICENSE) · [Beginner practice notes](CRYPTO_GUIDE.md)
