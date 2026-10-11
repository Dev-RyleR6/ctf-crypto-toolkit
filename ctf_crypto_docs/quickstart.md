# Start here

An offline toolkit for common CTF crypto and file-analysis tasks. Start with what the challenge gives you, then choose one recipe. Python 3.9 or newer is required.

## 1. Run your first command

If you already installed the toolkit:

```sh
ctf-crypto decode --from base64 --text "ZmxhZ3twcmFjdGljZX0="
```

Expected result:

```text
Hex: 666c61677b70726163746963657d
UTF-8: flag{practice}
```

Downloaded the source instead? Run this from the folder containing `crypto_toolkit.py`:

```sh
python crypto_toolkit.py decode --from base64 --text "ZmxhZ3twcmFjdGljZX0="
```

## 2. Pick the matching recipe

| I have... | Start with | Guide |
|---|---|---|
| PEM, DER, or a hex-encoded RSA private key | `rsa-key` | [RSA private keys](rsa.md) |
| RSA numbers `n`, `d`, and `c` | `rsa` | [RSA private keys](rsa.md) |
| An AES key and ciphertext | `aes` | [AES decryption](aes.md) |
| An LFSR state, taps, and ciphertext | `lfsr-aes` | [LFSR + AES](lfsr-aes.md) |
| Base64, hex, or scrambled letters | `decode`, `caesar`, `vigenere` | [Classical ciphers](classical.md) |
| XOR ciphertext | `xor`, `xor-crack`, `xor-repeat-crack` | [Classical ciphers](classical.md) |
| A mystery file, ZIP, or image | `file-info`, `strings`, `zip-info`, `image-info` | [Files & hidden data](misc.md) |
| A simple hash and a wordlist | `hash-check` | [Classical ciphers](classical.md) |

There is no universal decrypt button. You need the algorithm and its settings for AES/RSA. Encodings need no secret key. Hashes are checked against guesses, not decrypted.

## 3. Read the guide your way

**Visual guide** with navigation, search, and copy buttons:

```sh
ctf-crypto docs --open
```

**One topic** as readable terminal text:

```sh
ctf-crypto docs rsa
```

**Save a shareable offline HTML guide** (all topics included):

```sh
ctf-crypto docs --out guide.html
```

Open `guide.html` in any browser. It contains its own styles and scripts and makes no network requests. If Copy cannot run, the guide selects the text for manual copying.

Other options: `docs --list` lists topics, `docs all --out guide.md` exports Markdown, and `docs rsa --format markdown` prints raw Markdown. Every tool has `--help`, for example `ctf-crypto rsa-key --help`. Output files must be new.

## Install once, use from any folder

From the source folder, install all features with pipx:

```sh
python -m pip install --user pipx
python -m pipx ensurepath
python -m pipx install ".[all]"
```

Restart your terminal after `ensurepath`. Then `ctf-crypto` works from any folder. Use paths to your challenge files, or open the terminal in the challenge folder. If pipx is already installed, skip the first command.

**Updating an existing pipx install:** after downloading or pulling the updated source, run this from that source folder:

```sh
python -m pipx install --force ".[all]"
```

**Virtual environment alternative:** activate your environment, then run `python -m pip install ".[all]"`. Use `python -m crypto_toolkit` if the command is not found. Base-only install: `python -m pip install .`.

## Optional features and portable use

| Feature | Extra dependency |
|---|---|
| AES and RSA key files | `cryptography` (`.[aes]` or `.[rsa]`) |
| Image metadata and LSB extraction | `Pillow` (`.[images]`) |
| Other commands and visual documentation | None |

The `.[all]` install includes both dependencies. Installation may need internet; toolkit commands work offline afterward.

To run source or a portable `.pyz`, replace `ctf-crypto` with `python crypto_toolkit.py` or `python ctf-crypto-0.4.0.pyz`. For their optional features, install dependencies into the same Python environment:

```sh
python -m pip install cryptography Pillow
```

On Windows, try `py` if `python` is unavailable. On macOS/Linux, use `python3` if needed. A `.pyz` still requires Python; it is not a standalone executable.
