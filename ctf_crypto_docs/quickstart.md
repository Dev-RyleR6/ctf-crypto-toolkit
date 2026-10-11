# Quickstart

CTF Crypto Toolkit runs locally with Python 3.9 or newer. It never calls AI or a network service. Encoding, Caesar, XOR, hashes, RSA arithmetic, LFSR generation, and documentation need only Python's standard library. AES commands additionally require `cryptography`.

## Install or run from source

From the downloaded source folder, install into your activated virtual environment:

```sh
python -m pip install ".[aes]"
ctf-crypto --version
ctf-crypto docs
```

For the base commands without AES, use `python -m pip install .`.

You can also run directly without installing this project:

```sh
python crypto_toolkit.py docs
python crypto_toolkit.py decode --from base64 --text "SGVsbG8="
```

For AES when running from source or a portable `.pyz`, install its dependency in the same Python environment first:

```sh
python -m pip install cryptography
```

Installation may need the internet; commands work offline once their dependencies are installed. If you already installed an older toolkit version, install the updated source again to update `ctf-crypto`.

## Read documentation in the terminal

```sh
ctf-crypto docs --list
ctf-crypto docs reference
ctf-crypto docs lfsr
ctf-crypto docs aes
ctf-crypto docs lfsr-aes
ctf-crypto docs all --out toolkit-guide.md
```

`docs` prints bundled Markdown without opening a browser or requiring an internet connection. `--out` exports a UTF-8 Markdown file and refuses to overwrite an existing file. `docs --list` only lists topics. Each tool command also has `--help` for its exact arguments.

## First examples

```sh
ctf-crypto decode --from hex --text "666c61677b6865787d"
ctf-crypto caesar --text "synt{ebg13}" --shift 13
ctf-crypto lfsr --state 1001 --taps 0,3 --bits 8
```

Expected results: `flag{hex}`, `flag{rot13}`, and `91` (hex).

## LFSR + AES challenge files

If the challenge uses a left-shifting Fibonacci LFSR, outputs its first bit before each shift, numbers taps from zero on the left, packs the first 128 output bits most-significant-bit first, and uses AES-ECB with PKCS#7 padding:

```sh
ctf-crypto lfsr-aes --file output.txt --mode ecb
```

These defaults match one common convention, not every LFSR challenge. Read `ctf-crypto docs lfsr-aes` to select the convention and file format. The mode is always explicit. The command prints the derived key and plaintext; it does not submit a flag.

## Alternative launch commands

Replace `ctf-crypto` in any example with one of:

- `python crypto_toolkit.py` from the source folder.
- `python -m crypto_toolkit` after installation.
- `python ctf-crypto-0.2.0.pyz` for the portable download.

On Windows, `py` may be the Python launcher. On macOS/Linux, use `python3` if needed. If `ctf-crypto` is not found, activate the environment where you installed it, or use that environment's Python executable with `-m crypto_toolkit`.
