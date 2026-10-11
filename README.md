# CTF Crypto Toolkit

An offline toolkit for CTF cryptography and miscellaneous file analysis. Decode data, analyze Caesar/Vigenere/XOR, check simple hashes against wordlists, derive LFSR keys, decrypt AES, and investigate files, ZIP archives, metadata, and image bit-planes. Read the bundled documentation in your terminal.

**Requires Python 3.9 or newer.** Base crypto and file-analysis commands use the standard library. AES requires optional `cryptography`; image metadata and bit extraction require optional `Pillow`. Commands make no AI or network calls and work offline once dependencies are installed. Designed for Windows, macOS, and Linux terminals.

## Download and run — no installation

On [the GitHub repository](https://github.com/Dev-RyleR6/ctf-crypto-toolkit), select **Code → Download ZIP**, extract it, and open a terminal inside the extracted folder containing `crypto_toolkit.py`. Run:

```sh
python crypto_toolkit.py --help
python crypto_toolkit.py docs
python crypto_toolkit.py decode --from base64 --text "ZmxhZ3twcmFjdGljZX0="
```

Expected result:

```text
Hex: 666c61677b70726163746963657d
UTF-8: flag{practice}
```

On Windows, try `py` if `python` is unavailable. On macOS/Linux, use `python3` if needed. Get Python from [python.org](https://www.python.org/downloads/) if it is not installed.

### Single-file download

If the repository owner has attached release files, download `ctf-crypto-0.3.0.pyz` from **Releases**. Keep the file intact and run:

```sh
python ctf-crypto-0.3.0.pyz docs
python ctf-crypto-0.3.0.pyz caesar --text "synt{ebg13}" --shift 13
```

The `.pyz` contains the tool, offline documentation, README, practice guide, and license. It requires Python and is not a standalone Windows executable. Base commands work without pip. For AES/images, install `cryptography`/`Pillow` in the same Python environment; third-party libraries are not bundled.

## Install the `ctf-crypto` command

From the extracted source folder, create a virtual environment:

```sh
python -m venv .venv
```

Activate it with the command for your terminal:

| Terminal | Command |
|---|---|
| Windows PowerShell | `.\.venv\Scripts\Activate.ps1` |
| Windows Command Prompt | `.venv\Scripts\activate.bat` |
| macOS/Linux shell | `source .venv/bin/activate` |

Then install and run:

```sh
python -m pip install .
ctf-crypto --version
ctf-crypto decode --from hex --text "666c61677b6865787d"
```

For **all features**, install the optional extras instead (or run this later to add them):

```sh
python -m pip install ".[all]"
ctf-crypto docs misc
```

Use `".[aes]"` for only AES or `".[images]"` for only image support. For source/portable use, `python -m pip install cryptography Pillow` installs both. Use the same Python environment to install and run. To upgrade, pull/download the updated source and run `python -m pip install ".[all]"` again.

For pipx users, install from this source folder with `python -m pipx install ".[all]"`. To update an existing pipx copy from this folder, use `python -m pipx install --force ".[all]"`. Run `python -m pipx ensurepath` and restart the terminal if the command is not on PATH. See the [pipx setup guide](https://pipx.pypa.io/stable/how-to/install-pipx.html).

If PowerShell blocks activation, run `.\.venv\Scripts\python.exe -m pip install .` and `.\.venv\Scripts\ctf-crypto.exe --help` instead; no execution-policy change is needed.

Installing from source may download setuptools and optional dependencies. AES/images work offline after their dependencies are installed. For completely offline base use, run the source script or `.pyz`, or install a provided wheel without downloads:

```sh
python -m pip install --no-index --no-deps ctf_crypto_toolkit-0.3.0-py3-none-any.whl
```

After installation, `python -m crypto_toolkit` is an alternative to `ctf-crypto`. Use the Python interpreter from the environment where you installed it. Activate that environment in each new terminal, or run its executable by full path.

## Documentation command

```sh
ctf-crypto docs
ctf-crypto docs --list
ctf-crypto docs lfsr
ctf-crypto docs aes
ctf-crypto docs lfsr-aes
ctf-crypto docs classical
ctf-crypto docs misc
ctf-crypto docs all --out toolkit-guide.md
```

Documentation is bundled with the source, wheel, and portable download. It prints Markdown in the terminal without a browser or network connection. `--out` exports to a new UTF-8 file. Each command also supports `--help`.

Read on GitHub: [Quickstart](ctf_crypto_docs/quickstart.md) · [Command reference](ctf_crypto_docs/reference.md) · [LFSR](ctf_crypto_docs/lfsr.md) · [AES](ctf_crypto_docs/aes.md) · [LFSR + AES](ctf_crypto_docs/lfsr-aes.md) · [Classical crypto](ctf_crypto_docs/classical.md) · [Misc/file analysis](ctf_crypto_docs/misc.md).

## Misc practice workflow

Generate a NEW directory of synthetic examples, then investigate it:

```sh
python examples/create_misc_demo.py --out-dir practice
ctf-crypto file-info --file practice/mystery.bin --scan
ctf-crypto strings --file practice/mystery.bin --encoding all
ctf-crypto zip-info --file practice/notes.zip
ctf-crypto image-info --file practice/picture.png
ctf-crypto lsb --file practice/picture.png --bytes 16
```

The final command recovers `flag{pixel_bits}`. The generator supplies metadata, strings, ZIP comments/members, a wordlist, and exact offsets for carving exercises. It refuses an existing directory. See `ctf-crypto docs misc` for the full walkthrough.

## LFSR + AES quick example

The bundled synthetic practice file can be solved with:

```sh
python crypto_toolkit.py lfsr-aes --file examples/lfsr_aes_demo.txt --mode ecb
```

Expected plaintext: `flag{lfsr_aes_demo}`. To use your own three-field challenge file:

```sh
ctf-crypto lfsr-aes --file output.txt --mode ecb
```

The default LFSR shifts left, emits the first bit before shifting, uses zero-based taps counted from the left, and packs 128 bits most-significant-bit first. Mode is always explicit; padding defaults to PKCS#7. These conventions must match the challenge. The [combined workflow guide](ctf_crypto_docs/lfsr-aes.md) explains overrides, CBC IVs, file format, and error messages.

## Commands

| Command | Purpose | Example arguments |
|---|---|---|
| `encode` | Hex, Base64, Base32, binary, URL encoding | `--to base64 --text "hello"` |
| `decode` | Convert an encoded value to bytes | `--from hex --text "6869"` |
| `caesar` | Try all shifts, or a specific shift | `--text "khoor"` |
| `xor` | Apply a known repeating key | `--text "hello" --key 2a --key-format hex` |
| `xor-crack` | Rank single-byte XOR candidates | `--text "424f464645" --input-format hex` |
| `frequency` | Count ASCII letters | `--text "a secret message"` |
| `hash` | MD5, SHA-1, SHA-256, SHA-512 digest | `--text "abc" --algorithm sha256` |
| `inverse` | Modular inverse | `17 3120` |
| `rsa` | Textbook RSA using known private exponent | `--n 3233 --d 2753 --c 2790` |
| `lfsr` | Generate bits or packed key material | `--state 1001 --taps 0,3 --bits 8` |
| `aes` | AES-ECB/CBC decryption with a known key | `--mode ecb --key HEX --file ciphertext.bin` |
| `lfsr-aes` | Read state/taps/ciphertext and derive an AES key | `--file output.txt --mode ecb` |
| `docs` | Read or export the offline guide | `lfsr-aes` or `all --out guide.md` |
| `vigenere` | Encrypt/decrypt with a known key | `--text LXFOPVEFRNHR --key LEMON` |
| `vigenere-crack` | Guess English Vigenere keys | `--file cipher.txt --key-size 5` |
| `xor-repeat-crack` | Guess repeating-key XOR | `--file cipher.bin --min-key 2 --max-key 40` |
| `hash-check` | Bounded unsalted-digest wordlist check | `--digest HEX --wordlist words.txt` |
| `file-info` | Size, hash, entropy, signature candidates | `--file mystery.bin --scan` |
| `strings` | ASCII/ASCII-range UTF-16 with offsets | `--file mystery.bin --encoding all` |
| `hexdump` | Inspect a byte range | `--file mystery.bin --length 64` |
| `carve` | Copy an exact range to a new file | `--file mystery.bin --offset 32 --length 128 --out slice.bin` |
| `zip-info` | ZIP entries and comments | `--file archive.zip` |
| `zip-read` | Copy one ZIP member to your chosen output | `--file archive.zip --member note.txt --out note.txt` |
| `image-info` | Image metadata and EXIF | `--file picture.png` |
| `lsb` | RGB/RGBA PNG/BMP bit-plane extraction | `--file picture.png --bytes 16` |

Prefix examples with `ctf-crypto` (installed) or `python crypto_toolkit.py` (source). Every command accepts `--help`.

### File input and output

```sh
ctf-crypto decode --from base64 --file encoded.txt --out decoded.bin
ctf-crypto xor --file encrypted.bin --key "ICE" --out decrypted.bin
ctf-crypto hash --file challenge.bin --algorithm sha256
```

Output files must not already exist. The tool refuses to overwrite files. See [CRYPTO_GUIDE.md](CRYPTO_GUIDE.md) for input formats, worked examples, and five short practice exercises.

### Limits

- XOR/Vigenere scores rank English-looking guesses, not proven solutions. Short or non-English messages can produce wrong guesses.
- RSA requires a known private exponent; it does not factor arbitrary keys or remove RSA padding.
- `hash-check` tests supplied wordlist entries against a simple unsalted digest; it does not support salted/password-hash records or generate candidates.
- LFSR uses explicit Fibonacci conventions and direct bit packing; it does not infer unknown states/taps or apply a hash-based key derivation function.
- AES currently supports ECB/CBC decryption, with PKCS#7 or no padding. It does not support CTR/GCM, authentication tags, or password-based key derivation. Valid padding alone does not prove that a candidate key is correct.
- Intended for modest CTF inputs loaded into memory. This is not a production encryption library.
- Signatures and entropy are clues, not proof of a file type or encryption. Carving requires explicit boundaries. Most file commands accept up to 64 MiB; image decoding is capped at 16 million pixels.
- Image bit extraction requires selected channels, bit-plane, offset, and length. It does not support every steganography format. This is not a PCAP, disk/memory-forensics, or reverse-engineering suite.

## Develop and test

```sh
python -m unittest discover -s tests -v
```

The test runner uses the standard library. Install `".[all]"` to run AES and image tests; missing dependencies cause those groups to skip. Coverage includes cipher vectors, heuristic recovery examples, padding, wordlist boundaries, file offsets, ZIP limits, image extraction, file preservation, and source/portable execution outside the source directory.

## Build downloads

```sh
python scripts/build_release.py
```

This uses the standard library to create a source ZIP, a portable `.pyz`, and SHA-256 checksums in `dist/`. It packages only an explicit list of project files, excluding virtual environments, caches, challenge files, and Git metadata. Rebuilding replaces generated release files for the same version.

Optional: build an installable wheel (this command may download build tools):

```sh
python -m pip wheel --no-deps --wheel-dir dist .
python scripts/build_release.py
```

The second command refreshes checksums to include the wheel, if present. Change `__version__` in `crypto_toolkit.py` when releasing a new version; package metadata and the release builder read it automatically.

## Push this folder to GitHub

For the initial upload to an empty repository, run these commands **inside this folder**. If you have already cloned or connected the repository, use your normal commit and push workflow instead:

```sh
git init -b main
git add .
git commit -m "Initial CTF Crypto Toolkit release"
git remote add origin https://github.com/Dev-RyleR6/ctf-crypto-toolkit.git
git push -u origin main
```

The source is downloadable through **Code → Download ZIP** after pushing. To offer the prepared downloads, create a GitHub release tagged `v0.3.0` and attach the matching `.pyz`, source `.zip`, optional `.whl`, and `SHA256SUMS.txt` from `dist/`. Generated downloads are Git-ignored; attach them to Releases. Older artifacts may remain in `dist/`; choose only files matching the release version.

No PyPI publication is needed. The installation instructions above use your downloaded source or wheel; they do not assume that this package name exists on PyPI.

## License

[MIT](LICENSE).

Packaging reference: [setuptools pyproject configuration](https://setuptools.pypa.io/en/latest/userguide/pyproject_config.html).
