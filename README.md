# CTF Crypto Toolkit

An offline command-line toolkit for common Capture-the-Flag cryptography tasks. Encode and decode data, try Caesar shifts, apply XOR keys, inspect English-ranked XOR candidates, count letters, calculate hashes, and work through textbook RSA exercises.

**Requires Python 3.9 or newer. No runtime packages, AI features, or network access required.** Designed for Windows, macOS, and Linux terminals. This is a command-line program; open a terminal to run it.

## Download and run — no installation

On [the GitHub repository](https://github.com/Dev-RyleR6/ctf-crypto-toolkit), select **Code → Download ZIP**, extract it, and open a terminal inside the extracted folder containing `crypto_toolkit.py`. Run:

```sh
python crypto_toolkit.py --help
python crypto_toolkit.py decode --from base64 --text "ZmxhZ3twcmFjdGljZX0="
```

Expected result:

```text
Hex: 666c61677b70726163746963657d
UTF-8: flag{practice}
```

On Windows, try `py` if `python` is unavailable. On macOS/Linux, use `python3` if needed. Get Python from [python.org](https://www.python.org/downloads/) if it is not installed.

### Single-file download

If the repository owner has attached release files, download `ctf-crypto-0.1.0.pyz` from **Releases**. Keep the file intact and run:

```sh
python ctf-crypto-0.1.0.pyz --help
python ctf-crypto-0.1.0.pyz caesar --text "synt{ebg13}" --shift 13
```

The `.pyz` contains the tool, README, practice guide, and license. It still requires Python; it is not a standalone Windows executable. Once downloaded, it works offline without pip.

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

If PowerShell blocks activation, run `.\.venv\Scripts\python.exe -m pip install .` and `.\.venv\Scripts\ctf-crypto.exe --help` instead; no execution-policy change is needed.

Installing from source may download the setuptools build tool. For completely offline use, run the source script or `.pyz` directly. If a wheel is provided in Releases, install it without downloads inside your environment:

```sh
python -m pip install --no-index --no-deps ctf_crypto_toolkit-0.1.0-py3-none-any.whl
```

After installation, `python -m crypto_toolkit` is an alternative to `ctf-crypto`. Use the Python interpreter from the environment where you installed it. Activate that environment in each new terminal, or run its executable by full path.

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

Prefix examples with `ctf-crypto` (installed) or `python crypto_toolkit.py` (source). Every command accepts `--help`.

### File input and output

```sh
ctf-crypto decode --from base64 --file encoded.txt --out decoded.bin
ctf-crypto xor --file encrypted.bin --key "ICE" --out decrypted.bin
ctf-crypto hash --file challenge.bin --algorithm sha256
```

Output files must not already exist. The tool refuses to overwrite files. See [CRYPTO_GUIDE.md](CRYPTO_GUIDE.md) for input formats, worked examples, and five short practice exercises.

### Limits

- XOR scores rank English-looking guesses, not proven solutions. Short messages can rank poorly.
- RSA requires a known private exponent; it does not factor arbitrary keys or remove RSA padding.
- Hashing computes digests; it does not reverse or crack them.
- Intended for modest CTF inputs loaded into memory. This is not a production encryption library.

## Develop and test

```sh
python -m unittest discover -s tests -v
```

Tests use only the standard library and cover known cipher vectors, error handling, file preservation, release contents, and execution of the portable download outside the source directory.

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

The source is downloadable through **Code → Download ZIP** after pushing. To offer the prepared downloads, create a GitHub release tagged `v0.1.0` and attach the `.pyz`, source `.zip`, optional `.whl`, and `SHA256SUMS.txt` from `dist/`. Generated downloads are intentionally Git-ignored; attach them to Releases instead of committing them.

No PyPI publication is needed. The installation instructions above use your downloaded source or wheel; they do not assume that this package name exists on PyPI.

## License

[MIT](LICENSE).

Packaging reference: [setuptools pyproject configuration](https://setuptools.pypa.io/en/latest/userguide/pyproject_config.html).
