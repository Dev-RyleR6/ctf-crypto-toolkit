# Offline CTF crypto toolkit

See [README.md](README.md) for download and installation options. After installing, replace `python crypto_toolkit.py` in any example with `ctf-crypto` or `python -m crypto_toolkit`.

Run with Python 3.9 or newer. Base crypto and file-analysis commands use the standard library. AES and RSA private-key files need optional `cryptography`; image metadata and bit extraction need optional `Pillow`. Install all features with `python -m pip install ".[all]"` from the source folder. No commands make network or AI calls. On Windows, use `py` instead of `python` if needed. These examples work in PowerShell and Bash.

## Built-in documentation and advanced commands

```sh
python crypto_toolkit.py docs --open
python crypto_toolkit.py docs rsa
python crypto_toolkit.py docs --list
python crypto_toolkit.py docs lfsr
python crypto_toolkit.py docs aes
python crypto_toolkit.py docs lfsr-aes
python crypto_toolkit.py docs classical
python crypto_toolkit.py docs misc
python crypto_toolkit.py docs all --out toolkit-guide.md
```

The same documentation is bundled in every source, wheel, and portable download. See the [LFSR guide](ctf_crypto_docs/lfsr.md), [AES guide](ctf_crypto_docs/aes.md), [combined challenge workflow](ctf_crypto_docs/lfsr-aes.md), [classical crypto](ctf_crypto_docs/classical.md), and [misc workflow](ctf_crypto_docs/misc.md).

From your activated environment in the source folder, install AES support with `python -m pip install ".[aes]"`. Then try the synthetic practice fixture:

```sh
python crypto_toolkit.py lfsr-aes --file examples/lfsr_aes_demo.txt --mode ecb
```

Expected plaintext: `flag{lfsr_aes_demo}`. The combined command directly packs LFSR bits into a key and requires the AES mode explicitly. Its documented defaults are a left shift, first bit output before shifting, zero-based taps counted from the left, and MSB-first packing. These must match the challenge implementation.

```sh
python crypto_toolkit.py
python crypto_toolkit.py xor --help
```

## Quick decision guide

| Clue | Try | Important limit |
|---|---|---|
| Hex digits grouped in pairs | `decode --from hex` | A hex string could also represent a hash or ciphertext |
| Letters, digits, `+`, `/`, possibly `=` | `decode --from base64` | Appearance alone does not identify the encoding |
| Eight-bit groups of zeros and ones | `decode --from binary` | Requires complete bytes |
| `%7B`, `%20`, etc. | `decode --from url` | Literal `+` is preserved; this is not form decoding |
| Words with shifted letters | `caesar` | Tries 26 shifts; not a general substitution solver |
| Suspected single-byte XOR | `xor-crack` | English guesses, not guaranteed solutions |
| A known XOR key | `xor` | Repeating key; the same operation encrypts/decrypts |
| Substitution-cipher text | `frequency` | Counts provide clues, not automatic decryption |
| Given RSA integers | `inverse`, then `rsa` | Textbook RSA only; no factoring or padding removal |
| Given RSA private-key file | `rsa-key` | PEM/DER, hex/Base64 wrapper, OAEP/PKCS#1 v1.5/raw; see `docs rsa` |

## Copy-and-run examples

### Encoding is reversible without a secret key

```sh
python crypto_toolkit.py encode --to base64 --text 'flag{practice}'
python crypto_toolkit.py decode --from base64 --text 'ZmxhZ3twcmFjdGljZX0='
python crypto_toolkit.py decode --from hex --text '666c61677b6865787d'
python crypto_toolkit.py decode --from binary --text '01001000 01101001'
python crypto_toolkit.py decode --from url --text 'flag%7Burl%7D'
```

Expected decoded text: `flag{practice}`, `flag{hex}`, `Hi`, and `flag{url}`. Base64 requires correct padding and rejects invalid characters, while whitespace is permitted. Base32 is also supported. No automatic decoding chain is guessed: inspect each result and decide the next step.

### Caesar / ROT13

```sh
python crypto_toolkit.py caesar --text 'synt{ebg13}' --shift 13
python crypto_toolkit.py caesar --text 'khoor'
```

The first prints `flag{rot13}`. The second displays every forward shift; shift 23 prints `hello`. A negative shift reverses an encryption shift. Only ASCII A–Z/a–z change.

### XOR

```sh
python crypto_toolkit.py xor --text 'hello' --key 2a --key-format hex
python crypto_toolkit.py xor --text '424f464645' --input-format hex --key 2a --key-format hex
python crypto_toolkit.py xor-crack --text '424f464645' --input-format hex --top 10
```

The known-key examples produce `424f464645` and `hello`. Cracking tries all 256 possible single-byte keys, including zero. Short, non-English, or binary messages may rank poorly; inspect candidates yourself. Use `--top 256` to see everything. This does not crack repeating-key XOR.

### Frequency and hashes

```sh
python crypto_toolkit.py frequency --text 'Wklv lv d vhfuhw phvvdjh'
python crypto_toolkit.py hash --text 'abc' --algorithm sha256
python crypto_toolkit.py hash --file challenge.bin --algorithm sha256
```

The SHA-256 of `abc` starts with `ba7816bf`. File bytes are hashed exactly, including any newline. MD5, SHA-1, and SHA-512 are available for challenge analysis. Hashes are not decrypted by this tool; MD5 and SHA-1 are not recommended for new security designs.

### Small textbook RSA exercise

Given prime factors `p = 61`, `q = 53`, exponent `e = 17`, and ciphertext `c = 2790`:

1. Compute `n = p*q = 3233`.
2. For these distinct primes, compute `phi = (p-1)*(q-1) = 3120`.
3. Find `d`, the modular inverse of `e` modulo `phi`.
4. Decrypt using `m = c^d mod n`.

```sh
python crypto_toolkit.py inverse 17 3120
python crypto_toolkit.py rsa --n 3233 --d 2753 --c 2790
```

Expected results: `2753`, then message integer `65` and text `A`. RSA integers can also use `0x` hex notation. The tool does not derive factors or private keys from arbitrary public keys. Output is minimal big-endian bytes: original leading zero bytes and RSA padding are not reconstructed or removed. It is a learning aid, not production encryption software.

## Working with files

Every text/byte analysis command accepts either `--text` or `--file`. For `decode`, `caesar`, and `frequency`, files must contain UTF-8 text. XOR reads raw bytes unless `--input-format` is specified.

```sh
python crypto_toolkit.py decode --from base64 --file encoded.txt --out decoded.bin
python crypto_toolkit.py xor --file encrypted.bin --key 'ICE' --out decrypted.bin
```

`--out` saves exact bytes and refuses to overwrite an existing file. Without it, byte results show hex and a readable preview. The XOR key begins at byte zero and repeats. Large inputs and `xor-crack --top 256` can produce large output; this toolkit is intended for modest CTF artifacts.

## Twenty-minute practice

1. Decode `666c61677b7761726d75707d` as hex.
2. Find the shift that makes `iodj{fdhvdu}` readable.
3. Decode `ZmxhZ3t0d29fc3RlcHN9` as Base64.
4. XOR hex `2c262b2d3132253837` with hex key `4a`.
5. Explain why a SHA-256 digest cannot simply be Base64-decoded into its original input.

Answers: `flag{warmup}`, forward shift 23 gives `flag{caesar}`, `flag{two_steps}`, and `flag{xor}`. For item 5, hashing is a one-way transformation, while Base64 is a reversible representation of bytes.

During practice, record the evidence that suggested each operation. During HackForGov, the briefer allows custom scripts but challenge-specific rules can impose restrictions. This script runs offline and contains no AI; check any organizer rules about prepared or AI-assisted materials before bringing it.

## Verification

```sh
python -m unittest discover -s tests -v
```

Tests cover known encoding and cipher vectors, arbitrary binary round trips, invalid input, RSA arithmetic, file preservation, and command-line behavior.
