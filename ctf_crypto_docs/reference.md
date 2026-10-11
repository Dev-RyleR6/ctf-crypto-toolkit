# Command reference

Run `ctf-crypto COMMAND --help` for all options. Replace `ctf-crypto` with `python crypto_toolkit.py` when running from source, or `python -m crypto_toolkit` after installation.

## Encode and decode

```sh
ctf-crypto encode --to base64 --text "flag{practice}"
ctf-crypto decode --from base64 --text "ZmxhZ3twcmFjdGljZX0="
ctf-crypto decode --from hex --text "4869"
ctf-crypto decode --from binary --text "01001000 01101001"
ctf-crypto decode --from url --text "flag%7Burl%7D"
ctf-crypto decode --from base64 --file encoded.txt --out decoded.bin
```

Formats: `hex`, `base64`, `base32`, `binary`, `url`. Decoding returns bytes; encoding produces ASCII text. Base64 requires valid characters and padding, but permits whitespace. Binary requires complete eight-bit bytes. URL decoding preserves literal `+`; it is not form-data decoding. Encoding is not encryption.

## Caesar and XOR

```sh
ctf-crypto caesar --text "khoor"
ctf-crypto caesar --text "synt{ebg13}" --shift 13
ctf-crypto xor --text "424f464645" --input-format hex --key 2a --key-format hex
ctf-crypto xor-crack --text "424f464645" --input-format hex --top 10
```

Without `--shift`, Caesar prints all 26 forward shifts. Negative shifts reverse a rotation. Only ASCII letters change.

XOR repeats the supplied key beginning at byte zero. Default input is raw bytes; default key format is UTF-8 text. `xor-crack` tries all 256 single-byte keys and ranks English-looking results. Scores are not probabilities. It does not break arbitrary repeating-key XOR; short or non-English plaintext can rank poorly. `--top 256` prints every candidate.

## Frequency and hashes

```sh
ctf-crypto frequency --text "some example text"
ctf-crypto hash --text "abc" --algorithm sha256
ctf-crypto hash --file challenge.bin --algorithm sha256
```

Frequency counts ASCII letters case-insensitively. Hash algorithms: `md5`, `sha1`, `sha256` (default), `sha512`. Files are hashed byte-for-byte, including newlines. Hashing does not recover the original input. MD5 and SHA-1 are available for CTF analysis, not new security designs.

## Modular arithmetic and textbook RSA

```sh
ctf-crypto inverse 17 3120
ctf-crypto rsa --n 3233 --d 2753 --c 2790
```

Expected inverse: `2753`. Expected message: integer `65`, text `A`. Integers accept decimal or `0x` hex notation. RSA requires an already-known private exponent; it does not factor keys or remove encryption padding. Bytes use minimal big-endian representation, so leading zero bytes are not reconstructed.

## LFSR and AES

```sh
ctf-crypto lfsr --state 1001 --taps 0,3 --bits 8
ctf-crypto lfsr-aes --file output.txt --mode ecb
ctf-crypto docs lfsr
ctf-crypto docs aes
ctf-crypto docs lfsr-aes
```

LFSR is dependency-free; AES and LFSR-AES need the optional `cryptography` package. AES supports ECB/CBC decryption with known keys and PKCS#7 or no padding. LFSR-AES derives a key by directly packing output bits. All conventions are explicit and configurable; no automatic challenge detection is performed.

## Documentation and output

```sh
ctf-crypto docs
ctf-crypto docs --list
ctf-crypto docs all --out toolkit-guide.md
ctf-crypto --version
```

The guide is bundled with source, wheels, and portable `.pyz` downloads. It works without AES installed and without network access. `docs --list` only lists topic names; `docs TOPIC --out FILE` exports a guide.

For commands accepting `--text`/`--file`, provide exactly one. Quote text containing spaces. `--out` always refuses to overwrite existing files. For encode and LFSR generation it saves formatted ASCII; for decode, XOR, RSA, and AES it saves raw result bytes. Documentation exports UTF-8 Markdown. Without `--out`, binary-result commands display hex and a readable preview.

Return codes: `0` means the requested operation completed, `1` means an input/decryption/file/dependency error, and `2` means invalid command-line arguments. Success does not guarantee that a candidate plaintext is the intended flag.
