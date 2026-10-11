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

## RSA private-key files

For a PEM/DER private key instead of RSA numbers, see [RSA private keys](rsa.md):

```sh
ctf-crypto rsa-key --key-file private.pem --file encrypted.bin --padding oaep --oaep-hash sha256
ctf-crypto rsa-key --key-file private.hex --key-encoding hex --file encrypted.hex --input-format hex --padding pkcs1v15
```

These are templates: supply files and match the challenge's padding. `rsa-key` needs optional `cryptography`; supports OAEP, PKCS#1 v1.5, and unpadded `raw`; and accepts `--ask-password` for encrypted key files.

## LFSR and AES

```sh
ctf-crypto lfsr --state 1001 --taps 0,3 --bits 8
ctf-crypto lfsr-aes --file output.txt --mode ecb
ctf-crypto docs lfsr
ctf-crypto docs aes
ctf-crypto docs lfsr-aes
```

LFSR is dependency-free; AES and LFSR-AES need the optional `cryptography` package. AES supports ECB/CBC decryption with known keys and PKCS#7 or no padding. LFSR-AES derives a key by directly packing output bits. All conventions are explicit and configurable; no automatic challenge detection is performed.

## More crypto and misc commands

```sh
ctf-crypto vigenere --text LXFOPVEFRNHR --key LEMON
ctf-crypto vigenere-crack --file ciphertext.txt --key-size 5
ctf-crypto xor-repeat-crack --file ciphertext.bin
ctf-crypto hash-check --algorithm sha256 --digest ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad --wordlist words.txt
ctf-crypto file-info --file mystery.bin --scan
ctf-crypto strings --file mystery.bin --encoding all
ctf-crypto hexdump --file mystery.bin
ctf-crypto carve --file mystery.bin --offset 32 --length 128 --out slice.bin
ctf-crypto zip-info --file archive.zip
ctf-crypto zip-read --file archive.zip --member note.txt --out note.txt
ctf-crypto image-info --file picture.png
ctf-crypto lsb --file picture.png --bytes 16
```

Read `ctf-crypto docs classical` for cipher guessing and bounded local wordlist checks. Read `ctf-crypto docs misc` for file limits, offsets, ZIP handling, and image extraction. Guesses and signature matches are not verified solutions. Image commands need optional Pillow; the other commands in this section use the standard library.

## Documentation and output

```sh
ctf-crypto docs
ctf-crypto docs --open
ctf-crypto docs rsa --open
ctf-crypto docs --out guide.html
ctf-crypto docs --list
ctf-crypto docs all --out toolkit-guide.md
ctf-crypto --version
```

The guide is bundled with source, wheels, and portable `.pyz` downloads. It works without AES installed and without network access. `docs --list` only lists topic names; `docs TOPIC --out FILE` exports a guide.

For commands accepting `--text`/`--file`, provide exactly one. Quote text containing spaces. `--out` always refuses to overwrite existing files. For encode and LFSR generation it saves formatted ASCII; for decode, XOR, RSA, and AES it saves raw result bytes. Documentation defaults to readable terminal text. Exporting to `.html` creates the complete visual guide; other paths default to UTF-8 Markdown. Override with `--format text`, `markdown`, or `html`. Without `--out`, binary-result commands display hex and a readable preview.

Return codes: `0` means the requested operation completed, `1` means an input/decryption/file/dependency error, and `2` means invalid command-line arguments. Success does not guarantee that a candidate plaintext is the intended flag.
