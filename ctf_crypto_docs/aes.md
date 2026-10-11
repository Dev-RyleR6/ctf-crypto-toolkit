# AES decryption

The `aes` command decrypts AES-128, AES-192, or AES-256 in ECB or CBC mode. Key length selects the AES variant. Install the optional `cryptography` dependency first:

```sh
python -m pip install ".[aes]"
```

Run that from the source folder in your active virtual environment. Alternatively use `python -m pip install cryptography` with the Python interpreter running the source script or `.pyz`. The download includes no bundled third-party AES implementation.

## Known key, ECB example

This one-block AES test vector has no padding:

```sh
ctf-crypto aes --mode ecb --key 2b7e151628aed2a6abf7158809cf4f3c --text 3ad77bb40d7a3660a89ecaf32466ef97 --input-format hex --padding none
```

Expected plaintext hex: `6bc1bee22e409f96e93d7e117393172a`. The plaintext is binary; a readable flag is not expected from this example.

## CBC with an explicit IV

```sh
ctf-crypto aes --mode cbc --key 2b7e151628aed2a6abf7158809cf4f3c --iv 000102030405060708090a0b0c0d0e0f --text 7649abac8119b246cee98e9b12e9197d --input-format hex --padding none
```

This decrypts to the same plaintext hex as above. The IV is exactly 16 bytes (32 hex digits). ECB does not use an IV and rejects IV arguments. CBC requires an explicit IV or `--iv-prefix`; there is no guessed zero IV.

If the challenge file has a 16-byte IV followed by raw CBC ciphertext:

```sh
ctf-crypto aes --mode cbc --key 2b7e151628aed2a6abf7158809cf4f3c --file iv-and-ciphertext.bin --iv-prefix --out plaintext.bin
```

For a hex-encoded version of that file add `--input-format hex`. The IV is removed AFTER decoding, and is not part of the encrypted payload.

## Input and key formats

- Provide exactly one of `--text` or `--file` for ciphertext.
- `--input-format raw` is the default. Files are read as bytes; text is encoded as UTF-8.
- `--input-format hex` or `base64` decodes the supplied UTF-8 text/file before decryption. Hex may contain whitespace. Base64 needs correct padding.
- `--key` defaults to hex. Use `--key-format base64` or `text` when appropriate. Text keys are UTF-8 bytes, not passwords passed through a key derivation function.
- The decoded key must be exactly 16, 24, or 32 bytes.
- After removing any prefixed IV, ECB/CBC ciphertext must be nonempty and a multiple of 16 bytes.

## Padding and output

`--padding pkcs7` is the default. It validates and removes PKCS#7 padding for a 16-byte AES block. Invalid padding raises an error and does not create an output file. An error may mean the key, convention, IV, mode, padding choice, or ciphertext is wrong.

Use `--padding none` when the challenge specifies unpadded whole blocks. It preserves every decrypted byte, including trailing bytes that resemble padding. Do not treat garbage bytes as a recovered flag just because no padding check was requested.

Without `--out`, the command shows hex and a UTF-8/byte preview. `--out plaintext.bin` writes exact plaintext bytes and refuses to overwrite an existing file.

ECB/CBC do not authenticate a message. Valid padding alone is not proof that you found the intended key; check the plaintext against the challenge. This tool currently does not support CTR, GCM, tags, password-derived keys, or AES encryption.

Implementation reference: https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/
