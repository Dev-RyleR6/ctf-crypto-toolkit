# RSA private-key decryption

**Use this when:** the challenge gives you an RSA private key and an encrypted message. A key alone does not contain the flag; you also need ciphertext and the encryption settings.

## 1. Choose your key format

| What your key looks like | Save it as | Key option |
|---|---|---|
| Starts with `-----BEGIN PRIVATE KEY-----` or `-----BEGIN RSA PRIVATE KEY-----` | `private.pem` | `--key-file private.pem` |
| Starts with `2d2d2d2d2d424547494e...` | `private.hex` | `--key-file private.hex --key-encoding hex` |
| A binary DER file | `private.der` | `--key-file private.der` |
| Base64 of the complete PEM or DER file | `private.b64` | `--key-file private.b64 --key-encoding base64` |
| Numbers named `n`, `d`, and `c` | No key file needed | Use `rsa`, shown below |

For hex, save **only the hexadecimal value** in the file. Spaces and newlines are allowed. Do not include quotes, `0x`, a question, or other text. Ordinary PEM already contains Base64 between its headers: leave `--key-encoding` at `raw` for that.

`BEGIN PRIVATE KEY` identifies a key container, not its algorithm. This command verifies that the loaded key is RSA. It supports PKCS#8 and traditional RSA PEM/DER, including password-encrypted formats supported by the cryptography backend. It does not load OpenSSH or OpenPGP private keys.

## 2. Choose your ciphertext format

| What you received | Options |
|---|---|
| Binary ciphertext file | `--file encrypted.bin` |
| File containing hex text | `--file encrypted.hex --input-format hex` |
| File containing Base64 text | `--file encrypted.b64 --input-format base64` |
| Short hex value to paste | `--text "HEX_VALUE" --input-format hex` |

Key encoding and ciphertext encoding are separate options. A hex-encoded key can decrypt a binary ciphertext file.

## 3. Match the RSA padding

Read the challenge's encryption code or instructions. A PEM header cannot tell you the padding. Replace filenames below with your files; these are templates, not included challenge files.

**OAEP with SHA-256** (MGF1 also uses SHA-256):

```sh
ctf-crypto rsa-key --key-file private.pem --file encrypted.bin --padding oaep --oaep-hash sha256
```

**Your hex-encoded key, with hex ciphertext and PKCS#1 v1.5:**

```sh
ctf-crypto rsa-key --key-file private.hex --key-encoding hex --file encrypted.hex --input-format hex --padding pkcs1v15
```

Use `pkcs1v15` only if that is how the challenge encrypted the message. For OAEP, select the matching digest:

```sh
ctf-crypto rsa-key --key-file private.hex --key-encoding hex --file encrypted.hex --input-format hex --padding oaep --oaep-hash sha1
```

OAEP defaults to SHA-256. Supported digests: `sha1`, `sha256`, `sha384`, `sha512`. MGF1 defaults to the same digest. If needed, add `--mgf-hash sha1` or `--label-hex 637466` (the label `ctf`), matching the encryption source exactly.

## 4. Read or save the result

A successful command displays `Hex:` and `UTF-8:` (or a byte preview for non-text). Inspect the decrypted data against the expected flag format.

To save exact bytes, add `--out flag.txt`:

```sh
ctf-crypto rsa-key --key-file private.pem --file encrypted.bin --padding oaep --out flag.txt
```

The output file must be new. The private key is read locally and is not printed by this command.

## Password-protected keys

Add `--ask-password` to enter the key's password at a prompt. This unlocks the key file; it is separate from RSA encryption padding.

```sh
ctf-crypto rsa-key --key-file encrypted-private.pem --ask-password --file encrypted.bin --padding oaep
```

## Textbook RSA: numbers or no padding

For known `n`, `d`, and `c`, this dependency-free example works immediately:

```sh
ctf-crypto rsa --n 3233 --d 2753 --c 2790
```

Expected: message integer `65`, hex `41`, UTF-8 `A`. Numeric `rsa` outputs minimal-length bytes and does not remove padding.

For a PEM/DER key and explicitly unpadded RSA:

```sh
ctf-crypto rsa-key --key-file private.pem --file encrypted.bin --padding raw --out block.bin
```

`raw` preserves the full modulus-sized block, including leading zeros. It does not validate or remove padding. All `rsa-key` modes require exactly one modulus-sized ciphertext block (256 bytes for a 2048-bit key). A large encrypted file may use RSA to wrap an AES key: decrypt the wrapped key first, then use the appropriate AES settings.

## If a command fails

| Message or symptom | What to check |
|---|---|
| RSA key files require cryptography | Run `python -m pip install cryptography` in the tool's environment; pipx users can use `python -m pipx inject ctf-crypto-toolkit cryptography` |
| Cannot load private key | Encoding, complete headers/footer, and `--ask-password` if encrypted |
| Requires an RSA private key | EC/Ed25519/DSA keys need a different algorithm or protocol |
| Ciphertext must be exactly N bytes | Raw vs hex vs Base64, missing bytes, or a hybrid format |
| RSA decryption failed | Matching key, padding, OAEP digest, MGF1 digest, and label |
| Output looks wrong | Recheck settings and expected plaintext; raw RSA and some PKCS#1 v1.5 backends can return unverified bytes |

This does not recover missing private keys, factor arbitrary RSA moduli, or decrypt PGP/SSH containers. More options: `ctf-crypto rsa-key --help`.

Backend references: [RSA decryption](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/) and [key serialization](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/).
