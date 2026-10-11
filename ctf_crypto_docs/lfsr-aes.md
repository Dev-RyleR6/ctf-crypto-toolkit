# LFSR + AES challenge workflow

Use `lfsr-aes` when a file supplies an initial bit state, taps, and hex ciphertext, and the AES key is formed by packing LFSR output bits directly. The command reads the file, generates the key, decrypts AES, and removes padding if selected.

```sh
ctf-crypto lfsr-aes --file output.txt --mode ecb
```

Install AES support first if needed: `python -m pip install ".[aes]"` from the source folder, or `python -m pip install cryptography` in the environment running the tool.

## Required file format

The file must have exactly these three fields, in this order:

```text
LFSR Initial State:
[1, 0, 0, 1, 1, 0, 1, 0]
LFSR Taps:
[7, 5, 4, 3]
Encrypted Flag:
<hexadecimal ciphertext here>
```

Replace the placeholder with the actual ciphertext; angle brackets are not valid hex. State and taps are JSON arrays, not executable Python. Whitespace and wrapped arrays/hex are accepted. A UTF-8 BOM is accepted. Additional fields, invalid bits, malformed arrays, and non-hex ciphertext are rejected.

The file does not specify the AES mode or LFSR convention. You must choose those from the encryption source or challenge instructions. The command does not guess or brute-force them.

## Defaults and overrides

The default key generation is:

1. Keep the state in its listed order.
2. Treat taps as zero-based positions counted from the left.
3. Emit the first state bit BEFORE shifting.
4. XOR the selected state bits, shift left, and append the feedback.
5. Collect 128 output bits with no skipped steps.
6. Pack each group of eight bits most-significant-bit first into a 16-byte AES key.

These match the convention we used in the CryptoMaze exercise. They are not universal LFSR rules.

Use `--key-bits 192` or `--key-bits 256` for AES-192 or AES-256. The command also supports `--shift`, `--output-bit`, `--tap-base`, `--tap-origin`, `--byte-order`, and `--skip`, exactly as documented in `ctf-crypto docs lfsr`.

Example of explicitly selecting a different convention (only use it if your challenge requires it):

```sh
ctf-crypto lfsr-aes --file output.txt --mode ecb --shift right --output-bit last --tap-base 1 --tap-origin right --byte-order lsb --key-bits 256 --skip 64
```

Mode is required: `--mode ecb` or `--mode cbc`. CBC additionally needs `--iv` (hex) or `--iv-prefix`. `--padding pkcs7` is the default; use `--padding none` for unpadded whole blocks. See `ctf-crypto docs aes` for those options.

## Try the bundled practice fixture

From the source folder:

```sh
python crypto_toolkit.py lfsr-aes --file examples/lfsr_aes_demo.txt --mode ecb
```

Expected plaintext: `flag{lfsr_aes_demo}`. This is a synthetic practice message, not a published challenge answer. Source downloads include the fixture; a wheel only installs the code and documentation.

## Inspect or save the result

The command prints the derived key as hex, followed by plaintext hex and a text/byte preview. To save the exact plaintext bytes:

```sh
ctf-crypto lfsr-aes --file output.txt --mode ecb --out recovered.bin
```

It refuses to overwrite existing files. Padding failure happens before writing any plaintext. The command does not submit flags or call external services.

## Troubleshooting

- **Tap out of range:** confirm state width, tap base, and whether the tap numbers are array positions or polynomial exponents. Polynomial exponents must be translated according to the challenge's implementation.
- **Invalid padding / unreadable output:** check shift direction, output bit, tap numbering, bit packing, key size, skipped steps, mode, IV, and padding.
- **Missing AES dependency:** install `cryptography` in the same environment used to launch the command.
- **Key derived through SHA-256 or another transformation:** this combined command only packs bits directly. Generate the material with `lfsr`, reproduce the stated derivation separately, then use `aes` with the resulting key.
- **Different file layout or Galois LFSR:** convert the data or implement the stated recurrence first. This parser and generator intentionally use a documented, explicit format.
