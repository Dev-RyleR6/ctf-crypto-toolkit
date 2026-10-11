# Classical crypto and dictionary checks

These commands help analyze common CTF puzzles. They run offline with the standard library. Read this guide with `ctf-crypto docs classical`.

## First: rule out encoding and simple shifts

```sh
ctf-crypto decode --from base64 --text "ZmxhZ3twcmFjdGljZX0="
```

Expected: `flag{practice}`. Change `--from` to `hex`, `base32`, `binary`, or `url` to match the encoding. Use `--file encoded.txt` instead of `--text` for a file. Encodings require no key.

```sh
ctf-crypto caesar --text "synt{ebg13}" --shift 13
```

Expected: `flag{rot13}`. Omit `--shift` to try all 26 shifts.

```sh
ctf-crypto xor --text "424f464645" --input-format hex --key 2a --key-format hex
```

Expected: `hello`. For an unknown single-byte key, use `xor-crack` with the same input and omit the key options. Read [the reference](reference.md) for every encoding and XOR option.

## Vigenere with a known key

```sh
ctf-crypto vigenere --text "LXFOPVEFRNHR" --key LEMON
ctf-crypto vigenere --text "Attack at dawn!" --key LEMON --encrypt
ctf-crypto vigenere --file ciphertext.txt --key LEMON --out plaintext.txt
```

The first prints `ATTACKATDAWN`. Keys must be ASCII letters. Only ASCII letters in the message consume key positions; punctuation, spaces, and other characters are preserved. Letter case is preserved. Decryption is the default. `--out` saves UTF-8 text to a new file.

## Guess Vigenere keys

```sh
ctf-crypto vigenere-crack --file ciphertext.txt --key-size 5
ctf-crypto vigenere-crack --file ciphertext.txt --min-key 1 --max-key 20 --top 5
```

For each candidate length, the tool splits letters into columns and uses English letter-frequency chi-square scores to guess the shift in each column. It ranks the resulting keys using an English byte score with a small length penalty. Results are candidates, not verified decryptions. Non-English text, short flags, atypical letter distributions, and alternate Vigenere conventions may not work.

Analysis uses the first 8,192 text characters. Key lengths are bounded to 1-128 and need at least four analyzed letters per key position; much longer text is preferable. `--key-size` fixes a known length instead of searching. `--top` accepts 1-20. Use a candidate key with `vigenere` to decrypt the complete file.

## Repeating-key XOR analysis

```sh
ctf-crypto xor-repeat-crack --file ciphertext.bin
ctf-crypto xor-repeat-crack --file ciphertext.hex --input-format hex --key-size 3
ctf-crypto xor-repeat-crack --file ciphertext.bin --min-key 2 --max-key 40 --top 5
```

The tool analyzes the first 4,096 decoded bytes. With an unknown key size it compares normalized Hamming distances and tries the eight most promising lengths in the requested range. It guesses each key byte from transposed columns using English scores, then ranks the candidate plaintexts with a small key-length penalty. Repeated copies of the same key are reduced to their shortest period.

The output contains `key_hex`, a readable key representation, heuristic scores, and a 240-byte plaintext preview. A lower Hamming distance is a clue, not proof. Short or binary/non-English plaintext often gives wrong guesses. Supply a known `--key-size` when possible. At least four full blocks are needed for a tested key size. Default range: 2-40; maximum supported length: 128.

To apply a candidate key to the complete file, use the existing XOR command:

```sh
ctf-crypto xor --file ciphertext.bin --key 494345 --key-format hex --out plaintext.bin
```

The example key is `ICE`; replace it with the candidate you intend to test. Encoded text files need the corresponding `--input-format` here too. Guessing does not write plaintext files automatically.

## Check a local wordlist against an unsalted hash

```sh
ctf-crypto hash-check --algorithm sha256 --digest ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad --wordlist practice/words.txt
```

If the wordlist contains `abc`, the command prints a match. Generate this practice wordlist using `python examples/create_misc_demo.py` from the source folder; see `ctf-crypto docs misc`.

Algorithms: MD5, SHA-1, SHA-256 (default), SHA-512. You must choose the algorithm; digest length alone cannot identify it. The target is one hexadecimal digest, not a password-hash record.

Each file line is one candidate byte string. Only its LF/CRLF line ending is removed; spaces and non-UTF-8 bytes are preserved. A blank line tests an empty value. No candidates are generated or mutated. It stops at the first match or `--max-words` (default 100,000; maximum 10,000,000). Each wordlist line is limited to 1 MiB. The output reports whether the limit prevented checking more candidates.

This is a bounded dictionary check for simple CTF hashes. It does not support salted hashes, bcrypt, Argon2, GPU acceleration, network logins, or arbitrary password recovery. A no-match result means only that no checked candidate matched. The command returns success when the check completes, even when there is no match.
