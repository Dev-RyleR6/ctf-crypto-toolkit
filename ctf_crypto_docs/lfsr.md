# LFSR generation

An LFSR (Linear Feedback Shift Register) stores bits. At each step this implementation XORs the selected positions, emits one bit, then shifts the register and inserts the feedback bit. This command implements a Fibonacci LFSR, not a Galois LFSR.

```sh
ctf-crypto lfsr --state 1001 --taps 0,3 --bits 8
```

Output: `91`. In binary this is `10010001`.

## Define the state and taps

State accepts a bit string or a JSON list. Taps accept comma-separated integers or a JSON list. Quote lists containing spaces:

```sh
ctf-crypto lfsr --state "[1, 0, 0, 1]" --taps "[0, 3]" --bits 8 --format bits
```

The state is always written left to right. Its width includes leading zero bits. Invalid bits, duplicate taps, empty tap lists, and out-of-range tap indices are rejected. An all-zero state is allowed, but XOR feedback keeps it zero.

## Choose the exact convention

| Option | Default | Meaning |
|---|---|---|
| `--shift left/right` | `left` | Left: discard first, append feedback. Right: discard last, prepend feedback. |
| `--output-bit first/last/feedback` | `first` | Emit the first bit, last bit, or computed feedback from the state BEFORE shifting. |
| `--tap-base 0/1` | `0` | Whether the first position is numbered zero or one. |
| `--tap-origin left/right` | `left` | Which end is used when numbering taps. |
| `--bits N` | `128` | Number of generated output bits after skipping; must be positive. |
| `--skip N` | `0` | Discard N output steps before collecting bits. |
| `--byte-order msb/lsb` | `msb` | Bit order WITHIN each group of eight output bits. Does not reverse byte order. |
| `--format hex/base64/bits` | `hex` | Display packed bytes as hex/Base64, or display the unpacked bit string. |

For a four-bit state, `--tap-base 1 --taps 1,4` selects the same positions as the default base with `--taps 0,3`.

Default step, using zero-based indices:

```python
output_bit = state[0]
feedback = 0
for tap in taps:
    feedback ^= state[tap]
state = state[1:] + [feedback]
```

`--output-bit first` always means the list's first element, even when shifting right; it does not automatically mean the outgoing bit. Select `--output-bit last` for the outgoing bit of a right shift.

## Packing and saving

```sh
ctf-crypto lfsr --state 1001 --taps 0,3 --bits 8 --byte-order lsb
ctf-crypto lfsr --state 1001 --taps 0,3 --bits 5 --format bits
ctf-crypto lfsr --state 1001 --taps 0,3 --bits 128 --out key.hex
```

The first prints `89`: reversing the bits within `10010001` gives `10001001`. The second prints `10010`. Hex/Base64 output requires the bit count to be a multiple of eight. `--format bits` accepts other positive lengths and does not apply byte packing.

`--out` saves the selected formatted text as ASCII, without a trailing newline. It is NOT a raw key file. It refuses to overwrite an existing file. Copy the hex into `aes --key`, or use `lfsr-aes` to derive and apply the key in one command.

This generator reproduces a chosen convention; it does not infer taps, recover unknown states, apply a hash-based key derivation function, or automatically search conventions.
