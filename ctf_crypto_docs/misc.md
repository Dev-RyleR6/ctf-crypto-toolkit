# Miscellaneous file-analysis workflow

Use `ctf-crypto docs misc` to read this offline. File analysis commands work with local artifacts and never execute their contents. Basic commands use the standard library. `image-info` and `lsb` require optional Pillow:

```sh
python -m pip install ".[all]"
```

Run that from the source folder in the environment running the toolkit. For only image support, use `".[images]"`; for source/portable use, `python -m pip install Pillow` installs the image dependency. Optional dependency installation may need the internet; analysis works offline afterward.

## 1. Triage an unknown file

```sh
ctf-crypto file-info --file mystery.bin --scan
ctf-crypto hexdump --file mystery.bin
ctf-crypto strings --file mystery.bin --encoding all
```

`file-info` reports byte length, SHA-256, Shannon entropy, and recognized signature candidates. `--scan` searches for embedded headers as well as the start of the file. Recognized patterns include PNG, JPEG, GIF, PDF, ZIP records, ELF, MZ, gzip, 7-Zip, RAR, SQLite, RIFF, and TIFF. A signature match is a clue, not validation of a complete embedded file. ZIP entries naturally contain multiple local headers. High entropy can mean compressed, encrypted, or other dense data; it does not identify encryption.

`--limit` caps signature output (default 50, maximum 1,000). Without `--scan`, signatures are checked only at offset zero. File-info, strings, ZIP input, and image input are limited to 64 MiB. The analyzer does not automatically recover file boundaries.

`hexdump` shows up to the first 256 bytes by default. Select an exact range with `--offset` and `--length`; decimal and `0x` hexadecimal numbers are accepted. Explicit ranges beyond the end of the file are rejected. Each requested range is limited to 64 MiB.

```sh
ctf-crypto hexdump --file mystery.bin --offset 0x20 --length 64
```

`strings` finds printable ASCII text, or printable ASCII-range characters encoded as UTF-16 LE/BE. It is not a general Unicode text decoder. Defaults: `--min-length 4`, `--limit 100`, `--encoding ascii`. Use `ascii`, `utf16le`, `utf16be`, or `all`. Offsets are byte offsets. Output is escaped for terminal display and previews at most 4,096 characters per string. Multiple encoding interpretations may overlap.

## 2. Carve an exact byte range

```sh
ctf-crypto carve --file mystery.bin --offset 32 --length 1024 --out recovered.bin
```

Replace the offset and length with values established from your artifact. The command copies exactly that range to a new file; it does not infer where a ZIP, PNG, or other file ends. The source is not modified, and an existing output is never overwritten. You can carve a bounded range from an input larger than 64 MiB.

## 3. Inspect a ZIP archive

```sh
ctf-crypto zip-info --file archive.zip
ctf-crypto zip-read --file archive.zip --member note.txt --out recovered-note.txt
```

`zip-info` shows the archive comment, entry names, declared uncompressed/compressed sizes, encryption flags, and entry comments. It does not decompress the contents. Listing defaults to 100 entries; change `--limit` up to 10,000.

`zip-read` decompresses exactly one member to the explicit `--out` path. It never uses member names as filesystem destinations, so an entry like `../../note.txt` cannot redirect the output. Missing or duplicate member names and directory entries are rejected. The default decompressed size limit is 10 MiB; `--max-bytes` can raise it to at most 64 MiB. Existing outputs are refused.

An optional `--password` supplies a known UTF-8 password for ZIP encryption supported by Python's standard library. Password guessing and AES-encrypted ZIP files are not supported. Do not infer that a damaged archive is encrypted just because reading fails.

## 4. Inspect image metadata

```sh
ctf-crypto image-info --file picture.png
ctf-crypto image-info --file photograph.jpg
```

Shows format, dimensions, color mode, available image metadata, EXIF, and available nested GPS/EXIF tags. Long fields are previewed, not fully dumped. GPS values are reported as stored; they are not automatically converted into map coordinates. Stripped metadata cannot be recovered by this command. The image limit is 16 million pixels.

## 5. Extract a selected image bit-plane

```sh
ctf-crypto lsb --file picture.png --bytes 16
ctf-crypto lsb --file picture.png --channels bgr --bit-plane 0 --bit-order msb --offset-bits 0 --bytes 32 --out hidden.bin
```

This supports RGB/RGBA PNG and BMP images only. It does not silently convert indexed, grayscale, or JPEG images. Pixels are traversed left-to-right, top-to-bottom. Within each pixel, channels are visited in the order given by `--channels` (default `rgb`); channel letters must be unique. `a` requires an actual alpha channel.

- `--bit-plane 0` selects the least significant bit; values 0-7 are accepted.
- `--bit-order msb` packs the first collected bit as the high bit of each output byte. `lsb` packs it as the low bit.
- `--offset-bits` skips bits in that selected channel stream before extraction.
- `--bytes` is required and requests an exact number of output bytes. Exceeding capacity is an error.

The command displays bytes or saves them with `--out`. It does not discover which channels, bit-plane, offset, or length were used. Random-looking output does not confirm hidden content. It is not a replacement for all steganography tools and does not decode audio, DCT/JPEG, palette-index, or proprietary steganography schemes.

## Practice the full workflow

From the source folder, generate a NEW directory of synthetic practice files:

```sh
python examples/create_misc_demo.py --out-dir practice
ctf-crypto file-info --file practice/mystery.bin --scan
ctf-crypto strings --file practice/mystery.bin
ctf-crypto zip-info --file practice/notes.zip
ctf-crypto zip-read --file practice/notes.zip --member note.txt --out practice/recovered-note.txt
ctf-crypto image-info --file practice/picture.png
ctf-crypto lsb --file practice/picture.png --bytes 16
```

Expected clues include `flag{strings_demo}`, `flag{zip_comment}`, `flag{zip_member}`, `flag{metadata_demo}`, and `flag{pixel_bits}`. The generator also writes `practice/offsets.txt` with exact PNG/ZIP offsets and lengths inside `mystery.bin`, so you can practice `carve`. Reuse requires a different output-directory name; the generator refuses an existing directory.

For larger artifacts, full filesystem/memory forensics, PCAP analysis, or reverse engineering, use dedicated tools such as Wireshark, a forensic suite, or a disassembler. These commands cover a useful subset of misc CTF work, not every challenge type.

Implementation references: https://docs.python.org/3/library/zipfile.html and https://pillow.readthedocs.io/en/stable/reference/Image.html
