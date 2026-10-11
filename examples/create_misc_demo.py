"""Create synthetic CTF files in a NEW directory using only the standard library."""

import argparse
import io
from pathlib import Path
import struct
import zipfile
import zlib


def png_chunk(kind, data):
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xffffffff)


def create_demo(destination):
    hidden = b"flag{pixel_bits}"
    width, height = 32, 8
    pixels = bytearray([120, 160, 200] * (width * height))
    for index in range(len(hidden) * 8):
        bit = (hidden[index // 8] >> (7 - index % 8)) & 1
        pixels[index] = (pixels[index] & 254) | bit
    rows = b"".join(b"\0" + bytes(pixels[row * width * 3:(row + 1) * width * 3]) for row in range(height))
    png = (b"\x89PNG\r\n\x1a\n" + png_chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)) +
           png_chunk(b"tEXt", b"Comment\0flag{metadata_demo}") + png_chunk(b"IDAT", zlib.compress(rows)) + png_chunk(b"IEND", b""))
    memory = io.BytesIO()
    with zipfile.ZipFile(memory, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("note.txt", "flag{zip_member}\n")
        archive.comment = b"flag{zip_comment}"
    prefix = b"CTF practice\x00flag{strings_demo}\x00"
    archive_bytes = memory.getvalue()
    directory = Path(destination)
    directory.mkdir(parents=True, exist_ok=False)
    (directory / "picture.png").write_bytes(png)
    (directory / "notes.zip").write_bytes(archive_bytes)
    (directory / "mystery.bin").write_bytes(prefix + png + archive_bytes)
    (directory / "words.txt").write_bytes(b"hello\nabc\npractice\n")
    instructions = "PNG offset: {}\nPNG length: {}\nZIP offset: {}\nZIP length: {}\nLSB byte count: {}\n".format(
        len(prefix), len(png), len(prefix) + len(png), len(archive_bytes), len(hidden))
    (directory / "offsets.txt").write_text(instructions, encoding="utf-8")
    return instructions


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", default="practice")
    args = parser.parse_args()
    try:
        print(create_demo(args.out_dir))
        print("Created practice files in", args.out_dir)
    except OSError as error:
        parser.exit(1, "Error: {}\n".format(error))


if __name__ == "__main__":
    main()
