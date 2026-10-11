"""Read-only file triage and explicit bounded extraction for CTF artifacts."""

from collections import Counter
from contextlib import contextmanager
import hashlib
import math
from pathlib import Path
import re
import warnings
import zipfile
import zlib


COMMANDS = {"file-info", "strings", "hexdump", "carve", "zip-info", "zip-read", "image-info", "lsb"}
MAX_FILE_BYTES = 64 * 1024 * 1024
SIGNATURES = ((b"\x89PNG\r\n\x1a\n", "PNG"), (b"\xff\xd8\xff", "JPEG"),
              (b"GIF87a", "GIF87a"), (b"GIF89a", "GIF89a"), (b"%PDF-", "PDF"),
              (b"PK\x03\x04", "ZIP local header"), (b"PK\x05\x06", "ZIP end record"),
              (b"\x7fELF", "ELF"), (b"MZ", "DOS/PE candidate"), (b"\x1f\x8b\x08", "gzip"),
              (b"7z\xbc\xaf\x27\x1c", "7-Zip"), (b"Rar!\x1a\x07", "RAR"),
              (b"SQLite format 3\0", "SQLite 3"), (b"RIFF", "RIFF container"),
              (b"II\x2a\0", "TIFF little-endian"), (b"MM\0\x2a", "TIFF big-endian"))


def bounded_file(path):
    path = Path(path)
    if not path.is_file():
        raise ValueError("Input must be a regular file.")
    if path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError("This triage command accepts files up to 64 MiB; carve a smaller range first.")
    with path.open("rb") as handle:
        data = handle.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise ValueError("File exceeds the 64 MiB limit.")
    return data


def entropy(data):
    return -sum((count / len(data)) * math.log2(count / len(data)) for count in Counter(data).values()) if data else 0.0


def signatures(data, limit=50):
    if not 1 <= limit <= 1000:
        raise ValueError("Signature limit must be between 1 and 1000.")
    # Bound matches per signature, then retain the earliest offsets overall.
    matches = []
    for signature, label in SIGNATURES:
        offset = 0
        for _ in range(limit):
            found = data.find(signature, offset)
            if found < 0:
                break
            matches.append((found, label))
            offset = found + 1
    return sorted(matches)[:limit]


def extract_strings(data, minimum=4, encoding="ascii", limit=100):
    if not 1 <= minimum <= 4096 or not 1 <= limit <= 10000:
        raise ValueError("Use min-length 1-4096 and limit 1-10000.")
    patterns = {"ascii": rb"[\x20-\x7e]", "utf16le": rb"(?:[\x20-\x7e]\x00)",
                "utf16be": rb"(?:\x00[\x20-\x7e])"}
    if encoding not in tuple(patterns) + ("all",):
        raise ValueError("Unsupported string encoding.")
    matches = []
    for name in (patterns if encoding == "all" else (encoding,)):
        codec = {"ascii": "ascii", "utf16le": "utf-16-le", "utf16be": "utf-16-be"}[name]
        for index, match in enumerate(re.finditer(patterns[name] + ("{%d,}" % minimum).encode(), data)):
            if index >= limit:
                break
            matches.append((match.start(), name, match.group().decode(codec)))
    return sorted(matches)[:limit]


def read_range(path, offset, length):
    if offset < 0 or length < 1 or length > MAX_FILE_BYTES:
        raise ValueError("Offset must be nonnegative and length must be 1 byte to 64 MiB.")
    path = Path(path)
    if not path.is_file() or offset + length > path.stat().st_size:
        raise ValueError("Requested range is outside a regular input file.")
    with path.open("rb") as handle:
        handle.seek(offset)
        data = handle.read(length)
    if len(data) != length:
        raise ValueError("File changed or ended before the requested range.")
    return data


def zip_summary(path, limit=100):
    if not 1 <= limit <= 10000:
        raise ValueError("ZIP listing limit must be 1-10000.")
    # Check size without decompressing archive contents.
    check_file_size(path)
    try:
        with zipfile.ZipFile(path) as archive:
            items = archive.infolist()
            entries = [(info.filename, info.file_size, info.compress_size, bool(info.flag_bits & 1), info.comment)
                       for info in items[:limit]]
            return archive.comment, len(items), entries
    except zipfile.BadZipFile as error:
        raise ValueError("Not a readable ZIP archive: " + str(error)) from error


def check_file_size(path):
    path = Path(path)
    if not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError("Input must be a regular file no larger than 64 MiB.")


def zip_read(path, member, max_bytes=10 * 1024 * 1024, password=None):
    check_file_size(path)
    if not 1 <= max_bytes <= MAX_FILE_BYTES:
        raise ValueError("ZIP output limit must be between 1 byte and 64 MiB.")
    try:
        with zipfile.ZipFile(path) as archive:
            matches = [item for item in archive.infolist() if item.filename == member]
            if len(matches) != 1:
                raise ValueError("Member must match exactly one ZIP entry; missing or duplicate name.")
            info = matches[0]
            if info.is_dir() or info.file_size > max_bytes:
                raise ValueError("Member is a directory or exceeds --max-bytes.")
            with archive.open(info, pwd=password.encode("utf-8") if password is not None else None) as handle:
                data = handle.read(max_bytes + 1)
            if len(data) > max_bytes:
                raise ValueError("Decompressed member exceeds --max-bytes.")
            return data
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError, EOFError, zlib.error) as error:
        raise ValueError("ZIP read failed: " + str(error)) from error


def load_pillow():
    try:
        from PIL import Image, ExifTags
    except ImportError as error:
        raise ValueError("Image commands require Pillow. Install: python -m pip install Pillow "
                         '(or install this source with ".[images]" / ".[all]").') from error
    return Image, ExifTags


@contextmanager
def open_image(path):
    check_file_size(path)
    Image, _ = load_pillow()
    with warnings.catch_warnings():
        warnings.simplefilter("error", Image.DecompressionBombWarning)
        try:
            with Image.open(path) as image:
                if image.width * image.height > 16000000:
                    raise ValueError("Image exceeds the 16-million-pixel limit.")
                yield image
        except (Image.DecompressionBombWarning, Image.DecompressionBombError) as error:
            raise ValueError("Image exceeds the decoder's pixel limit.") from error


def image_metadata(path):
    _, ExifTags = load_pillow()
    with open_image(path) as image:
        result = {"format": image.format, "size": image.size, "mode": image.mode}
        for name, value in image.info.items():
            result["info." + str(name)] = value
        exif = image.getexif()
        for tag, value in exif.items():
            result["EXIF." + ExifTags.TAGS.get(tag, str(tag))] = value
        for directory, prefix, names in ((34853, "GPS.", ExifTags.GPSTAGS), (34665, "EXIF.", ExifTags.TAGS)):
            if directory in exif:
                for tag, value in exif.get_ifd(directory).items():
                    result[prefix + names.get(tag, str(tag))] = value
        return result


def extract_lsb(path, count, channels="rgb", plane=0, order="msb", offset=0):
    if count < 1 or not 0 <= plane <= 7 or offset < 0 or order not in ("msb", "lsb"):
        raise ValueError("Use a positive byte count, bit-plane 0-7, and nonnegative bit offset.")
    if not channels or any(c not in "rgba" for c in channels) or len(set(channels)) != len(channels):
        raise ValueError("Channels must be unique letters from rgba, in the desired traversal order.")
    with open_image(path) as image:
        if image.format not in ("PNG", "BMP") or image.mode not in ("RGB", "RGBA"):
            raise ValueError("LSB extraction supports RGB/RGBA PNG or BMP; no implicit color conversion is performed.")
        if "a" in channels and image.mode != "RGBA":
            raise ValueError("The image has no alpha channel.")
        capacity = image.width * image.height * len(channels)
        if offset + count * 8 > capacity:
            raise ValueError("Requested bit range exceeds the selected channels' capacity.")
        indices = ["rgba".index(channel) for channel in channels]
        pixels = image.load()
        output = bytearray()
        byte = 0
        for position in range(offset, offset + count * 8):
            pixel, channel = divmod(position, len(indices))
            y, x = divmod(pixel, image.width)
            bit = (pixels[x, y][indices[channel]] >> plane) & 1
            bit_index = (position - offset) % 8
            byte |= bit << (7 - bit_index if order == "msb" else bit_index)
            if bit_index == 7:
                output.append(byte)
                byte = 0
        return bytes(output)


def offset_number(value):
    try:
        return int(value, 16) if value.lower().startswith("0x") else int(value)
    except ValueError:
        import argparse
        raise argparse.ArgumentTypeError("Expected decimal or 0x-prefixed hexadecimal integer.")


def add_commands(commands):
    for name, description in (
        ("file-info", "Show file size, hash, entropy, and signature candidates"),
        ("strings", "Find printable ASCII or ASCII-range UTF-16 strings with offsets"),
        ("hexdump", "Show a bounded byte range as hex and ASCII"),
        ("carve", "Copy an exact byte range to a new file"),
        ("zip-info", "List ZIP entries and comments without extracting"),
        ("zip-read", "Read one ZIP member to an explicitly named new file"),
        ("image-info", "Show image metadata and EXIF (optional Pillow)"),
        ("lsb", "Extract a selected bit-plane from RGB/RGBA PNG/BMP (optional Pillow)"),
    ):
        p = commands.add_parser(name, help=description)
        p.add_argument("--file", required=True)
        if name == "file-info":
            p.add_argument("--scan", action="store_true", help="Scan for embedded signature candidates")
            p.add_argument("--limit", type=int, default=50)
        elif name == "strings":
            p.add_argument("--min-length", type=int, default=4)
            p.add_argument("--encoding", choices=("ascii", "utf16le", "utf16be", "all"), default="ascii")
            p.add_argument("--limit", type=int, default=100)
        elif name in ("hexdump", "carve"):
            p.add_argument("--offset", type=offset_number, default=0)
            p.add_argument("--length", type=offset_number, required=name == "carve", default=None)
            if name == "carve":
                p.add_argument("--out", required=True)
        elif name == "zip-info":
            p.add_argument("--limit", type=int, default=100)
        elif name == "zip-read":
            p.add_argument("--member", required=True)
            p.add_argument("--out", required=True)
            p.add_argument("--max-bytes", type=offset_number, default=10 * 1024 * 1024)
            p.add_argument("--password", help="Known UTF-8 password for legacy ZIP encryption")
        elif name == "lsb":
            p.add_argument("--bytes", type=int, required=True, dest="count")
            p.add_argument("--channels", default="rgb", help="Ordered, unique channels: r, rgb, bgr, rgba, etc.")
            p.add_argument("--bit-plane", type=int, default=0)
            p.add_argument("--bit-order", choices=("msb", "lsb"), default="msb")
            p.add_argument("--offset-bits", type=int, default=0)
            p.add_argument("--out")


def run(args, show_bytes):
    if args.command == "file-info":
        data = bounded_file(args.file)
        print("Bytes:", len(data))
        print("SHA256:", hashlib.sha256(data).hexdigest())
        print("Entropy: {:.4f} bits/byte (not proof of encryption)".format(entropy(data)))
        matches = signatures(data, args.limit) if args.scan else [(0, name) for sig, name in SIGNATURES if data.startswith(sig)]
        for offset, name in matches:
            print("0x{:08x}: {} signature candidate".format(offset, name))
        if not matches:
            print("No recognized signatures.")
        if args.scan and len(matches) == args.limit:
            print("Signature listing limit reached; more matches may exist.")
    elif args.command == "strings":
        matches = extract_strings(bounded_file(args.file), args.min_length, args.encoding, args.limit)
        for offset, encoding, value in matches:
            print("0x{:08x} {} {}".format(offset, encoding, repr(value[:4096])))
        if len(matches) == args.limit:
            print("String listing limit reached; more matches may exist.")
    elif args.command in ("hexdump", "carve"):
        length = args.length
        if length is None:
            length = min(256, max(0, Path(args.file).stat().st_size - args.offset))
            if length == 0 and args.offset == 0 and Path(args.file).is_file() and Path(args.file).stat().st_size == 0:
                print("Empty file.")
                return
        data = read_range(args.file, args.offset, length)
        if args.command == "carve":
            show_bytes(data, args.out)
        else:
            for index in range(0, len(data), 16):
                chunk = data[index:index + 16]
                print("{:08x}  {:47s}  |{}|".format(args.offset + index, " ".join("{:02x}".format(b) for b in chunk),
                                                   "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)))
    elif args.command == "zip-info":
        comment, count, entries = zip_summary(args.file, args.limit)
        print("Entries:", count)
        print("Archive comment:", repr(comment))
        for name, size, compressed, encrypted, comment in entries:
            print("{} bytes={} compressed={} encrypted={} comment={}".format(repr(name), size, compressed, encrypted, repr(comment)))
        if count > len(entries):
            print("Listing limited to {} entries.".format(len(entries)))
    elif args.command == "zip-read":
        show_bytes(zip_read(args.file, args.member, args.max_bytes, args.password), args.out)
    elif args.command == "image-info":
        for name, value in image_metadata(args.file).items():
            preview = repr(value[:128]) + " ..." if isinstance(value, bytes) and len(value) > 128 else repr(value)
            print("{}: {}".format(repr(name), preview[:512] + (" ..." if len(preview) > 512 else "")))
    elif args.command == "lsb":
        show_bytes(extract_lsb(args.file, args.count, args.channels, args.bit_plane, args.bit_order, args.offset_bits), args.out)
