"""Shared examples and option explanations for CLI help and the offline guide."""

import argparse
import base64
import textwrap


# (arguments, expected result / prerequisite). File examples are templates.
EXAMPLES = {
    "encode": [('encode --to base64 --text "hi"', 'Runs immediately: aGk=')],
    "decode": [('decode --from hex --text "6869"', 'Runs immediately: UTF-8: hi')],
    "caesar": [('caesar --text "khoor" --shift -3', 'Runs immediately: hello'), ('caesar --text "khoor"', 'Runs immediately: lists all 26 shifts')],
    "xor": [('xor --text "424f464645" --input-format hex --key 2a --key-format hex', 'Runs immediately: UTF-8: hello')],
    "xor-crack": [('xor-crack --text "424f464645" --input-format hex --top 5', 'Runs immediately: ranked guesses; short input is unreliable')],
    "frequency": [('frequency --text "banana"', 'Runs immediately: a=3, n=2, b=1')],
    "hash": [('hash --text "abc" --algorithm md5', 'Runs immediately: 900150983cd24fb0d6963f7d28e17f72')],
    "inverse": [('inverse 17 3120', 'Runs immediately: 2753')],
    "rsa": [('rsa --n 3233 --d 2753 --c 2790', 'Runs immediately: message 65, UTF-8: A')],
    "rsa-key": [('rsa-key --key-file private.pem --file encrypted.bin --padding oaep --oaep-hash sha256', 'Template: matching RSA key + ciphertext; requires cryptography'), ('rsa-key --key-file private.hex --key-encoding hex --file encrypted.hex --input-format hex --padding pkcs1v15', 'Template: hex-wrapped key and hex ciphertext; padding must match')],
    "aes": [('aes --mode ecb --key 2b7e151628aed2a6abf7158809cf4f3c --text 3ad77bb40d7a3660a89ecaf32466ef97 --input-format hex --padding none', 'Requires cryptography: hex 6bc1bee22e409f96e93d7e117393172a'), ('aes --mode cbc --key 2b7e151628aed2a6abf7158809cf4f3c --iv 000102030405060708090a0b0c0d0e0f --text 7649abac8119b246cee98e9b12e9197d --input-format hex --padding none', 'Requires cryptography: same plaintext as the ECB example')],
    "lfsr": [('lfsr --state 1001 --taps 0,3 --bits 8', 'Runs immediately: 91')],
    "lfsr-aes": [('lfsr-aes --file examples/lfsr_aes_demo.txt --mode ecb', 'Source-folder practice file + cryptography: flag{lfsr_aes_demo}')],
    "vigenere": [('vigenere --text LXFOPVEFRNHR --key LEMON', 'Runs immediately: ATTACKATDAWN'), ('vigenere --text ATTACKATDAWN --key LEMON --encrypt', 'Runs immediately: LXFOPVEFRNHR')],
    "vigenere-crack": [('vigenere-crack --file ciphertext.txt --key-size 5 --top 3', 'Template: a long Vigenere ciphertext; outputs English-ranked guesses')],
    "xor-repeat-crack": [('xor-repeat-crack --file ciphertext.bin --min-key 2 --max-key 40 --top 3', 'Template: repeating-XOR ciphertext; outputs guessed keys and previews')],
    "hash-check": [('hash-check --algorithm md5 --digest 900150983cd24fb0d6963f7d28e17f72 --wordlist words.txt --max-words 1000', 'Template: words.txt with one candidate per line; abc will match')],
    "file-info": [('file-info --file mystery.bin --scan --limit 20', 'Template: your file; prints size, hash, entropy, and signature offsets')],
    "strings": [('strings --file mystery.bin --encoding all --min-length 4 --limit 50', 'Template: your file; prints candidate strings and byte offsets')],
    "hexdump": [('hexdump --file mystery.bin --offset 0 --length 32', 'Template: file of at least 32 bytes; shows hex and printable bytes')],
    "carve": [('carve --file mystery.bin --offset 0x20 --length 128 --out slice.bin', 'Template: file of at least 160 bytes; writes exactly 128 bytes to a new file')],
    "zip-info": [('zip-info --file archive.zip --limit 20', 'Template: your ZIP; lists names, sizes, encryption flags, and comments')],
    "zip-read": [('zip-read --file archive.zip --member note.txt --out extracted-note.txt', 'Template: ZIP containing note.txt; creates the chosen output file')],
    "image-info": [('image-info --file picture.png', 'Template: your image + Pillow; prints image metadata and EXIF')],
    "lsb": [('lsb --file picture.png --bytes 16 --channels rgb --bit-plane 0 --bit-order msb', 'Template: RGB/RGBA PNG/BMP + Pillow; extracts 16 bytes, not a guaranteed flag')],
    "docs": [('docs --open', 'Opens the complete offline visual guide'), ('docs commands --open', 'Opens the expandable command and option catalog'), ('docs rsa', 'Prints the RSA recipe in the terminal')],
    "help": [('help rsa-key', 'Shows command usage, options, and examples'), ('help rsa-key padding', 'Explains every RSA padding choice with option examples'), ('help decode from', 'Shows an input example for each encoding')],
}

# Every argument has a sample, including flags and positional arguments.
SAMPLES = {
    "help": "--help", "text": '--text "hello"', "file": "--file input.bin", "out": "--out result.bin",
    "key": '--key "ICE"', "encrypt": "--encrypt", "min_key": "--min-key 2", "max_key": "--max-key 20",
    "key_size": "--key-size 5", "top": "--top 3", "digest": "--digest 900150983cd24fb0d6963f7d28e17f72 --algorithm md5",
    "wordlist": "--wordlist words.txt", "max_words": "--max-words 1000", "scan": "--scan", "limit": "--limit 20",
    "min_length": "--min-length 6", "offset": "--offset 0x20", "length": "--length 64",
    "member": '--member "folder/note.txt"', "max_bytes": "--max-bytes 1048576", "password": '--password "ctf-demo"',
    "count": "--bytes 16", "channels": "--channels bgr", "bit_plane": "--bit-plane 1", "offset_bits": "--offset-bits 8",
    "key_file": "--key-file private.pem", "ask_password": "--ask-password", "label_hex": "--label-hex 637466 --padding oaep",
    "list_topics": "--list", "open_browser": "--open", "state": "--state 1001", "taps": "--taps 0,3", "bits": "--bits 8",
    "skip": "--skip 16", "iv": "--mode cbc --iv 000102030405060708090a0b0c0d0e0f", "iv_prefix": "--mode cbc --iv-prefix",
    "a": "17", "modulus": "3120", "n": "--n 3233", "d": "--d 2753", "c": "--c 2790",
    "help_command": "rsa-key", "help_option": "padding",
}

DESCRIPTIONS = {
    "help": "Show help and examples; no input files are read.",
    "text": "Input supplied as text. Use either --text or --file, never both.",
    "file": "Path to your input file. Relative paths start in your terminal's current folder.",
    "out": "Save result bytes to a NEW file; existing files are never overwritten.",
    "input_format": "How input bytes are represented; decode this outer encoding before processing.",
    "key_format": "Encoding of --key, independent of the ciphertext's --input-format.",
    "min_key": "Smallest key length to try (1-128); must not exceed --max-key.",
    "max_key": "Largest key length to try (1-128). Short samples cannot support long keys.",
    "key_size": "Known key length (1-128); replaces the search range. Needs at least four samples per key position.",
    "digest": "Target hexadecimal digest. Its length must match --algorithm; this is not a password-hash record.",
    "wordlist": "Local file with one candidate per line. Spaces are preserved; line endings are removed.",
    "algorithm": "Digest algorithm to calculate or compare; hashes are not decrypted.",
    "max_words": "Maximum wordlist entries to check, from 1 to 10000000.",
    "min_length": "Minimum printable characters in each result, from 1 to 4096.",
    "encoding": "String representation to search; UTF-16 searches cover printable ASCII characters only.",
    "offset": "Starting byte offset (zero-based). Accepts decimal or 0x-prefixed hex; must be nonnegative.",
    "length": "Number of bytes to read, from 1 to 67108864 (64 MiB); range must fit inside the file.",
    "member": "Exact ZIP entry name, including any directory. Must match one entry; use zip-info first.",
    "max_bytes": "Maximum decompressed member size in bytes, from 1 to 67108864.",
    "count": "Number of output bytes to extract; must be positive and fit the selected image channels.",
    "channels": "Unique channel letters in traversal order: r, g, b, a. For example rgb, bgr, r, rgba. Alpha requires RGBA.",
    "bit_plane": "Bit to read from each channel: 0 is the least significant, 7 the most significant. Range 0-7.",
    "bit_order": "Position of the first extracted bit within each output byte; does not reverse pixel order.",
    "offset_bits": "Number of selected channel bits to skip before extracting; nonnegative, measured in bits.",
    "key_encoding": "Outer encoding of the entire PEM/DER file. Normal PEM uses raw despite its Base64 body.",
    "key_bits": "Number of LFSR output bits packed directly into the AES key; must match the challenge.",
    "topic": "Documentation topic. HTML contains every topic and opens to your selected one.",
    "a": "Integer whose inverse you need; it must be coprime with the modulus. Decimal or 0x hex.",
    "modulus": "Modulus greater than 1. The result x satisfies (a * x) modulo modulus = 1.",
    "n": "Known RSA modulus greater than 1; accepts decimal or 0x hex.",
    "d": "Known RSA private exponent greater than 0; accepts decimal or 0x hex.",
    "c": "Ciphertext integer with 0 <= c < n; accepts decimal or 0x hex.",
    "help_command": "Command to explain. Omit to list all commands; no challenge input is required.",
    "help_option": "One option name without its dashes, such as padding, input-format, or key-encoding.",
}


def command_parsers(parser):
    return next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction)).choices


def label(action):
    return action.option_strings[-1] if action.option_strings else action.dest


def description(name, action):
    dest = action.dest
    if dest == "key":
        return {"aes": "Known AES key: 16, 24, or 32 decoded bytes. Not a password-derived key.",
                "vigenere": "Known key made only of ASCII letters A-Z; decryption is the default."}.get(name, "Known nonempty XOR key; repeated from input byte zero.")
    if dest == "top":
        return "Number of English-ranked guesses to display (1-{}); scores are not proof.".format(256 if name == "xor-crack" else 20)
    if dest == "limit":
        return "Maximum {} to list, from 1 to {}.".format("signature candidates" if name == "file-info" else "strings" if name == "strings" else "ZIP entries", 1000 if name == "file-info" else 10000)
    if dest == "format":
        return {"docs": "Documentation output format. Auto: terminal text, HTML for .html/--open, otherwise Markdown export.",
                "lfsr": "Representation of generated output; hex/base64 need complete eight-bit bytes.",
                "decode": "Encoding to remove from the input text.", "encode": "Encoding to produce from raw input bytes."}[name]
    if name == "docs" and dest == "out":
        return "Export docs to a NEW UTF-8 file. A .html suffix selects the visual guide; otherwise Markdown. --format overrides."
    if name == "hexdump" and dest == "length":
        return DESCRIPTIONS[dest] + " If omitted: up to 256 remaining bytes."
    if name == "lfsr" and dest == "out":
        return "Save the selected ASCII representation (hex/base64/bits) to a NEW file; not raw packed bytes."
    if name == "encode" and dest == "out":
        return "Save encoded ASCII text to a NEW file."
    if name == "vigenere" and dest == "out":
        return "Save the result as UTF-8 text to a NEW file."
    if name == "lfsr-aes" and dest == "file":
        return "Three-field state/taps/hex-ciphertext file. See ctf-crypto docs lfsr-aes for its exact layout."
    return DESCRIPTIONS.get(dest) or action.help


def encoded(data, fmt):
    if fmt == "hex": return data.hex()
    if fmt == "base64": return base64.b64encode(data).decode("ascii")
    if fmt == "base32": return base64.b32encode(data).decode("ascii")
    if fmt == "binary": return " ".join(format(b, "08b") for b in data)
    if fmt == "url": return "".join("%{:02X}".format(b) for b in data)
    return data.decode("ascii")


def choice_detail(name, action, value):
    """Return a meaning and an option fragment for every parser-declared choice."""
    dest, val, flag = action.dest, str(value), label(action)
    fragment = (flag + " " if action.option_strings else "") + val
    formats = {"hex": "Two hexadecimal digits per byte, e.g. 6869 is hi.", "base64": "Base64 text; padding is required where applicable, e.g. aGk=.",
               "base32": "Base32 text using A-Z and 2-7, e.g. NBUQ====.", "binary": "Groups of eight 0/1 bits per byte, e.g. 01101000 01101001.",
               "url": "Percent-encoded bytes, e.g. %68%69. Literal + is preserved.", "raw": "Use the input bytes without decoding an outer encoding.",
               "text": "Use UTF-8 text bytes directly; no password derivation."}
    if dest == "key_encoding":
        return {"raw": "Normal PEM text or binary DER; no outer decoding.", "hex": "Hex of the entire PEM/DER key, such as a value beginning 2d2d2d.",
                "base64": "Base64 of the entire PEM/DER key, not just the PEM body."}[val], fragment + " --key-file private." + {"raw":"pem","hex":"hex","base64":"b64"}[val]
    if dest == "key_format":
        sample = encoded(b"0123456789abcdef" if name == "aes" else b"ICE", val)
        return formats[val], fragment + ' --key "' + sample + '"'
    if dest == "input_format" or (dest == "format" and name in ("encode", "decode")):
        sample = "hi" if name == "encode" else encoded(b"hi", val)
        note = " The sample shows encoding syntax, not a complete encrypted message." if dest == "input_format" and val != "raw" else ""
        return formats[val] + note, fragment + (' --file ciphertext.bin' if val == "raw" else ' --text "' + sample + '"')
    if dest == "format" and name == "lfsr":
        return {"hex":"Packed bytes as hex; the eight-bit demo produces 91.", "base64":"Packed bytes as Base64; the eight-bit demo produces kQ==.", "bits":"One character per output bit; demo produces 10010001."}[val], fragment + " --bits 8"
    if dest == "format" and name == "docs":
        return {"text":"Readable plain text in the terminal.", "markdown":"Markdown source with headings, tables, and code fences.", "html":"Complete offline visual guide; export it and open in a browser."}[val], fragment + (" --out guide.html" if val == "html" else "")
    if dest in ("algorithm", "oaep_hash", "mgf_hash"):
        sizes = {"md5":128,"sha1":160,"sha256":256,"sha384":384,"sha512":512}
        meaning = "{}-bit digest.".format(sizes[val])
        if dest != "algorithm":
            return meaning + " Must match the RSA encryption code; used only with OAEP.", fragment + " --padding oaep"
        if name == "hash-check":
            import hashlib
            return meaning + " Select the algorithm used to create the supplied hash.", fragment + " --digest " + hashlib.new(val, b"abc").hexdigest()
        return meaning, fragment + ' --text "abc"'
    if dest == "topic":
        from crypto_docs import TOPICS
        return TOPICS.get(val, "Every documentation topic combined."), "ctf-crypto docs " + val
    if dest == "help_command":
        return "Show help and examples for " + val + ".", "ctf-crypto help " + val
    meanings = {
        "mode": {"ecb":"Independent AES blocks; no IV allowed.", "cbc":"Chained AES blocks; requires --iv or --iv-prefix."},
        "padding": {"oaep":"RSA OAEP; digest defaults to SHA-256, MGF1 to the same digest, label to empty.", "pkcs1v15":"RSA PKCS#1 v1.5 encryption padding; use only when specified by the challenge.",
                    "raw":"Unpadded RSA; preserves the full modulus-sized block, including leading zeros.", "pkcs7":"Validate and remove AES PKCS#7 padding; incorrect padding causes an error.", "none":"Keep every decrypted AES byte; ciphertext must be whole blocks."},
        "shift": {"left":"Drop the leftmost state bit and append the feedback bit on the right.", "right":"Drop the rightmost state bit and insert feedback on the left."},
        "output_bit": {"first":"Emit the leftmost state bit before shifting.", "last":"Emit the rightmost state bit before shifting.", "feedback":"Emit the XOR of tapped state bits."},
        "tap_base": {"0":"Count taps starting at zero: state 1001 uses indices 0 through 3.", "1":"Count taps starting at one: state 1001 uses indices 1 through 4."},
        "tap_origin": {"left":"Count tap positions from the left end of the written state.", "right":"Count tap positions from the right end of the written state."},
        "byte_order": {"msb":"First generated bit becomes bit 7 (most significant) of its byte.", "lsb":"First generated bit becomes bit 0 (least significant) of its byte."},
        "bit_order": {"msb":"First extracted bit becomes bit 7 of its output byte.", "lsb":"First extracted bit becomes bit 0 of its output byte."},
        "key_bits": {"128":"Generate 16 key bytes for AES-128.", "192":"Generate 24 key bytes for AES-192.", "256":"Generate 32 key bytes for AES-256."},
        "encoding": {"ascii":"Printable ASCII bytes, e.g. 48 69 for Hi.", "utf16le":"Printable ASCII stored as UTF-16 little endian, e.g. 48 00 69 00.", "utf16be":"Printable ASCII stored as UTF-16 big endian, e.g. 00 48 00 69.", "all":"Search all three encodings and merge results by byte offset."},
    }
    if dest == "mode" and val == "cbc": fragment += " --iv 000102030405060708090a0b0c0d0e0f"
    if dest == "tap_base": fragment += " --taps " + ("0,3" if val == "0" else "1,4")
    return meanings[dest][val], fragment


def sample(name, action):
    if action.choices:
        value = action.default if action.default in action.choices else next(iter(action.choices))
        return choice_detail(name, action, value)[1]
    if action.dest == "shift" and name == "caesar": return "--shift -3"
    if action.dest == "key":
        return {"aes":"--key 2b7e151628aed2a6abf7158809cf4f3c", "vigenere":"--key LEMON"}.get(name, SAMPLES["key"])
    if action.dest == "out" and name == "docs": return "--out guide.html"
    if action.dest == "file":
        filename = {"lsb":"picture.png", "image-info":"picture.png", "zip-read":"archive.zip", "zip-info":"archive.zip",
                    "lfsr-aes":"output.txt", "decode":"encoded.txt", "vigenere":"ciphertext.txt", "vigenere-crack":"ciphertext.txt"}.get(name, "input.bin")
        return "--file " + filename
    return SAMPLES[action.dest]


def requirement(parser, action):
    if action.required: return "Required."
    for group in parser._mutually_exclusive_groups:
        if action in group._group_actions:
            names = " or ".join(label(a) for a in group._group_actions)
            return ("Choose exactly one: " if group.required else "Use at most one: ") + names + "."
    if action.default not in (None, argparse.SUPPRESS):
        return "Default: {}.".format("off" if action.default is False else action.default)
    return "Optional."


def examples_text(name):
    return "\n\n".join("  " + note + "\n    ctf-crypto " + args for args, note in EXAMPLES[name])


def configure(parser):
    commands = command_parsers(parser)
    subaction = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    summaries = {a.dest:a.help for a in subaction._choices_actions}
    for name, child in commands.items():
        child.description = summaries[name]
        child.formatter_class = argparse.RawDescriptionHelpFormatter
        for action in child._actions:
            detail = description(name, action)
            if not detail:
                raise ValueError("Missing help for {} {}".format(name, action.dest))
            # Keep the structured text separate from argparse's percent interpolation.
            action.explanation = detail
            action.example = sample(name, action)
            action.help = (detail + " " + requirement(child, action) + " Example: " + action.example).replace("%", "%%")
        focus = next((a for a in child._actions if a.choices), child._actions[-1])
        child.epilog = ("Examples:\n" + examples_text(name) + "\n\n"
                        "Choice-by-choice help: ctf-crypto help " + name + " OPTION\n"
                        "Example: ctf-crypto help " + name + " " + label(focus).lstrip("-") + "\n"
                        "Visual catalog: ctf-crypto docs commands --open\n"
                        "File examples are templates; provide your own files and matching settings.\n"
                        "From source, replace ctf-crypto with python crypto_toolkit.py.")


def option_text(name, parser, action):
    lines = ["{} / {}".format(name, label(action)), "=" * 50,
             textwrap.fill(action.explanation, 88), requirement(parser, action), "", "Option example (fragment):", "  " + action.example]
    if action.choices:
        lines += ["", "Choices (match these to your input or encryption settings):"]
        for value in action.choices:
            meaning, example = choice_detail(name, action, value)
            lines.extend(["", "  " + str(value), textwrap.fill(meaning, 88, initial_indent="    ", subsequent_indent="    "), "    Example: " + example])
    lines.extend(["", "Complete command examples:", examples_text(name), "", "Fragments show option syntax; combine them with the command's required arguments."])
    return "\n".join(lines)


def show(parser, name=None, option=None):
    if name is None:
        parser.print_help()
        return
    child = command_parsers(parser)[name]
    if option is None:
        child.print_help()
        return
    normalized = option.lstrip("-").replace("-", "_")
    for action in child._actions:
        if normalized == action.dest or option.lstrip("-") in [s.lstrip("-") for s in action.option_strings]:
            print(option_text(name, child, action))
            return
    raise ValueError("Unknown option '{}' for {}. Run: ctf-crypto help {}".format(option, name, name))


def command_markdown(name, parser):
    result = ["## " + name, "", parser.description, "", "### Examples", ""]
    for args, note in EXAMPLES[name]:
        result += [note, "", "```sh", "ctf-crypto " + args, "```", ""]
    result += ["### Options", "", "Option examples below are fragments. Combine them with the required arguments above; do not paste all alternatives together.", ""]
    for action in parser._actions:
        result += ["#### " + label(action), "", action.explanation + " " + requirement(parser, action), "", "Example: `" + action.example + "`", ""]
        if action.choices:
            result += ["| Choice | Meaning | Option example |", "|---|---|---|"]
            for value in action.choices:
                meaning, example = choice_detail(name, action, value)
                result.append("| `{}` | {} | `{}` |".format(value, meaning, example))
            result.append("")
    return "\n".join(result)


def catalog(parser):
    return "# Commands, options & examples\n\nOpen one command at a time in the visual guide. In the terminal, use `ctf-crypto help COMMAND OPTION` for focused help.\n\n" + "\n\n".join(command_markdown(name, child) for name, child in command_parsers(parser).items())
