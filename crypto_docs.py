"""Dependency-free offline documentation, with terminal and browser renderers."""

import html
from importlib import resources
from pathlib import Path
import re
import tempfile
import textwrap
import webbrowser


TOPICS = {
    "quickstart": "Start here",
    "rsa": "RSA private keys",
    "aes": "AES decryption",
    "lfsr-aes": "LFSR + AES",
    "lfsr": "LFSR bits & keys",
    "classical": "Classical ciphers",
    "misc": "Files & hidden data",
    "reference": "Command reference",
}


def markdown(topic):
    names = TOPICS if topic == "all" else (topic,)
    return "\n\n".join(resources.files("ctf_crypto_docs").joinpath(name + ".md").read_text(encoding="utf-8") for name in names)


def inline(text):
    # Escape first; documentation is text, never trusted HTML. Allow only known local topics and HTTPS links.
    def link(match):
        label, target = match.groups()
        slug = target.removesuffix(".md")
        if slug in TOPICS:
            return '<a href="#{}">{}</a>'.format(slug, label)
        if target.startswith("https://"):
            return '<a href="{}" rel="noreferrer">{}</a>'.format(target, label)
        return label
    parts = re.split(r"(`[^`]+`)", text)
    result = []
    for part in parts:
        if part.startswith("`") and part.endswith("`"):
            result.append("<code>" + html.escape(part[1:-1]) + "</code>")
        else:
            part = html.escape(part, quote=True)
            part = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", link, part)
            part = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", part)
            result.append(part)
    return "".join(result)


def blocks(source):
    lines = source.splitlines()
    output, index = [], 0
    while index < len(lines):
        line = lines[index].strip()
        index += 1
        if not line:
            continue
        if line.startswith("```"):
            code = []
            while index < len(lines) and not lines[index].strip().startswith("```"):
                code.append(lines[index]); index += 1
            index += 1
            output.append('<div class="code-block"><div class="code-bar"><span>{}</span><button type="button" class="copy" aria-label="Copy code">Copy</button></div><pre><code>{}</code></pre></div>'.format(
                "OUTPUT" if line[3:] == "text" else "TERMINAL", html.escape("\n".join(code))))
        elif re.match(r"^#{1,6} ", line):
            level = min(len(line.split(" ", 1)[0]) + 1, 6)
            output.append("<h{0}>{1}</h{0}>".format(level, inline(line.split(" ", 1)[1])))
        elif line.startswith("|"):
            rows = [line]
            while index < len(lines) and lines[index].strip().startswith("|"):
                rows.append(lines[index].strip()); index += 1
            table = []
            for number, row in enumerate(rows):
                cells = [cell.strip() for cell in row.strip("|").split("|")]
                if all(re.fullmatch(r":?-{3,}:?", cell) for cell in cells):
                    continue
                tag = "th" if number == 0 else "td"
                table.append("<tr>" + "".join("<{0}>{1}</{0}>".format(tag, inline(cell)) for cell in cells) + "</tr>")
            output.append('<div class="table-wrap"><table>' + "".join(table) + "</table></div>")
        elif line.startswith("- ") or re.match(r"^\d+\. ", line):
            ordered = not line.startswith("- ")
            pattern = r"^\d+\. " if ordered else r"^- "
            items = [re.sub(pattern, "", line)]
            while index < len(lines) and re.match(pattern, lines[index].strip()):
                items.append(re.sub(pattern, "", lines[index].strip())); index += 1
            tag = "ol" if ordered else "ul"
            output.append("<{}>".format(tag) + "".join("<li>" + inline(item) + "</li>" for item in items) + "</{}>".format(tag))
        else:
            paragraph = [line]
            while index < len(lines) and lines[index].strip() and not re.match(r"^(#|\||```|- |\d+\. )", lines[index].strip()):
                paragraph.append(lines[index].strip()); index += 1
            output.append("<p>" + inline(" ".join(paragraph)) + "</p>")
    return "\n".join(output)


def terminal(source, width=88):
    result, in_code = [], False
    for line in source.splitlines():
        if line.startswith("```"):
            in_code = not in_code
            result.append("")
        elif in_code:
            result.append("    " + line)
        elif re.match(r"^#+ ", line):
            title = line.lstrip("# ")
            result.extend([title, ("=" if line.startswith("# ") else "-") * min(len(title), width)])
        elif line.startswith("|"):
            cells = [cell.strip().replace("`", "").replace("**", "") for cell in line.strip("|").split("|")]
            if not all(re.fullmatch(r":?-{3,}:?", cell) for cell in cells):
                result.extend(textwrap.wrap(" / ".join(cells), width, subsequent_indent="    "))
        else:
            line = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r"\1 (\2)", line).replace("**", "").replace("`", "")
            result.extend(textwrap.wrap(line, width, subsequent_indent="  ") or [""])
    return "\n".join(result).strip() + "\n"


def visual_guide(topic="quickstart"):
    package = resources.files("ctf_crypto_docs")
    template = package.joinpath("guide.html").read_text(encoding="utf-8")
    nav = "".join('<a href="#{}">{}</a>'.format(name, title) for name, title in TOPICS.items())
    sections = "".join('<section class="topic" id="{}" tabindex="-1">{}</section>'.format(name, blocks(markdown(name))) for name in TOPICS)
    document = template.replace("{{NAV}}", nav).replace("{{CONTENT}}", sections).replace("{{TOPIC}}", topic if topic in TOPICS else "quickstart")
    # Numeric HTML entities also survive Windows terminals using legacy encodings.
    return document.encode("ascii", "xmlcharrefreplace").decode("ascii")


def run(args):
    if args.list_topics:
        for name, title in TOPICS.items():
            print("{:<12} {}".format(name, title))
        print("all          Every topic\n\nVisual guide: ctf-crypto docs --open")
        return
    if args.open_browser and args.format not in (None, "html"):
        raise ValueError("--open requires HTML; omit --format or use --format html.")
    fmt = args.format or ("html" if args.open_browser or (args.out and Path(args.out).suffix.lower() == ".html") else "markdown" if args.out else "text")
    content = visual_guide(args.topic) if fmt == "html" else markdown(args.topic)
    if fmt == "text":
        content = terminal(content)
        if args.topic == "quickstart" and not args.out:
            content = (
                "CTF CRYPTO TOOLKIT - START HERE\n"
                "===============================\n\n"
                "Open the visual guide:  ctf-crypto docs --open\n"
                "Try a first command:    ctf-crypto decode --from hex --text 6869\n"
                "Expected result:        UTF-8: hi\n\n"
                "WHAT YOU HAVE                 READ THIS RECIPE\n"
                "RSA private key or numbers    ctf-crypto docs rsa\n"
                "AES key + ciphertext          ctf-crypto docs aes\n"
                "LFSR state + taps             ctf-crypto docs lfsr-aes\n"
                "Encoded text / XOR / ciphers  ctf-crypto docs classical\n"
                "Mystery file / ZIP / image    ctf-crypto docs misc\n\n"
                "All command examples:   ctf-crypto docs reference\n"
                "Save the visual guide:  ctf-crypto docs --out guide.html\n"
                "Help for a command:     ctf-crypto rsa-key --help\n\n"
                "From source, replace ctf-crypto with python crypto_toolkit.py.\n"
                "For install steps, open the visual guide or use docs --format markdown.\n"
            )
    target = None
    if args.out:
        target = Path(args.out).resolve()
        with target.open("x", encoding="utf-8") as handle:
            handle.write(content)
        print("Saved documentation to " + str(target))
    elif args.open_browser:
        # A fresh local file works from installed wheels, source trees, and zipapps.
        with tempfile.NamedTemporaryFile(mode="w", suffix=".html", prefix="ctf-crypto-guide-", encoding="utf-8", delete=False) as handle:
            handle.write(content)
            target = Path(handle.name)
        print("Offline guide: " + str(target))
    else:
        print(content)
    if args.open_browser:
        if not webbrowser.open(target.as_uri() + "#" + (args.topic if args.topic in TOPICS else "quickstart")):
            print("Browser could not open automatically. Open the HTML file above manually.")
