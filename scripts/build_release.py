"""Build allowlisted source/portable ZIP downloads without external packages."""

import argparse
import ast
import hashlib
from pathlib import Path
import re
import zipfile


ROOT = Path(__file__).resolve().parents[1]
SOURCE_FILES = (
    "crypto_toolkit.py", "crypto_advanced.py", "crypto_extra.py", "ctf_misc.py", "README.md", "CRYPTO_GUIDE.md", "LICENSE",
    "pyproject.toml", "MANIFEST.in", ".gitignore",
    "scripts/build_release.py", "tests/test_crypto_toolkit.py",
    "tests/test_distribution.py", "tests/test_advanced.py", "tests/test_extra_misc.py",
    "ctf_crypto_docs/__init__.py", "ctf_crypto_docs/quickstart.md", "ctf_crypto_docs/reference.md",
    "ctf_crypto_docs/lfsr.md", "ctf_crypto_docs/aes.md", "ctf_crypto_docs/lfsr-aes.md",
    "ctf_crypto_docs/classical.md", "ctf_crypto_docs/misc.md",
    "examples/lfsr_aes_demo.txt", "examples/create_misc_demo.py",
)
PORTABLE_FILES = ("crypto_toolkit.py", "crypto_advanced.py", "crypto_extra.py", "ctf_misc.py", "README.md", "CRYPTO_GUIDE.md", "LICENSE",
                  "ctf_crypto_docs/__init__.py", "ctf_crypto_docs/quickstart.md", "ctf_crypto_docs/reference.md",
                  "ctf_crypto_docs/lfsr.md", "ctf_crypto_docs/aes.md", "ctf_crypto_docs/lfsr-aes.md",
                  "ctf_crypto_docs/classical.md", "ctf_crypto_docs/misc.md")


def version():
    tree = ast.parse((ROOT / "crypto_toolkit.py").read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets
        ):
            result = ast.literal_eval(node.value)
            if not isinstance(result, str) or not re.fullmatch(r"\d+\.\d+\.\d+", result):
                raise ValueError("Use a major.minor.patch version, for example 0.1.0.")
            return result
    raise ValueError("Missing __version__ in crypto_toolkit.py")


def write_member(archive, name, data):
    # Fixed metadata produces the same ZIP bytes for unchanged source files.
    entry = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    entry.create_system = 3
    entry.external_attr = 0o100644 << 16
    entry.compress_type = zipfile.ZIP_DEFLATED
    archive.writestr(entry, data)


def build(output):
    # Read all allowlisted sources before creating outputs.
    sources = {name: (ROOT / name).read_bytes() for name in SOURCE_FILES}
    release_version = version()
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    prefix = "ctf-crypto-toolkit-" + release_version
    source_zip = output / (prefix + "-source.zip")
    portable = output / ("ctf-crypto-" + release_version + ".pyz")
    with zipfile.ZipFile(source_zip, "w") as archive:
        for name, data in sources.items():
            write_member(archive, prefix + "/" + name, data)
    with zipfile.ZipFile(portable, "w") as archive:
        write_member(archive, "__main__.py",
                     b"import sys\nfrom crypto_toolkit import main\nsys.exit(main())\n")
        for name in PORTABLE_FILES:
            write_member(archive, name, sources[name])
    artifacts = [source_zip, portable]
    wheel = output / ("ctf_crypto_toolkit-" + release_version + "-py3-none-any.whl")
    if wheel.is_file():
        artifacts.append(wheel)
    checksums = output / "SHA256SUMS.txt"
    checksums.write_text("".join(
        hashlib.sha256(path.read_bytes()).hexdigest() + "  " + path.name + "\n"
        for path in artifacts
    ), encoding="utf-8")
    return artifacts + [checksums]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, default=ROOT / "dist")
    args = parser.parse_args()
    for path in build(args.out_dir):
        print(path)


if __name__ == "__main__":
    main()
