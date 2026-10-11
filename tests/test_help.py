"""Keep all help paths usable offline and verify the advertised examples."""

from contextlib import redirect_stdout, redirect_stderr
import io
from pathlib import Path
import shlex
import subprocess
import sys
import unittest

import crypto_docs
import crypto_help
import crypto_toolkit


def invoke(*args):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            code = crypto_toolkit.main(list(args))
        except SystemExit as error:
            code = error.code
    return code, out.getvalue(), err.getvalue()


class HelpTests(unittest.TestCase):
    def test_every_command_option_and_choice_has_explanation_and_example(self):
        parser = crypto_toolkit.build_parser()
        commands = crypto_help.command_parsers(parser)
        self.assertEqual(set(commands), set(crypto_help.EXAMPLES))
        for name, child in commands.items():
            for action in child._actions:
                with self.subTest(command=name, option=action.dest):
                    result = invoke("help", name, crypto_help.label(action).lstrip("-"))
                    self.assertEqual(result[0], 0, result)
                    self.assertTrue(action.explanation)
                    self.assertTrue(action.example)
                    self.assertIn("Complete command examples:", result[1])
                    for value in action.choices or ():
                        meaning, example = crypto_help.choice_detail(name, action, value)
                        self.assertTrue(meaning)
                        self.assertTrue(example)
                        self.assertIn(example, result[1])

    def test_command_help_works_without_required_inputs(self):
        commands = crypto_help.command_parsers(crypto_toolkit.build_parser())
        for name in commands:
            with self.subTest(command=name):
                standard = invoke(name, "--help")
                friendly = invoke("help", name)
                self.assertEqual(standard[0], 0, standard)
                self.assertEqual(friendly[0], 0, friendly)
                self.assertEqual(standard[1], friendly[1])
                self.assertIn("Examples:", standard[1])
        self.assertEqual(invoke("help")[0], 0)
        self.assertEqual(invoke("help", "missing-command")[0], 2)
        error = invoke("help", "rsa-key", "missing-option")
        self.assertEqual(error[0], 1)
        self.assertIn("Unknown option", error[2])
        self.assertNotIn("Traceback", error[2])

    def test_every_complete_example_parses(self):
        parser = crypto_toolkit.build_parser()
        for name, examples in crypto_help.EXAMPLES.items():
            for command, _ in examples:
                with self.subTest(command=command):
                    args = parser.parse_args(shlex.split(command))
                    self.assertEqual(args.command, name)

    def test_runnable_examples_and_each_encoding_choice(self):
        expected = {"encode":"aGk=", "decode":"UTF-8: hi", "caesar":"hello", "xor":"UTF-8: hello", "hash":"900150983cd24fb0d6963f7d28e17f72",
                    "inverse":"2753", "rsa":"UTF-8: A", "lfsr":"91", "vigenere":"ATTACKATDAWN"}
        for name, text in expected.items():
            result = invoke(*shlex.split(crypto_help.EXAMPLES[name][0][0]))
            self.assertEqual(result[0], 0, result)
            self.assertIn(text, result[1])
        parser = crypto_help.command_parsers(crypto_toolkit.build_parser())["decode"]
        option = next(a for a in parser._actions if a.dest == "format")
        for value in option.choices:
            fragment = crypto_help.choice_detail("decode", option, value)[1]
            result = invoke("decode", *shlex.split(fragment))
            self.assertEqual(result[0], 0, result)
            self.assertIn("UTF-8: hi", result[1])

    def test_defaults_required_and_exclusive_inputs_are_explained(self):
        self.assertIn("Choose exactly one: --text or --file", invoke("help", "aes", "text")[1])
        self.assertIn("Use at most one: --iv or --iv-prefix", invoke("help", "aes", "iv")[1])
        self.assertIn("Default: 100000", invoke("help", "hash-check", "max-words")[1])
        self.assertIn("Required.", invoke("help", "rsa-key", "padding")[1])
        self.assertIn("UTF-16 little endian", invoke("help", "strings", "encoding")[1])

    def test_visual_catalog_and_markdown_include_every_command(self):
        document = crypto_docs.visual_guide("commands")
        catalog = crypto_docs.markdown("commands")
        self.assertEqual(document.count('class="command-card"'), len(crypto_help.EXAMPLES))
        self.assertIn('data-start="commands"', document)
        self.assertNotIn("{{", document)
        for name in crypto_help.EXAMPLES:
            self.assertIn("## " + name, catalog)
        self.assertIn("--key-encoding hex --key-file private.hex", catalog)

    def test_help_and_catalog_need_no_optional_packages(self):
        source = Path(crypto_toolkit.__file__)
        for args in (("help", "rsa-key", "padding"), ("help", "lsb", "bit-order"), ("docs", "commands", "--format", "html")):
            result = subprocess.run([sys.executable, "-S", str(source), *args], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
