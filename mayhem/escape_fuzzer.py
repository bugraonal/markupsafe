#!/usr/bin/python3

import sys
import atheris
with atheris.instrument_imports():
    from markupsafe import Markup, escape


def test(fuzz_in):
    escape(Markup(fuzz_in))


if __name__ == "__main__":
    atheris.Setup(sys.argv, test, enable_python_coverage=True, dict="markdown.dict")
    atheris.Fuzz()
