#!/usr/bin/python3

import sys
import atheris
with atheris.instrument_imports():
    from markupsafe import Markup, escape


def test_escape(fuzz_in):
    '''
    Test the escape method
    '''
    fdp = atheris.FuzzedDataProvider(fuzz_in)
    data = fdp.ConsumeUnicode(atheris.ALL_REMAINING)
    escape(Markup(data))


def test_unescape(fuzz_in):
    '''
    Test the unescape method
    '''
    fdp = atheris.FuzzedDataProvider(fuzz_in)
    data = fdp.ConsumeUnicode(atheris.ALL_REMAINING)
    Markup(data).unescape()


if __name__ == "__main__":
    command = sys.argv.pop()
    if command == "escape":
        atheris.Setup(sys.argv, test_escape, enable_python_coverage=True)
    else:
        atheris.Setup(sys.argv, test_unescape, enable_python_coverage=True)
    atheris.Fuzz()
