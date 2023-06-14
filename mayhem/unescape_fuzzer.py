#!/usr/bin/python3

import sys
import atheris
with atheris.instrument_imports():
    from markupsafe import Markup


def test_unescape(fuzz_in):
    '''
    Test the unescape method
    '''
    fdp = atheris.FuzzedDataProvider(fuzz_in)
    data = fdp.ConsumeUnicode(atheris.ALL_REMAINING)
    Markup(data).unescape()


if __name__ == "__main__":
    atheris.Setup(sys.argv, test_unescape, enable_python_coverage=True)
    atheris.Fuzz()
