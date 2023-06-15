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


if __name__ == "__main__":
    atheris.Setup(sys.argv, test_escape, enable_python_coverage=True)
    atheris.Fuzz()
