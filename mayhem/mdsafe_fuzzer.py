#!/usr/bin/python3

import sys
import random
import atheris
with atheris.instrument_imports():
    from markupsafe import Markup, escape

# Useful markdown elemets
# Taken from https://github.com/google/fuzzing/dictionaries/markdown.dict
markdown_elems = 
    [
    "~~"
    "2."
    "[a]("
    "[a]["
    "![b]("
    "**"
    "---"
    "# "
    "```"
    "[a]:"
    "<http://"
    "[1]: http://a.com"
    "- [x"
    "[TOC]"
    ":::python"
    "| ---"
    "***"
    "___"
    "```html"
    "- [ ]"
    "[^a]"
    "#a {#b}"
    ]


def markdown_mutator(data, max_size, seed):
    '''
    Custom Mutator for markdown. Inserts markdown keywords to the data
    '''
    random.seed(seed)
    fdp = atheris.FuzzedDataProvider(data)
    data = fdp.ConsumeUnicode(atheris.ALL_REMAINING)
    num_elems = random.randint(0, len(markdown_elems))
    elem_pos = [random.randint(0, len(data)) for i in range(num_elems)]
    elems = random.choices(markdown_elems, k=num_elems)
    curr_pos = 0
    for elem, pos in zip(elems, elem_pos):
        data = data[:curr_pos + pos] + elem + data[curr_pos + pos:]
        curr_pos += len(elem)
    return atheris.Mutate(data, len(data))


def test_escape(fuzz_in):
    ''' 
    Test the escape method
    '''
    escape(Markup(fuzz_in))


def test_unescape(fuzz_in):
    ''' 
    Test the unescape method
    '''
    Markup(fuzz_in).unescape()


if __name__ == "__main__":
    command = sys.argv.pop()
    if command == "escape":
        atheris.Setup(sys.argv, test_escape, custom_mutator=markdown_mutator, enable_python_coverage=True)
    else:
        atheris.Setup(sys.argv, test_unescape, custom_mutator=markdown_mutator, enable_python_coverage=True)
    atheris.Fuzz()
