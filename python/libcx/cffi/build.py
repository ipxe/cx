"""libcx CFFI builder"""

from pathlib import Path

import cffi

builder = cffi.FFI()
path = Path(__file__).parent
builder.set_source("libcx.cffi", (path / 'source.c').read_text())
builder.cdef((path / 'cdef.c').read_text())

if __name__ == '__main__':
    builder.compile(verbose=True)
