"""BIO wrappers"""

from .cffi import ffi, lib

__all__ = [
    'MemoryBIO',
]


class MemoryBIO:
    """An in-memory BIO"""

    _bio: ffi.CType

    def __init__(self) -> None:
        self._bio = lib.BIO_new(lib.BIO_s_mem())
        if not self._bio:
            raise MemoryError

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, tb) -> None:
        if self._bio:
            lib.BIO_free(self._bio)
        self._bio = None

    def __del__(self) -> None:
        if self._bio:
            lib.BIO_free(self._bio)

    @property
    def bio(self) -> ffi.CType:
        """BIO pointer"""
        return self._bio

    @property
    def data(self) -> bytes:
        """Accumulated data"""
        if not self._bio:
            return None
        p_biodata = ffi.new("char **")
        biolen = lib.BIO_get_mem_data(self._bio, p_biodata)
        if biolen < 0:
            raise ValueError("Could not retrieve BIO data")
        return ffi.buffer(p_biodata[0], biolen)[:]
