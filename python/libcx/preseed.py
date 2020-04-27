"""Preseeds"""

from .cffi import ffi, lib
from .pkey import CryptoKey, ExportedPKey

__all__ = [
    'Preseed',
]


class Preseed:
    """A preseed constructor"""

    @staticmethod
    def value(gentype: int) -> bytes:
        """Construct preseed value"""
        seedlen = lib.cx_gen_seed_len(gentype)
        if not seedlen:
            raise ValueError("Invalid generator type %d" % gentype)
        preseed = ffi.new("unsigned char[]", seedlen)
        if not lib.cx_preseed_value(gentype, preseed, len(preseed)):
            raise ValueError("Could not construct preseed value")
        return bytes(preseed)

    @staticmethod
    def key() -> CryptoKey:
        """Construct preseed key using default algorithm and parameters"""
        pkey = lib.cx_preseed_key()
        try:
            return ExportedPKey(pkey).key
        finally:
            lib.EVP_PKEY_free(pkey)
