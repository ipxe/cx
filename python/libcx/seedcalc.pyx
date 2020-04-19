"""Seed calculators"""

from OpenSSL import crypto

from .cdefs cimport (
    EVP_PKEY,
    EVP_PKEY_free,
    d2i_PUBKEY,
    cx_generator_type,
    cx_seedcalc,
)
from .generator import GeneratorType, Generator


cdef class SeedCalculator:
    """A seed calculator"""

    cdef cx_generator_type _type
    cdef unsigned char[::1] _seed

    def __init__(self, cx_generator_type type,
                 const unsigned char[::1] preseed, key: crypto.PKey):
        cdef const unsigned char[::1] key_der
        cdef const unsigned char *tmp
        cdef EVP_PKEY *pkey = NULL
        try:
            self._type = type
            key_der = crypto.dump_publickey(crypto.FILETYPE_ASN1, key)
            tmp = &key_der[0]
            pkey = d2i_PUBKEY(NULL, &tmp, key_der.shape[0])
            if not pkey:
                raise ValueError("Invalid key")
            self._seed = bytearray(preseed.shape[0])
            if not cx_seedcalc(type, &preseed[0], preseed.shape[0], pkey,
                               &self._seed[0]):
                raise ValueError("Invalid preseed")
        finally:
            EVP_PKEY_free(pkey)

    @property
    def type(self):
        """Generator type"""
        return GeneratorType(self._type)

    @property
    def seed(self):
        """Seed value"""
        return bytes(self._seed)

    @property
    def generator(self):
        """Generator"""
        return Generator(self._type, self._seed)
