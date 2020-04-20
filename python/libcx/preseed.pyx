"""Preseeds"""

from OpenSSL import crypto

from .cdefs cimport (
    EVP_PKEY,
    OPENSSL_free,
    i2d_PUBKEY,
    cx_generator_type,
    cx_gen_seed_len,
    cx_preseed_value,
    cx_preseed_key,
)


cdef class Preseed:
    """A preseed constructor"""

    @staticmethod
    def value(cx_generator_type type):
        cdef unsigned char[::1] preseed
        cdef size_t len
        len = cx_gen_seed_len(type)
        if not len:
            raise ValueError("Invalid preseed type")
        preseed = bytearray(len)
        if not cx_preseed_value(type, &preseed[0], preseed.shape[0]):
            raise ValueError("Could not construct preseed value")
        return bytes(preseed)

    @staticmethod
    def key():
        cdef EVP_PKEY *key
        cdef unsigned char *key_der = NULL
        cdef int key_der_len
        try:
            key = cx_preseed_key()
            if not key:
                raise ValueError("Could not construct preseed key")
            key_der_len = i2d_PUBKEY(key, &key_der)
            if key_der_len < 0:
                raise ValueError("Invalid preseed key")
            return crypto.load_publickey(crypto.FILETYPE_ASN1,
                                         key_der[:key_der_len])
        finally:
            OPENSSL_free(key_der)
