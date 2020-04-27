"""EVP_PKEY wrappers"""

from typing import Any

from cryptography.hazmat.bindings.openssl.binding import Binding
from cryptography.hazmat.primitives.serialization import (load_der_private_key,
                                                          load_der_public_key)
from cryptography.hazmat.backends import default_backend

from .cffi import ffi, lib

__all__ = [
    'InvalidPKeyError',
    'PKey',
    'ImportedPKey',
    'ExportedPKey',
]

crypto = Binding()

# cryptography provides no common base class for keys
CryptoKey = Any


class InvalidPKeyError(ValueError):
    """Invalid key"""


class PKey:
    """An EVP_PKEY wrapper"""

    _key: CryptoKey
    _pkey: ffi.CType

    @property
    def key(self) -> CryptoKey:
        """Python key object"""
        return self._key

    @property
    def pkey(self) -> ffi.CType:
        """EVP_PKEY pointer

        This pointer remains valid only while the `PKey` object itself
        remains alive.
        """
        return self._pkey


class ImportedPKey(PKey):
    """An EVP_PKEY wrapper around a Python key object"""

    def __init__(self, key: CryptoKey) -> None:
        self._key = key
        try:
            self._pkey = key._evp_pkey  # pylint: disable=protected-access
        except AttributeError:
            raise InvalidPKeyError("Invalid key (no _evp_pkey attribute)")
        if not isinstance(self._pkey, crypto.ffi.CData):
            raise InvalidPKeyError("Invalid key (_evp_pkey not a CData)")

    @property
    def pkey(self) -> ffi.CType:
        """EVP_PKEY pointer"""
        return ffi.cast("EVP_PKEY *", self._pkey)


class ExportedPKey(PKey):
    """An EVP_PKEY wrapper around an EVP_PKEY pointer"""

    def __init__(self, pkey: ffi.CType) -> None:
        if not lib.EVP_PKEY_up_ref(pkey):
            raise InvalidPKeyError("Could not acquire EVP_PKEY reference")
        self._pkey = pkey
        try:
            self._wrap_privatekey()
        except InvalidPKeyError:
            self._wrap_publickey()

    def __del__(self) -> None:
        lib.EVP_PKEY_free(self._pkey)

    def _wrap_privatekey(self) -> None:
        """Construct Python key object from EVP_PKEY private key pointer"""
        p_der = ffi.new("unsigned char **")
        der_len = lib.i2d_PrivateKey(self._pkey, p_der)
        if der_len < 0:
            raise InvalidPKeyError("Could not serialize private key")
        try:
            der = ffi.buffer(p_der[0], der_len)[:]
            try:
                self._key = load_der_private_key(der, password=None,
                                                 backend=default_backend())
            except ValueError as exc:
                raise InvalidPKeyError from exc
        finally:
            lib.OPENSSL_free(p_der[0])

    def _wrap_publickey(self) -> None:
        """Construct Python key object from EVP_PKEY public key pointer"""
        p_der = ffi.new("unsigned char **")
        der_len = lib.i2d_PublicKey(self._pkey, p_der)
        if der_len < 0:
            raise InvalidPKeyError("Could not serialize public key")
        try:
            der = ffi.buffer(p_der[0], der_len)[:]
            try:
                self._key = load_der_public_key(der, backend=default_backend())
            except ValueError as exc:
                raise InvalidPKeyError from exc
        finally:
            lib.OPENSSL_free(p_der[0])
