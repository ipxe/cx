"""Seed calculators"""

from .cffi import ffi, lib
from .generator import GeneratorType, Generator
from .pkey import CryptoKey, PKey, ImportedPKey

__all__ = [
    'SeedCalculator',
]


class SeedCalculator:
    """A seed calculator"""

    _type: int
    _preseed: bytes
    _key: PKey
    _seed: bytes

    def __init__(self, gentype: int, preseed: bytes, key: CryptoKey) -> None:
        self._type = gentype
        self._preseed = preseed
        self._key = ImportedPKey(key)
        seedlen = lib.cx_gen_seed_len(gentype)
        if not seedlen:
            raise ValueError("Invalid generator type %d" % gentype)
        seed = ffi.new("unsigned char[]", seedlen)
        if not lib.cx_seedcalc(gentype, preseed, len(preseed),
                               self._key.pkey, seed):
            raise ValueError("Could not calculate seed")
        self._seed = bytes(seed)

    @property
    def type(self) -> GeneratorType:
        """Generator type"""
        return GeneratorType(self._type)

    @property
    def preseed(self) -> bytes:
        """Preseed value"""
        return self._preseed

    @property
    def key(self) -> CryptoKey:
        """Preseed verification key"""
        return self._key.key

    @property
    def seed(self) -> bytes:
        """Seed value"""
        return self._seed

    @property
    def generator(self) -> Generator:
        """Generator"""
        return Generator(self._type, self._seed)
