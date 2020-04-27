"""Generators"""

from enum import IntEnum
from typing import Iterator
from uuid import UUID

from .cffi import ffi, lib

__all__ = [
    'GeneratorType',
    'Generator',
]


class GeneratorTypeMixin(IntEnum):
    """Generator type additional properties"""

    @property
    def seed_len(self) -> int:
        """Seed value length"""
        return lib.cx_gen_seed_len(self.value)

    @property
    def max_iterations(self) -> int:
        """Maximum number of iterations"""
        return lib.cx_gen_max_iterations(self.value)


GeneratorType = GeneratorTypeMixin(
    'GeneratorType', ffi.typeof("enum cx_generator_type").relements
)


class Generator:
    """A generator"""

    _type: int
    _seed: bytes

    def __init__(self, gentype: int, seed: bytes) -> None:
        self._type = gentype
        self._seed = seed
        seedlen = lib.cx_gen_seed_len(gentype)
        if not seedlen:
            raise ValueError("Invalid generator type %d" % gentype)
        if len(seed) != seedlen:
            raise ValueError("Invalid seed for generator type %d" % gentype)

    def __iter__(self) -> Iterator[UUID]:
        gen = lib.cx_gen_instantiate(self._type, self._seed, len(self._seed))
        if not gen:
            raise ValueError("Failed to instantiate generator")
        try:
            cid = ffi.new("struct cx_contact_id *")
            while lib.cx_gen_iterate(gen, cid):
                yield UUID(bytes=bytes(cid.bytes))
        finally:
            lib.cx_gen_uninstantiate(gen)

    @property
    def type(self) -> GeneratorType:
        """Generator type"""
        return GeneratorType(self._type)

    @property
    def seed(self) -> bytes:
        """Seed value"""
        return self._seed
