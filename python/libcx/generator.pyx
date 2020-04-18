"""Generators"""

from enum import IntEnum
from uuid import UUID

from .cdefs cimport (
    cx_contact_id,
    cx_generator_type,
    cx_generator,
    cx_gen_seed_len,
    cx_gen_max_iterations,
    cx_gen_instantiate,
    cx_gen_iterate,
    cx_gen_uninstantiate,
)
from . import cdefs


__all__ = [
    'GeneratorType',
    'Generator',
]


class GeneratorTypeMixin(IntEnum):
    """Generator type additional properties"""

    @property
    def seed_len(self):
        """Seed value length"""
        return cx_gen_seed_len(self.value)

    @property
    def max_iterations(self):
        """Maximum number of iterations"""
        return cx_gen_max_iterations(self.value)


GeneratorType = GeneratorTypeMixin(
    'GeneratorType', ((x.name, x.value) for x in cdefs.cx_generator_type)
)


cdef class Generator:
    """A generator"""

    cdef cx_generator_type _type
    cdef cx_generator * gen

    def __init__(self, cx_generator_type type, const unsigned char[::1] seed):
        self._type = type
        self.gen = cx_gen_instantiate(type, &seed[0], seed.shape[0])
        if not self.gen:
            raise ValueError

    def __dealloc__(self):
        if self.gen:
            cx_gen_uninstantiate(self.gen)

    def __iter__(self):
        return self

    def __next__(self):
        cdef cx_contact_id id
        if not cx_gen_iterate(self.gen, &id):
            raise StopIteration
        return UUID(bytes=id.bytes[:sizeof(id.bytes)])

    @property
    def type(self):
        """Generator type"""
        return GeneratorType(self._type)
