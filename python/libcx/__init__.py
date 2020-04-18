"""libcx interface"""

from .generator import GeneratorType, Generator

CX_GEN_AES_128_CTR_2048 = GeneratorType.CX_GEN_AES_128_CTR_2048
CX_GEN_AES_256_CTR_2048 = GeneratorType.CX_GEN_AES_256_CTR_2048

__all__ = [
    'CX_GEN_AES_128_CTR_2048',
    'CX_GEN_AES_256_CTR_2048',
    'Generator',
    'GeneratorType',
]
