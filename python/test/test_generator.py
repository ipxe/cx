"""Generator self-tests"""

import unittest
from uuid import UUID

from libcx import (CX_GEN_AES_128_CTR_2048, CX_GEN_AES_256_CTR_2048,
                   GeneratorType, Generator)


class TestGenerator(unittest.TestCase):
    """Generator self-tests"""

    def test_type(self):
        """Test generator type"""
        self.assertIs(CX_GEN_AES_128_CTR_2048, GeneratorType(1))
        self.assertEqual(CX_GEN_AES_128_CTR_2048, 1)
        self.assertEqual(CX_GEN_AES_128_CTR_2048.seed_len, 24)
        self.assertEqual(CX_GEN_AES_128_CTR_2048.max_iterations, 2048)
        self.assertIs(CX_GEN_AES_256_CTR_2048, GeneratorType(2))
        self.assertEqual(CX_GEN_AES_256_CTR_2048, 2)
        self.assertEqual(CX_GEN_AES_256_CTR_2048.seed_len, 48)
        self.assertEqual(CX_GEN_AES_256_CTR_2048.max_iterations, 2048)

    def test_properties(self):
        """Test properties"""
        gen = Generator(CX_GEN_AES_128_CTR_2048, bytes(range(24)))
        self.assertIs(gen.type, CX_GEN_AES_128_CTR_2048)
        with self.assertRaises(AttributeError):
            gen.type = CX_GEN_AES_256_CTR_2048
        self.assertEqual(gen.seed, bytes(range(24)))
        with self.assertRaises(AttributeError):
            gen.seed = b'invalid'

    def test_iteration(self):
        """Test iteration"""
        gen = Generator(CX_GEN_AES_128_CTR_2048, bytes(range(24)))
        ids1 = list(gen)
        ids2 = list(gen)
        self.assertEqual(len(ids1), 2048)
        self.assertEqual(ids1, ids2)

    def test_errors(self):
        """Test expected errors"""
        with self.assertRaises(ValueError):
            Generator(0, bytes(range(24)))
        with self.assertRaises(ValueError):
            Generator(CX_GEN_AES_128_CTR_2048, b'hello')

    def test_spec_type1(self):
        """Test generator type 1 with official test vectors"""
        ids = list(Generator(CX_GEN_AES_128_CTR_2048, bytes(range(24))))
        self.assertEqual(len(ids), 2048)
        self.assertEqual(ids[0], UUID('aeaa0891-03d8-400c-beb0-046a2dab8522'))
        self.assertEqual(ids[-1], UUID('61f3d4b4-844f-4516-9651-d2d2cf8af346'))
        ids = list(Generator(CX_GEN_AES_128_CTR_2048, bytes([
            0x04, 0xb4, 0xe8, 0x66, 0xac, 0x9e, 0x39, 0xc9,
            0x2c, 0x2d, 0x8a, 0xfe, 0x68, 0xcb, 0x74, 0x96,
            0x0b, 0xf9, 0xcc, 0xfc, 0x94, 0x11, 0xe3, 0xdb
        ])))
        self.assertEqual(len(ids), 2048)
        self.assertEqual(ids[0], UUID('e3e6c75a-5b7b-43d2-973a-b8c3c55b27e4'))
        self.assertEqual(ids[-1], UUID('eb61bab8-b7b7-45e6-aaf8-8b3b6ac3c146'))

    def test_spec_type2(self):
        """Test generator type 2 with official test vectors"""
        ids = list(Generator(CX_GEN_AES_256_CTR_2048, bytes(range(48))))
        self.assertEqual(len(ids), 2048)
        self.assertEqual(ids[0], UUID('7ad7f061-2b3e-4f3e-91f8-b3517deca58d'))
        self.assertEqual(ids[-1], UUID('e8a1b8c3-3de6-4198-8650-2b4188aef12e'))
        ids = list(Generator(CX_GEN_AES_256_CTR_2048, bytes([
            0xd1, 0xad, 0xd7, 0x91, 0xe8, 0x2e, 0x98, 0xf2,
            0x6c, 0xda, 0xbf, 0xb1, 0x2e, 0x30, 0x76, 0x9f,
            0x5c, 0x5f, 0x86, 0xc9, 0xfe, 0xeb, 0x18, 0x26,
            0x2b, 0x7f, 0xac, 0x77, 0x54, 0x8b, 0x49, 0xc4,
            0x65, 0xd2, 0x0c, 0x76, 0x01, 0x20, 0xcf, 0x35,
            0x21, 0x34, 0x93, 0xba, 0xce, 0xf7, 0x53, 0x5a
        ])))
        self.assertEqual(len(ids), 2048)
        self.assertEqual(ids[0], UUID('e46c75f2-6968-4655-b751-3738547b5cc9'))
        self.assertEqual(ids[-1], UUID('9d9b113a-94d4-4d0c-9ea6-540db7bb8fb8'))
