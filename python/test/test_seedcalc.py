"""Seed calculator self-tests"""

import textwrap
import unittest

from OpenSSL import crypto

from libcx import (
    CX_GEN_AES_128_CTR_2048,
    CX_GEN_AES_256_CTR_2048,
    Generator,
    SeedCalculator,
)


class TestSeedCalculator(unittest.TestCase):
    """Seed calculator self-tests"""

    KEY_A = crypto.load_publickey(crypto.FILETYPE_PEM, textwrap.dedent("""
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq++v4g9bweWB+wOOCIEP
    h2ORXBOdGDXyNOuHpYOabgabhJRFbLNzEULhhDD2fqR3GEne6wJ8vDB0fj4foKiR
    HHzuQ7pJW+H5AVk8tGGPvYdkVepOedgUcAY2nNKRmqZrdz3gUMLzIJGdgbfM2vRb
    qQh3p6JyNDJSOvW3VIdmdVz+Vc4vIq5eL5srAnHhSTYTRgnUQz72lc/sZJZOfLup
    pT2ZV1vA7cqb/VzVpcRYlj0A3LQX0ZT9cB/50rZTsPOgrQRfdxJrdRQv4oIHNVpu
    lZfcpwRmkhI2s4gUog9R72TEkJWpudDpwQb0HEq2uMJbfnPnrFLOHr/ZjK1KVKPm
    9QIDAQAB
    -----END PUBLIC KEY-----
    """))

    KEY_B = crypto.load_publickey(crypto.FILETYPE_PEM, textwrap.dedent("""
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwfgIKqmWkKZE7wE5R7mP
    5LTZtrWsfU2qSASga8TutHHqfvncAK36+ZFHLY8/UJtjbkP3q0tPmIRmJfeM2QLM
    3WxdM5+AWm503TQOrYdWPI/z2sTBWe5hT/+G19Vpo56KGsDB2Vrs4BOaF7maxhY+
    IrjMzZVfsEEjbd8EfsyJ2NYeXZT6UTOsz6rZ5xzfGkv8O3AU/zFGZjIk8wMsUuDn
    sTxayv5KfYcZ0E0r9snhrDh51uljxZCeCN1q+82R7/GnBR74EKT8CKPErXsBmnO7
    cYWRvaXIaQMEhou6Ouli30YjNZPvbhMxRck4+lSF9KN209L/1nfvlw3MCAGfc662
    jQIDAQAB
    -----END PUBLIC KEY-----
    """))

    def test_api(self):
        """Test API usage"""
        seedcalc = SeedCalculator(CX_GEN_AES_128_CTR_2048, bytes(range(24)),
                                  self.KEY_A)
        self.assertIs(seedcalc.type, CX_GEN_AES_128_CTR_2048)
        self.assertEqual(len(seedcalc.seed), 24)
        self.assertIsInstance(seedcalc.seed, bytes)
        gen = seedcalc.generator
        self.assertIsInstance(gen, Generator)
        self.assertIs(gen.type, CX_GEN_AES_128_CTR_2048)
        self.assertEqual(len(list(gen)), 2048)

    def test_spec_type1(self):
        """Test generator type 1 with official test vectors"""
        seedcalc = SeedCalculator(CX_GEN_AES_128_CTR_2048, bytes(range(24)),
                                  self.KEY_A)
        self.assertEqual(seedcalc.seed, bytes([
            0xc9, 0xf7, 0xfd, 0xe4, 0x50, 0x97, 0x7c, 0x5d,
            0x7d, 0xaa, 0xcb, 0x2d, 0x93, 0x7c, 0x5a, 0x48,
            0x20, 0xeb, 0xca, 0xaa, 0x7e, 0xdb, 0xcd, 0xac
        ]))
        seedcalc = SeedCalculator(CX_GEN_AES_128_CTR_2048, bytes(range(24)),
                                  self.KEY_B)
        self.assertEqual(seedcalc.seed, bytes([
            0x65, 0x55, 0xa6, 0xe9, 0xe4, 0x61, 0x17, 0xa0,
            0x8d, 0xe1, 0x1e, 0x06, 0x80, 0x13, 0x7f, 0x0b,
            0x66, 0x4a, 0x77, 0x6c, 0x0c, 0x68, 0x95, 0xd8
        ]))
        seedcalc = SeedCalculator(CX_GEN_AES_128_CTR_2048, bytes([
            0x33, 0x13, 0x7e, 0x02, 0x24, 0xf0, 0xac, 0x03,
            0x1f, 0xf1, 0x78, 0x76, 0xf9, 0xfb, 0xfc, 0xdc,
            0x20, 0x8f, 0xe5, 0x20, 0x11, 0x9d, 0x23, 0xb1
        ]), self.KEY_B)
        self.assertEqual(seedcalc.seed, bytes([
            0x20, 0xc4, 0x4d, 0xe4, 0x64, 0x16, 0x04, 0xc8,
            0x5c, 0xf7, 0xcf, 0x29, 0x27, 0xf8, 0x70, 0xc8,
            0xe9, 0x86, 0x6a, 0x31, 0x17, 0x4a, 0xd5, 0x7f
        ]))

    def test_spec_type2(self):
        """Test generator type 2 with official test vectors"""
        seedcalc = SeedCalculator(CX_GEN_AES_256_CTR_2048, bytes(range(48)),
                                  self.KEY_A)
        self.assertEqual(seedcalc.seed, bytes([
            0x58, 0xf4, 0x82, 0x5b, 0x6b, 0xcc, 0x59, 0xc2,
            0x69, 0x2b, 0xf1, 0x2b, 0x19, 0x43, 0x47, 0xf8,
            0xd1, 0x47, 0x6c, 0x25, 0xf2, 0xba, 0x52, 0x6f,
            0xe5, 0x19, 0x22, 0xfd, 0xc2, 0x8f, 0xbd, 0xac,
            0xc8, 0x24, 0x3e, 0xe9, 0x4e, 0x44, 0x3e, 0x1a,
            0xc6, 0x8f, 0x6c, 0x3c, 0x38, 0xd3, 0x16, 0xc8
        ]))
        seedcalc = SeedCalculator(CX_GEN_AES_256_CTR_2048, bytes(range(48)),
                                  self.KEY_B)
        self.assertEqual(seedcalc.seed, bytes([
            0x18, 0x60, 0xc1, 0xb5, 0x77, 0x3f, 0x62, 0x57,
            0x72, 0x7e, 0x7c, 0x68, 0x1f, 0x24, 0x5d, 0xc3,
            0x4f, 0x55, 0xe4, 0x01, 0x6e, 0x55, 0x80, 0xa9,
            0x8d, 0xae, 0x95, 0x97, 0x9b, 0x07, 0x18, 0x13,
            0xdf, 0xa2, 0x1c, 0x18, 0x40, 0xf7, 0x8b, 0xe8,
            0x76, 0xda, 0x26, 0x0f, 0x12, 0x91, 0x66, 0xc3
        ]))
        seedcalc = SeedCalculator(CX_GEN_AES_256_CTR_2048, bytes([
            0x5b, 0xad, 0x27, 0xe1, 0x63, 0x64, 0x7e, 0x8c,
            0x63, 0x1a, 0xe7, 0xc6, 0xd2, 0x36, 0xcf, 0xec,
            0x43, 0x92, 0xc7, 0xb0, 0x56, 0x26, 0x90, 0x5f,
            0x72, 0xf7, 0xd2, 0xa5, 0xa0, 0xaa, 0x65, 0xcd,
            0x78, 0xac, 0xc5, 0x36, 0xb7, 0x05, 0xe6, 0xeb,
            0x92, 0xdf, 0x4b, 0xcb, 0xf3, 0xaa, 0xcc, 0x4d
        ]), self.KEY_B)
        self.assertEqual(seedcalc.seed, bytes([
            0x20, 0x95, 0xee, 0x61, 0x27, 0xa0, 0x36, 0x90,
            0xd7, 0xee, 0xab, 0x1b, 0x4c, 0xf0, 0xc0, 0x91,
            0xcf, 0x39, 0x31, 0x34, 0x7c, 0xd2, 0x82, 0xcc,
            0xa5, 0xf6, 0xbf, 0x2f, 0x7a, 0x45, 0xa1, 0xd8,
            0x4f, 0x99, 0xeb, 0xb8, 0x24, 0x3b, 0x73, 0x6a,
            0x07, 0x42, 0x8b, 0x22, 0x0d, 0x7e, 0x46, 0xb1
        ]))

    def test_errors(self):
        """Test expected errors"""
        with self.assertRaises(ValueError):
            SeedCalculator(0, bytes(range(24)), self.KEY_A)
        with self.assertRaises(ValueError):
            SeedCalculator(CX_GEN_AES_128_CTR_2048, bytes(range(23)),
                           self.KEY_A)
        with self.assertRaises(Exception):
            SeedCalculator(CX_GEN_AES_128_CTR_2048, bytes(range(24)), None)
        with self.assertRaises(Exception):
            SeedCalculator(CX_GEN_AES_128_CTR_2048, bytes(range(24)),
                           crypto.PKey())
