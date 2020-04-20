"""Preseed self-tests"""

import unittest

from OpenSSL import crypto

from libcx import (
    CX_GEN_AES_128_CTR_2048,
    SeedCalculator,
    Preseed,
)


class TestPreseed(unittest.TestCase):
    """Preseed self-tests"""

    def test_api(self):
        """Test API usage"""
        preseed = Preseed.value(CX_GEN_AES_128_CTR_2048)
        self.assertIsInstance(preseed, bytes)
        self.assertEqual(len(preseed), 24)
        key = Preseed.key()
        self.assertIsInstance(key, crypto.PKey)
        seedcalc = SeedCalculator(CX_GEN_AES_128_CTR_2048, preseed, key)
        gen = seedcalc.generator
        self.assertEqual(len(list(gen)), 2048)

    def test_errors(self):
        """Test expected errors"""
        with self.assertRaises(ValueError):
            Preseed.value(0)
