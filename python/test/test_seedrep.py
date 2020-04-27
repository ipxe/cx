"""Seed report self-tests"""

from base64 import b64decode
import textwrap
import unittest

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend

from libcx import (CX_GEN_AES_128_CTR_2048, CX_GEN_AES_256_CTR_2048,
                   SeedDescriptor, SeedReport)


class TestSeedReport(unittest.TestCase):
    """Seed report self-tests"""

    KEY = load_pem_private_key(textwrap.dedent("""
    -----BEGIN RSA PRIVATE KEY-----
    MIIEpAIBAAKCAQEAq8VOOpc0qHw9FpyXOezINVsWP2Y1yjqX+dqlKPGtHlwSuRkK
    L7i5xJkyNrgjxVCtNPI/uBJb3XaBi02MBOYRN3YhZ8QAW7sx6Vi7/c3HAuJiwnUn
    REXdL012fDf1x+Wrjic+ONRPa3QuVDVTdLt+7t0PiWXyxxq5iFYhllOaA/ifMCr6
    YJ/bOH9POE2JR2weCwZ85ZF5hLE02BFiFgc+D0IVakQ7nBW8gSZKOEPLHfrxN2Gl
    rbX5Fr5cIDH92pIqS7JzXEgl2QuQRREOmlRxvnDLWZosBvAKl52Q9obetZKuBlEO
    li3xjhXDKpSpnEdPe6bZdPqnThSzgVC6Rbh1rwIDAQABAoIBAQCh9on73wUs9PCY
    +I/zc1uYS8nff92qULNqSQrAX5kP7ltNItojAzhOsvDQ/bHk5Fxddyozw0PRv2MI
    2dbz64dCV2XKNNrto8W9NAkWmMhU5OegWdzrmECl0JGvMQjUMrAfestFxJMaS9M/
    XYTSpdRbIB/9Ox6/NGjKsAQ9fZjUsjba/VnDSX3nJdvt4lBI9ya9zYepg+B2yM4s
    4kCBxliyJQiCn+EkIkcZYkJ4gMnm4PtqfEeaYOepKlmK9kIdqzh5P3c97SklRNTH
    UuwA1TeWf+DHvCE/kAVE6C1N7OwK9eW0Em65WReVObYk6zmMXyx0rDTqsVj9qMQy
    33Oz6Zk5AoGBANHQsULe8XHsgNGXCDPyFAzQDDOboCRpOdjza+7pkdF9UvGKdv/P
    xQK2JZqfDJz9Qgm2098SdE3aN8ukUzW4rXXIDAmKXhuihZBo28gkdzxjUk/wDGbE
    PuJGPKN7khYgk4QoLhG+JWCNT26ddk6w7MnZnk0kA0yZrOFIy5lCHPHzAoGBANGU
    xEU6Cj4PiC2eS5ve1/NQ4AHMLOvrrtFerUpcAFLhAv5XrrHBBlAlf8b26A1n4NfY
    SBHiq8KI6/Nce0ol7ECqPnUyzG+Gm00ZyoDYTHBg6r4Lq+8P2v/wYg7IhQNG1gpB
    MnL9xkVFyYkELMpm4fcS7rYrsndW187bvrsyW2BVAoGADMfBhGlAG8hkMGAax88/
    GWiy1ZHtN0qRk32AXZUspK4Vl1Dv3rUxMvEVaU223vkuRJk2XqgpHXTlYSopR2Rw
    bHQ7B3m+McC8kgdRG+fcu3jxUp00pC3gBrhwiSTFyUNCuRIZfEswy6jP5dUBl9l/
    EuyGj/xZlxjlRvPAMx2r1bECgYBwqylYjfszoeXzoEXFZedyRugmDz2XFvzEUcGX
    WB5Ub+LMGRcxODPMolwu+k2F53JYl00nUFRGIJW4Ht+o3PpFSUCKgOSmkBatPFBB
    NAbj4zZPNLcZrcxuCyysBeB8AnjOyn30k7kjRIEzx6rMpMKVsPfjt1oaDfW2nyvK
    NygogQKBgQCYOburA+cXD4es9cbvAh0NcrI4PLATsWx+D8LQXej8BUlw/X3F8yl1
    RVn7+/e7ALJ7EXjpFSzU4JB55T1hSh3hmno1m0AnBnDaSIeAmqtVUvKchITaliTd
    dgat2lmuZLSOZg3ArU3uR4oRaaztwjSOeNXr2ojxEVgeAwgekln7uw==
    -----END RSA PRIVATE KEY-----
    """).encode(), password=None, backend=default_backend())

    def test_sign_verify(self):
        """Test signing and verifying"""
        report = SeedReport(publisher='NHS', challenge='12345', descriptors=(
            SeedDescriptor(CX_GEN_AES_128_CTR_2048, bytes(range(24)),
                           self.KEY),
            SeedDescriptor(CX_GEN_AES_256_CTR_2048, bytes(range(48)),
                           self.KEY),
        ))
        signed = report.sign()
        der = signed.der
        self.assertIsInstance(der, bytes)
        self.assertIn('publisherName: NHS', str(signed))
        pem = signed.pem
        self.assertEqual(b64decode(''.join(pem.splitlines()[1:-1])), der)
        verified = SeedReport.verify(der)
        self.assertIsInstance(verified, SeedReport)
        self.assertEqual(verified.publisher, 'NHS')
        self.assertEqual(verified.challenge, '12345')
        self.assertEqual(len(verified.descriptors), 2)
        self.assertEqual(verified.descriptors[0].type, CX_GEN_AES_128_CTR_2048)
        self.assertEqual(verified.descriptors[0].preseed, bytes(range(24)))
        self.assertIsInstance(verified.descriptors[0].key, RSAPublicKey)
        self.assertEqual(verified.descriptors[0].key.public_numbers(),
                         self.KEY.public_key().public_numbers())
