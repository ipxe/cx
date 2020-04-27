"""EVP_PKEY wrapper self-tests"""

import textwrap
from types import SimpleNamespace
import unittest

from cryptography.hazmat.primitives.asymmetric.rsa import (RSAPrivateKey,
                                                           RSAPublicKey)
from cryptography.hazmat.primitives.serialization import (load_pem_private_key,
                                                          load_pem_public_key)
from cryptography.hazmat.backends import default_backend

from libcx.pkey import ImportedPKey, ExportedPKey, InvalidPKeyError
from libcx.cffi import ffi


class TestPKey(unittest.TestCase):
    """EVP_PKEY wrapper self-tests"""

    PRIVKEY = load_pem_private_key(textwrap.dedent("""
    -----BEGIN RSA PRIVATE KEY-----
    MIIEpAIBAAKCAQEArJKHcRffM2qj1lTIC5bAcIGACZPq7o7l4YU1owWb8EkTHAm8
    IlGtThDR3qZtrAdhUqPv4wfFUEPlLQwhUzjxErSRWI8FdzVUwAuMOWH5WnHUNjiy
    fzHEE8NSU3prhPkhuEOGjqFhHP2M23klEevYG+TBgywdXZy4uFc0uVREWl+2nN7l
    P6JsuAYhJuPF0Vx4t8S6YXzi2q7a5XFZbbAaw/m+tdf41cizIcy85ni260SyrUxF
    maZUophG8FCknYC9Ng6kF3T7LDrIGDNadVk3zefev1iyMc5VihZ9rDhY2N7H/TIY
    5Rz3YtLkB2JAFFerhzC/1upWYLqPkjoI8nSA7QIDAQABAoIBAGfuv9+ezvA6c33s
    BablHfUkKSabjUwrh8tw3MLX5/ipKfci7cmFg2iWvK7pcPfAYh7RWPJUhcM3gNjG
    i3OBwb7QPREm4dXPqsEWs1cD6JdOIs6dCvOL11lHs1dPTV4CZQqCsJFKJCC/m4u6
    xFaswbTa6qjDctQkRSPQcZKEa745FaPqbHYGxf5J8DgOnQlHDoCbsVuNV7Q2dzeU
    q0PM9xkBLTKdG7BxKNJCFdhlDpgHDcBhDvmfInkUkO/uaDvXkh0g15gXsHD0YiMg
    AsEK6/dvSVYoef5/YDBelzorJtA/0uWB7xi42CWa1RzJ+dMPZpzS5OWbnhJlXBq6
    0QzQB0ECgYEA1D8rabYvNCNz+mnOYzkyagq7P97Ze5QLcvhMJj/hNpBBHyKrEOCb
    UOS29Ab7W1sefTMZgVDc/SMMWHaIL8vne/L46Cf0OxJSSlOcvInpcTK1qespsVZ8
    Hj9EfdSKUqsxFEeJQAenUUY3UIP74isJAuWvniUdU09L2w3LQlCCXXkCgYEA0CWi
    4ElcapR+VwhuiKRA46Z/eJHFnXZcWYb6w2+m5K6kExdAyj34Tr7jh+txoz0XtTBs
    B17WhUZLg1nJITnyGX+rm0QszlBvxJWntu+DC6PntDC557yiP339Q2HT6+1fb2rB
    Klz15WywkrLRaCOy3lvjNrtOTgT/AEXCdXuiBhUCgYEA0zXdfL/4b1kMc9hQsrrb
    aV0ug1u/btOfJRTjqniNJGAe/d3g/9WTmcdQLLy562pch9iO+/m9QAZdpbamxXGS
    9OyQN25zA0mzLBXSdmiDLst4rhO/lKLstqjc/p6/245SM80QTvCO1zkZmH0O7j1H
    JWPuBGEIsrvJT76FU4OMh3kCgYEAiPz8IRinFg38yFLoTE2t1yWxJyzpHiTTyqgn
    SZCmCkNWAKqBHZmDXnALV10BQSnn/HuN3ZvxG22ULTJeSNvWFioMSvendXFC3eKQ
    qrkfSf3pdJHNCFMBhT/p+vrbep6S/MUJtFPSEdhirWm6oAs+oVFgTJkhg/+NxCQl
    QyTHEbECgYALKVLo3b7FUcNmH5AkbdiLkh0ZTucKpVPqAF/sHGCgh4kmzVMRIoiu
    eQhu0uf5qMy74d9EihfV9RmrfVFnCNFewFNFaZFBKr+7Sl+k+ZnZQrByNYXrukhb
    axdA+/wKv2DwvKDBUJJxj0OVLgPd5ew+LXETxVcE/HFuRd5QR6g73A==
    -----END RSA PRIVATE KEY-----
    """).encode(), password=None, backend=default_backend())

    PUBKEY = load_pem_public_key(textwrap.dedent("""
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArJKHcRffM2qj1lTIC5bA
    cIGACZPq7o7l4YU1owWb8EkTHAm8IlGtThDR3qZtrAdhUqPv4wfFUEPlLQwhUzjx
    ErSRWI8FdzVUwAuMOWH5WnHUNjiyfzHEE8NSU3prhPkhuEOGjqFhHP2M23klEevY
    G+TBgywdXZy4uFc0uVREWl+2nN7lP6JsuAYhJuPF0Vx4t8S6YXzi2q7a5XFZbbAa
    w/m+tdf41cizIcy85ni260SyrUxFmaZUophG8FCknYC9Ng6kF3T7LDrIGDNadVk3
    zefev1iyMc5VihZ9rDhY2N7H/TIY5Rz3YtLkB2JAFFerhzC/1upWYLqPkjoI8nSA
    7QIDAQAB
    -----END PUBLIC KEY-----
    """).encode(), backend=default_backend())

    def test_private(self):
        """Test private keys"""
        imported = ImportedPKey(self.PRIVKEY)
        self.assertIsInstance(imported.key, RSAPrivateKey)
        self.assertIsInstance(imported.pkey, ffi.CData)
        exported = ExportedPKey(imported.pkey)
        self.assertEqual(exported.pkey, imported.pkey)
        self.assertIsInstance(exported.key, RSAPrivateKey)
        self.assertEqual(exported.key.public_key().public_numbers(),
                         imported.key.public_key().public_numbers())

    def test_public(self):
        """Test public keys"""
        imported = ImportedPKey(self.PUBKEY)
        self.assertIsInstance(imported.key, RSAPublicKey)
        self.assertIsInstance(imported.pkey, ffi.CData)
        exported = ExportedPKey(imported.pkey)
        self.assertEqual(exported.pkey, imported.pkey)
        self.assertIsInstance(exported.key, RSAPublicKey)
        self.assertEqual(exported.key.public_numbers(),
                         imported.key.public_numbers())

    def test_error(self):
        """Test expected errors"""
        with self.assertRaises(InvalidPKeyError):
            ImportedPKey(None)
        with self.assertRaises(InvalidPKeyError):
            ImportedPKey(SimpleNamespace(_evp_pkey=None))
