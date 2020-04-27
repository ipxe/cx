"""Seed reports"""

from typing import List, Sequence, Union
from .bio import MemoryBIO
from .cffi import ffi, lib
from .generator import GeneratorType, Generator
from .pkey import CryptoKey, PKey, ImportedPKey, ExportedPKey
from .seedcalc import SeedCalculator

__all__ = [
    'SeedDescriptor',
    'SeedReport',
    'SeedReportData',
]


class SeedDescriptor:
    """A seed descriptor"""

    _type: int
    _preseed: bytes
    _key: PKey

    def __init__(self, gentype: int, preseed: bytes, key: CryptoKey) -> None:
        self._type = gentype
        self._preseed = preseed
        self._key = ImportedPKey(key)

    def __repr__(self) -> str:
        return "%s(%r, %r, %r)" % (self.__class__.__name__, self._type,
                                   self._preseed, self._key.key)

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
        """Preseed key"""
        return self._key.key

    @property
    def pkey(self) -> ffi.CType:
        """Preseed key EVP_PKEY pointer"""
        return self._key.pkey

    @property
    def calculator(self) -> SeedCalculator:
        """Seed calculator"""
        return SeedCalculator(self._type, self._preseed, self._key.key)

    @property
    def generator(self) -> Generator:
        """Generator"""
        return self.calculator.generator


class SeedReport:
    """A seed report"""

    _publisher: str
    _challenge: str
    _descriptors: List[SeedDescriptor]

    def __init__(self, publisher: str = '', challenge: str = '',
                 descriptors: Sequence[SeedDescriptor] = ()) -> None:
        self._publisher = publisher
        self._challenge = challenge
        self._descriptors = list(descriptors)

    def __repr__(self) -> str:
        return "%s(%r, %r, %r)" % (self.__class__.__name__, self._publisher,
                                   self._challenge, self._descriptors)

    @property
    def publisher(self) -> str:
        """Publisher name"""
        return self._publisher

    @publisher.setter
    def publisher(self, value: str) -> None:
        """Publisher name"""
        self._publisher = value

    @property
    def challenge(self) -> str:
        """Seed report challenge"""
        return self._challenge

    @challenge.setter
    def challenge(self, value: str) -> None:
        """Seed report challenge"""
        self._challenge = value

    @property
    def descriptors(self) -> List[SeedDescriptor]:
        """Seed descriptors"""
        return self._descriptors

    def sign(self) -> 'SeedReportData':
        """Construct and sign seed report"""
        preseeds = [ffi.from_buffer(x.preseed) for x in self._descriptors]
        desc = ffi.new("struct cx_seed_descriptor []", [{
            'type': x.type,
            'preseed': preseed,
            'len': len(preseed),
            'key': x.pkey,
        } for x, preseed in zip(self._descriptors, preseeds)])
        publisher = ffi.new("char []", self._publisher.encode())
        challenge = ffi.new("char []", self._challenge.encode())
        report = ffi.new("struct cx_seed_report *", {
            'desc': desc,
            'count': len(self._descriptors),
            'publisher': publisher,
            'challenge': challenge,
        })
        der_len = ffi.new("size_t *")
        der = lib.cx_seedrep_sign_der(report, ffi.NULL, der_len)
        if not der:
            raise ValueError("Could not sign seed report")
        try:
            return SeedReportData(ffi.buffer(der, der_len[0])[:])
        finally:
            lib.OPENSSL_free(der)

    @classmethod
    def verify(cls, data: Union[bytes, 'SeedReportData']):
        """Verify and parse seed report"""
        der = bytes(data)
        report = lib.cx_seedrep_verify_der(der, len(der))
        if not report:
            raise ValueError("Could not verify seed report")
        try:
            descriptors = (SeedDescriptor(
                gentype=x.type,
                preseed=ffi.buffer(x.preseed, x.len)[:],
                key=ExportedPKey(x.key).key,
            ) for x in (report.desc[i] for i in range(report.count)))
            return cls(
                publisher=ffi.string(report.publisher).decode(),
                challenge=ffi.string(report.challenge).decode(),
                descriptors=descriptors,
            )
        finally:
            lib.cx_seedrep_free(report)


class SeedReportData:
    """A seed report ASN.1 data object"""

    _der: bytes
    _asn1: ffi.CType

    def __init__(self, der: bytes) -> None:
        self._der = der
        tmp = ffi.new("unsigned char **")
        tmp[0] = ffi.from_buffer(der)
        self._asn1 = lib.d2i_CX_SEED_REPORT(ffi.NULL, tmp, len(der))
        if not self._asn1:
            raise ValueError("Could not parse seed report")

    def __del__(self) -> None:
        lib.CX_SEED_REPORT_free(self._asn1)

    def __str__(self) -> str:
        with MemoryBIO() as bio:
            if lib.CX_SEED_REPORT_print_ctx(bio.bio, self._asn1, 0,
                                            ffi.NULL) != 1:
                raise ValueError("Could not print seed report")
            return bio.data.decode()

    def __bytes__(self) -> bytes:
        return self._der

    @property
    def der(self) -> bytes:
        """Seed report in DER format"""
        return self._der

    @property
    def pem(self):
        """Seed report in PEM format"""
        with MemoryBIO() as bio:
            if not lib.PEM_write_bio_CX_SEED_REPORT(bio.bio, self._asn1):
                raise ValueError("Could not create PEM")
            return bio.data.decode()
