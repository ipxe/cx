package org.ipxe.cx

import java.security.InvalidKeyException
import java.security.KeyFactory
import java.security.KeyPair
import java.security.NoSuchAlgorithmException
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.X509EncodedKeySpec
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers

/** Invalid public or private key */
public actual typealias InvalidKeyException = InvalidKeyException

/** A public key specification */
public actual typealias PublicKeySpec = X509EncodedKeySpec

/** A public key */
public actual typealias PublicKey = PublicKey

/** A private key */
public actual typealias PrivateKey = PrivateKey

/** A key pair */
public actual typealias KeyPair = KeyPair

/**
 * A factory for [KeyFactory] instances
 *
 * The use of ASN.1 object identifiers (OIDs) to specify an encryption
 * algorithm has been standardised since at least 1988.  OpenSSL
 * handles all of this entirely autonomously: the appropriate
 * algorithm is automatically selected based on the
 * algorithmIdentifier embedded within the data structure being
 * processed.
 *
 * Java instead requires the calling code to select an explicit
 * algorithm before instantiating the objects capable of performing
 * signing or verification.  This makes zero sense when dealing with
 * verification, since the calling code has no a priori knowledge of
 * the algorithm used to sign the data that has not yet been received.
 *
 * Java provides an [X509EncodedKeySpec] object representing the
 * SubjectPublicKeyInfo structure, which contains the OID that
 * identifies the relevant algorithm.  Java 7 conveniently provides no
 * way to extract the OID from this structure, requiring the use of an
 * external library such as BouncyCastle just to get as far as
 * extracting the algorithmIdentifier.
 *
 * Mapping the algorithmIdentifier OID to the string literal required
 * by Java's [KeyFactory.getInstance] method is, of course, left as an
 * exercise for every new piece of code that ever wants to perform
 * signature verification.  Judging by the example code found all over
 * the web, most Java programmers seem not to bother with this step
 * and instead simply hardcode in an assumption that everything is
 * going to use RSA.
 *
 * Entertainingly, calling [KeyFactory.getInstance] with the string
 * representation of the OID does seem to return an appropriate
 * instance, but only if the *wrong* OID is used.  Calling
 * [KeyFactory.getInstance]`("1.2.840.113549.1.1")` returns an RSA
 * KeyFactory.  Calling [KeyFactory.getInstance]`("1.2.840.113549.1.1.1")`
 * (which is the correct OID for rsaEncryption) throws a
 * [NoSuchAlgorithmException].
 */
internal object KeyFactoryFactory {

    private val keyFactories =
        emptyMap<ASN1ObjectIdentifier, KeyFactory>().withDefault {
            algorithm -> KeyFactory.getInstance(
                when (algorithm) {
                    PKCSObjectIdentifiers.rsaEncryption -> "RSA"
                    X9ObjectIdentifiers.id_dsa -> "DSA"
                    /* Fall back to attempting a lookup by OID string */
                    else -> algorithm.getId()
                }
            )
        }

    /** Get key factory by ASN.1 OID */
    public fun getKeyFactory(oid: ASN1ObjectIdentifier) =
        keyFactories.getValue(oid)

    /** Get key factory by algorithmIdentifier */
    public fun getKeyFactory(algid: AlgorithmIdentifier) =
        getKeyFactory(algid.getAlgorithm())

    /** Get key factory by SubjectPublicKeyInfo */
    public fun getKeyFactory(spki: SubjectPublicKeyInfo) =
        getKeyFactory(spki.getAlgorithm())

    /** Get key factory by X509EncodedKeySpec */
    public fun getKeyFactory(spec: X509EncodedKeySpec) =
        getKeyFactory(SubjectPublicKeyInfo.getInstance(spec.encoded))
}

/**
 * Construct public key from specification
 *
 * @param spec Public key specification
 * @return Public key
 */
public actual fun publicKeyOf(spec: X509EncodedKeySpec) =
    KeyFactoryFactory.getKeyFactory(spec).generatePublic(spec)
