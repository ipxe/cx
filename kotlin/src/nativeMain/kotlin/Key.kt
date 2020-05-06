package org.ipxe.cx

import kotlinx.cinterop.*
import openssl.EVP_PKEY
import openssl.EVP_PKEY_free
import openssl.d2i_PUBKEY
import openssl.i2d_PUBKEY
import openssl.openssl_free

/**
 * Invalid public or private key
 *
 * The JVM implementation uses [java.security.InvalidKeyException].
 * There is no existing multiplatform equivalent.
 */
public actual class InvalidKeyException() : IllegalArgumentException()

/**
 * A key specification
 */
public abstract class KeySpec(
    /** DER representation */
    public val encoded: ByteArray
) {

    /** Get DER representation */
    public fun getEncoded() = encoded
}

/** A public key specification */
public actual class PublicKeySpec actual constructor(
    /** DER representation */
    encoded: ByteArray
) : KeySpec(encoded)

/**
 * An OpenSSL key
 *
 * This exists as an interface (rather than an abstract class) solely
 * to allow the JVM implementation to use the
 * [java.security.PublicKey] and [java.security.PrivateKey]
 * typealiases.
 */
public interface OpenSSLKeyInterface {

    /** OpenSSL EVP_PKEY pointer */
    public val pkey: CPointer<EVP_PKEY>?

    /** Get DER representation */
    fun getEncoded(): ByteArray
}

/** A public key */
public actual interface PublicKey : OpenSSLKeyInterface

/** A private key */
public actual interface PrivateKey : OpenSSLKeyInterface

/**
 * A key pair
 *
 * This exists as a platform-specific class solely to allow the JVM
 * implementation to use the [java.security.KeyPair] typealias.
 */
public actual class KeyPair actual constructor(
    /** Public key */
    public val publicKey: PublicKey,
    /** Private key */
    public val privateKey: PrivateKey
) {

    /** Get public key */
    actual fun getPublic() = publicKey

    /** Get private key */
    actual fun getPrivate() = privateKey
}

/** An OpenSSL key */
public abstract class OpenSSLKey(
    /**
     * OpenSSL EVP_PKEY pointer
     *
     * The object takes ownership of the EVP_PKEY pointer reference
     * and will eventually free it.  The caller must use
     * EVP_PKEY_up_ref if the caller needs to retain a separate
     * reference.
     */
    override val pkey: CPointer<EVP_PKEY>?
) : OpenSSLKeyInterface {

    /* Free EVP_PKEY when object is destroyed */
    protected fun finalize() = pkey?.let { EVP_PKEY_free(pkey) }
}

/** An OpenSSL public key */
public class OpenSSLPublicKey(
    /** OpenSSL EVP_PKEY pointer */
    pkey: CPointer<EVP_PKEY>?
) : OpenSSLKey(pkey), PublicKey {

    /** Construct from DER representation */
    public constructor(
        /** DER representation */
        encoded: ByteArray
    ) : this(
        memScoped {
            encoded.usePinned { pinnedEncoded ->
                val tmp = alloc<CPointerVar<UByteVar>>()
                tmp.value = pinnedEncoded.addressOf(0).reinterpret()
                d2i_PUBKEY(null, tmp.ptr, encoded.size.convert())
                    ?: throw InvalidKeyException()
            }
        }
    )

    /** Construct from key specification */
    public constructor(
        /** Key specification */
        spec: PublicKeySpec
    ) : this(spec.encoded)

    /** Get DER representation */
    public override fun getEncoded(): ByteArray {
        memScoped {
            val der = alloc<CPointerVar<UByteVar>>()
            val len = i2d_PUBKEY(pkey, der.ptr)
            len < 0 && throw IllegalArgumentException()
            try {
                return der.value!!.readBytes(len)
            } finally {
                openssl_free(der.value)
            }
        }
    }
}

/**
 * Construct public key from specification
 *
 * @param spec Public key specification
 * @return Public key
 */
actual fun publicKeyOf(spec: PublicKeySpec): PublicKey = OpenSSLPublicKey(spec)
