package org.ipxe.cx

/** Invalid public or private key */
public expect class InvalidKeyException

/**
 * A public key specification
 *
 * @param encoded DER representation
 */
public expect class PublicKeySpec(encoded: ByteArray) {

    /** Get DER representation */
    public fun getEncoded(): ByteArray
}

/** A public key */
public expect interface PublicKey {

    /** Get canonical DER representation */
    public fun getEncoded(): ByteArray
}

/** A private key */
public expect interface PrivateKey {

    /** Get canonical DER representation */
    public fun getEncoded(): ByteArray
}

/** A key pair */
public expect class KeyPair(publicKey: PublicKey, privateKey: PrivateKey) {

    /** Get public key */
    public fun getPublic(): PublicKey

    /** Get private key */
    public fun getPrivate(): PrivateKey
}

/**
 * Construct public key from specification
 *
 * @param spec Public key specification
 * @return Public key
 */
public expect fun publicKeyOf(spec: PublicKeySpec): PublicKey
