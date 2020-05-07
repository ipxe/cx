package org.ipxe.cx

import com.benasher44.uuid.uuidOf
import java.util.UUID
import kotlin.experimental.and
import kotlin.experimental.or
import org.spongycastle.crypto.engines.AESEngine
import org.spongycastle.crypto.prng.EntropySource
import org.spongycastle.crypto.prng.drbg.CTRSP800DRBG
import org.spongycastle.crypto.prng.drbg.SP80090DRBG

/**
 * Generator entropy source
 *
 * @param entropy Entropy input
 */
private class GeneratorEntropy(entropy: ByteArray) : EntropySource {

    /** Unconsumed entropy */
    private var unusedEntropy = entropy

    /** Size of unconsumed entropy (in bits) */
    public override fun entropySize() = unusedEntropy.size * 8

    /** Consume entropy */
    public override fun getEntropy(): ByteArray {
        val entropy = unusedEntropy
        unusedEntropy = ByteArray(0)
        return entropy
    }

    /** Support for prediction resistance (always false) */
    public override fun isPredictionResistant() = false
}

/**
 * Generator DRBG types
 *
 */
internal enum class GeneratorDrbg(
    /** Generator type */
    public val type: GeneratorType,
    /** Seed value entropy input length */
    private val entropyLength: Int,
    /** DRBG instantiator
     *
     * @param entropy Entropy input
     * @param personal Personalization string
     * @param nonce Nonce
     * @return DRBG instance
     */
    private val instantiator: (
        entropy: EntropySource,
        personal: ByteArray?,
        nonce: ByteArray
    ) -> SP80090DRBG
) {
    /** Type 1: CTR_DRBG using AES-128 with DF */
    Aes128Ctr2048(
        GeneratorType.Aes128Ctr2048, 16, {
            entropy, personal, nonce ->
            CTRSP800DRBG(AESEngine(), 128, 128, entropy, personal, nonce)
        }
    ),
    /** Type 2: CTR_DRBG using AES-256 with DF */
    Aes256Ctr2048(
        GeneratorType.Aes256Ctr2048, 32, {
            entropy, personal, nonce ->
            CTRSP800DRBG(AESEngine(), 256, 256, entropy, personal, nonce)
        }
    );

    /**
     * Instantiate DRBG
     *
     * @param seed Seed value
     * @param key Public key
     * @return DRBG instance
     */
    public fun instantiate(
        seed: ByteArray,
        key: PublicKey?
    ): SP80090DRBG {
        val entropy = GeneratorEntropy(seed.copyOfRange(0, entropyLength))
        val nonce = seed.copyOfRange(entropyLength, type.seedLength)
        return instantiator(entropy, key?.getEncoded(), nonce)
    }

    companion object {

        /** Generator DRBG types indexed by generator type */
        private val by_type = values().associateBy { it.type }

        /**
         * Get generator DRBG type from generator type
         *
         * @param type Generator type
         * @return Generator DRBG type
         */
        public fun fromType(type: GeneratorType) =
            by_type[type] ?: throw UnknownGeneratorTypeException()
    }
}

/**
* Generator
*
* @param type Generator type
* @param seed Seed value
*/
public actual class Generator(
    type: GeneratorType,
    seed: ByteArray
) : GeneratorBase(type, seed) {

    /** DRBG instance */
    private val drbg: SP80090DRBG =
        GeneratorDrbg.fromType(type).instantiate(seed, null)

    /** Generate next contact ID */
    protected override fun generate(): UUID {
        val id = ByteArray(CX_ID_BYTES)

        /* Generate raw data */
        drbg.generate(id, null, false)

        /* Set reserved bits for an RFC 4122 version 4 UUID */
        id[CX_ID_VARIANT_BYTE] = (
            id[CX_ID_VARIANT_BYTE] and
            CX_ID_VARIANT_MASK or
            CX_ID_VARIANT_RFC4122
        )
        id[CX_ID_VERSION_BYTE] = (
            id[CX_ID_VERSION_BYTE] and
            CX_ID_VERSION_MASK or
            CX_ID_VERSION_V4
        )

        return uuidOf(id)
    }
}
