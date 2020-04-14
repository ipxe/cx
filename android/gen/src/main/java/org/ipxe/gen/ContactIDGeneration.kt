package org.ipxe.gen

import org.spongycastle.crypto.engines.AESEngine
import org.spongycastle.crypto.prng.EntropySource
import org.spongycastle.crypto.prng.EntropySourceProvider
import org.spongycastle.crypto.prng.drbg.CTRSP800DRBG
import java.nio.ByteBuffer
import java.util.*
import kotlin.experimental.and
import kotlin.experimental.inv
import kotlin.experimental.or


private const val UUID_BYTES_LEN = 16


/**
 * Representation of Generator Types as specified by section 3.1 of the CX specification.
 * @param keySize [Int] AES cypher key size (bits).
 * @param securityStrength [Int] Required security strength (bits).
 * @param entropyInputLen [Int] Required entropy input length (bits).
 * @param nonceLen [Int] Required nonce length (bits).
 * @param maxIterations [Int] Maximum number of permitted generator iterations.
 */
sealed class GeneratorType(
    val keySize: Int,
    val securityStrength: Int,
    val entropyInputLen: Int,
    val nonceLen: Int,
    val maxIterations: Int
) {
    val seedLen: Int = entropyInputLen + nonceLen
}

object Type1 : GeneratorType(
    128, 128, 16, 8, 2048
)

object Type2 : GeneratorType(
    256, 256, 32, 16, 2048
)



/**
 * Contact Identifier Generator as described by section 3 of the CX specification.
 *
 * Example usage:
 *
 * ```
 * val gen = ContactIDGenerator.ofType(
 *   Type1,
 *   byteArrayOf(
 *     0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
 *     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
 *     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
 *   )
 * )
 *
 * val firstID = gen.iterate()
 * ```
 */
class ContactIDGenerator internal constructor(private val rng: FixedDRBG) {
    // Instantiated via one of the public constructor functions e.g. [ofType] to ensure the correct
    // ownership and usage of the underlying generator and seed values (hence the internal constructor)
    companion object {
        fun ofType(type: GeneratorType, seed: ByteArray): ContactIDGenerator {
            val rng = FixedDRBG(type, Seed.fromBytes(type, seed))
            return ContactIDGenerator(rng)
        }

        fun ofType(type: GeneratorType, seed: Seed): ContactIDGenerator {
            assert(type == seed.type)
            val rng = FixedDRBG(type, seed)
            return ContactIDGenerator(rng)
        }
    }

    /**
     * Generate the next Contact Identifier.
     *
     * @throws [GeneratorExhaustedException]
     */
    fun iterate(): UUID {
        // Generate next bytes to base Contact Identifier on
        val bytes = ByteArray(UUID_BYTES_LEN)
        rng.generate(bytes)
        // Set fixed bits for version 4 UUID
        bytes[8] = (bytes[8] and 0xc0.toByte().inv()).or(0x80.toByte()) // clock_seq_hi_and_reserved
        bytes[6] = (bytes[6] and 0xf0.toByte().inv()).or(0x40.toByte()) // time_hi_and_version
        // Instantiate a Java UUID - no direct constructor from a single ByteArray is provided,
        // instead the API for manual UUID instantiation requires specifying two Long values
        val buf = ByteBuffer.wrap(bytes) // Wrap in a ByteBuffer to avoid manual parsing of Longs
        val high = buf.long // e.g. side-effectful buf.getLong() advances internal state of buf
        val low = buf.long
        return UUID(high, low)
    }
}


/**
 * Represents a seed value constructed from some fixed entropy and a nonce value as described in
 * section 3 of the CX specification. The primary role of this class is to ensure the invariants
 * specified for seed length, entropy length and nonce length are upheld.
 */
class Seed internal constructor(
    val type: GeneratorType,
    val entropyInput: ByteArray,
    val nonce: ByteArray
) {
    init {
        if (entropyInput.size != type.entropyInputLen) {
            throw IllegalArgumentException(
                "entropyInput length must match the value specified by the Generator Type"
            )
        }
        if (nonce.size != type.nonceLen) {
            throw IllegalArgumentException(
                "nonce length must match the value specified by the Generator Type"
            )
        }
    }

    companion object {
        /**
         * Instantiate a [Seed] from a complete seed value from which [entropyInput] and [nonce]
         * will be parsed according to the given [type].
         */
        fun fromBytes(type: GeneratorType, seed: ByteArray): Seed {
            if (seed.size != type.seedLen) {
                throw IllegalArgumentException(
                    "seed length must match the value specified by the Generator Type"
                )
            }
            return Seed(
                type,
                seed.copyOfRange(0, type.entropyInputLen),
                seed.copyOfRange(type.entropyInputLen, type.seedLen)
            )
        }
    }
}


class GeneratorExhaustedException(message: String) : Exception(message)


/**
 * DRBG with a fixed entropy source and maximum iteration limit as specified by section 3 of the
 * CX specification.
 */
class FixedDRBG internal constructor(
    val type: GeneratorType,
    private val seed: Seed
) {
    private val entropySource =
        FixedEntropySourceProvider(seed.entropyInput).get(seed.entropyInput.size * 8)
    private var currentIterations = 0

    private val rng = CTRSP800DRBG(
        AESEngine(),
        type.securityStrength,
        type.securityStrength,
        entropySource,
        null,
        seed.nonce
    )

    /**
     * Populate a passed in array with randomly generated data.
     *
     * @throws [GeneratorExhaustedException] If [maxIterations] limit has been reached.
     */
    fun generate(output: ByteArray) {
        if (currentIterations >= type.maxIterations) {
            throw GeneratorExhaustedException("${type.maxIterations} iteration limit reached")
        }
        currentIterations += 1
        rng.generate(output, null, false)
    }
}


class EntropySourceExhaustedException(message: String) : Exception(message)


/**
 * Generates 'entropy' from a pre-determined sequence of bytes. Intended to satisfy the
 * [EntropySource] interface required by the SpongyCastle PRNGs whilst with a pre-computed
 * entropy input as per the CX specification.
 */
class FixedEntropySourceProvider constructor(private val bytes: ByteArray) : EntropySourceProvider {

    /**
     * Create an [EntropySource] that 'generates' entropy as sequential [bitsRequired] size chunks
     * from [bytes].
     *
     * @param bitsRequired [Int] Number of bits to return in each generated 'chunk' of entropy.
     * @throws [IllegalArgumentException] If [bitsRequired] is > than the available number of bits.
     */
    override fun get(bitsRequired: Int): EntropySource {
        val nBytes = bitsRequired / 8
        if (nBytes > bytes.size) {
            throw IllegalArgumentException(
                "bitsRequired must be less than the number of bits available in the source data: "
                        + "bitsRequired=$bitsRequired, available=${bytes.size * 8}"
            )
        }

        return object : EntropySource {
            var nextBytesIndex = 0
            override fun isPredictionResistant(): Boolean {
                return false
            }

            /**
             * @throws [EntropySourceExhaustedException]
             */
            override fun getEntropy(): ByteArray {
                val rv = ByteArray(nBytes)
                try {
                    System.arraycopy(bytes, nextBytesIndex, rv, 0, rv.size)
                } catch (e: IndexOutOfBoundsException) {
                    throw EntropySourceExhaustedException("Available entropy bytes already requested")
                }
                nextBytesIndex += nBytes
                return rv
            }

            override fun entropySize(): Int {
                return bitsRequired
            }
        }
    }
}