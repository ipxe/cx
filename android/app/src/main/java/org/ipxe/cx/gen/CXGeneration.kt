package org.ipxe.cx.gen

import org.spongycastle.crypto.prng.EntropySource
import org.spongycastle.crypto.prng.EntropySourceProvider


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