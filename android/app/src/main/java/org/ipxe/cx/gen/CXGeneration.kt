package org.ipxe.cx.gen

import org.spongycastle.crypto.prng.EntropySource
import org.spongycastle.crypto.prng.EntropySourceProvider

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
                "bitsRequired must be less than the number of bits available in the source data: " +
                        "bitsRequired=$bitsRequired, available=${bytes.size * 8}"
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