package org.ipxe.cx.gen

import org.junit.Test
import org.spongycastle.util.encoders.Hex
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/*
 * Converts a ByteArray into a hexidecimal string, formatted to match the NIST examples from:
 * https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/CTR_DRBG_withDF.pdf
 */
fun toHexString(bytes: ByteArray): String {
    return Hex.toHexString(bytes).chunked(8).joinToString(" ").toUpperCase()
}


class TestFixedEntropySourceProvider {
    @Test
    fun `EntropySource getEntropy returns correct bits from source data`() {
        val data = Hex.decode(
            """
                                                00010203 04050607
            08090A0B 0C0D0E0F 10111213 14151617 18191A1B 1C1D1E1F
            """
        )
        val eSource = FixedEntropySourceProvider(data).get(128)

        assertEquals(128, eSource.entropySize())

        val first128Bits = "00010203 04050607 08090A0B 0C0D0E0F"
        val second128Bits = "10111213 14151617 18191A1B 1C1D1E1F"

        // Kotlin-Java interop property acces syntax causes eSource.entropy -> eSource.getEntropy()
        // may be misleading as it does not convey the state change of advancing the internal buffer
        assertEquals(first128Bits, toHexString(eSource.entropy))
        assertEquals(second128Bits, toHexString(eSource.entropy))
    }

    @Test
    fun `EntropySource getEntropy throws if source data exhausted`() {
        val data = Hex.decode(
            """
                                                00010203 04050607
            08090A0B 0C0D0E0F 10111213 14151617 18191A1B 1C1D1E1F
            """
        )
        val eSource = FixedEntropySourceProvider(data).get(256)

        // "Use up" available data
        eSource.entropy

        assertFailsWith(EntropySourceExhaustedException::class) {
            eSource.entropy
        }
    }

    @Test
    fun `get throws if more bits requested than in source data`() {
        val data = Hex.decode("00010203")

        assertFailsWith(IllegalArgumentException::class) {
            val eSource = FixedEntropySourceProvider(data).get(256)
        }
    }
}