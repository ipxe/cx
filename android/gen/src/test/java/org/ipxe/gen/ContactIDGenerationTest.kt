package org.ipxe.gen

import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.Parameterized
import org.spongycastle.util.encoders.Hex
import java.util.*
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/*
 * Converts a ByteArray into a hexidecimal string, formatted to match the NIST examples from:
 * https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/CTR_DRBG_withDF.pdf
 */
fun toHexString(bytes: ByteArray): String {
    return Hex.toHexString(bytes).chunked(8).joinToString(" ").toUpperCase()
}


class CXIdTestVector(
    val type: GeneratorType,
    val count: Int,
    seed: String,
    expectedFirst: String,
    expectedLast: String
) {
    val expectedFirst: UUID = UUID.fromString(expectedFirst)
    val expectedLast: UUID = UUID.fromString(expectedLast)
    val seed: ByteArray = Hex.decode(seed)
}


/**
 * Perform Contact Identifier iteration tests.
 *
 * Note: These tests match the `cx_id_test` function from `gen_test.c` and the corresponding
 * `gen_type<x>_test<n>.c` data files from the reference implementation.
 */
@RunWith(value = Parameterized::class)
class ContactIDGeneratorTest(private val name: String, private val tv: CXIdTestVector) {
    @Test
    fun `Contact Identifier iteration sequence`() {
        val gen = ContactIDGenerator.ofType(tv.type, tv.seed)

        // Generate the first Contact Identifier
        val idFirst = gen.iterate()
        assertEquals(tv.expectedFirst, idFirst)

        // Generate and discard the intermediate Contact Identifiers
        for (i in 0 until tv.count - 2) {
            gen.iterate()
        }

        // Generate the first Contact Identifier
        val idLast = gen.iterate()
        assertEquals(tv.expectedLast, idLast)

        // Check that generator refuses to iterate further
        assertFailsWith(GeneratorExhaustedException::class) {
            gen.iterate()
        }
    }

    companion object {
        @JvmStatic
        @Parameterized.Parameters(name = "{index}: {0}")
        fun data(): Iterable<Array<Any>> {
            return arrayListOf(
                arrayOf(
                    "AES-128 (natural)",
                    CXIdTestVector(
                        Type1,
                        2048,
                        "00010203 04050607 08090a0b 0c0d0e0f 10111213 14151617",
                        "aeaa0891-03d8-400c-beb0-046a2dab8522",
                        "61f3d4b4-844f-4516-9651-d2d2cf8af346"
                    )
                ),
                arrayOf(
                    "AES-128 (random)",
                    CXIdTestVector(
                        Type1,
                        2048,
                        "04b4e866 ac9e39c9 2c2d8afe 68cb7496 0bf9ccfc 9411e3db",
                        "e3e6c75a-5b7b-43d2-973a-b8c3c55b27e4",
                        "eb61bab8-b7b7-45e6-aaf8-8b3b6ac3c146"
                    )
                ),
                arrayOf(
                    "AES-256 (natural)",
                    CXIdTestVector(
                        Type2,
                        2048,
                        """
                        00010203 04050607 08090A0B 0C0D0E0F 10111213 14151617
                        18191A1B 1C1D1E1F 20212223 24252627 28292A2B 2C2D2E2F
                        """,
                        "7ad7f061-2b3e-4f3e-91f8-b3517deca58d",
                        "e8a1b8c3-3de6-4198-8650-2b4188aef12e"
                    )
                ),
                arrayOf(
                    "AES-256 (random)",
                    CXIdTestVector(
                        Type2,
                        2048,
                        """
                        D1ADD791 E82E98F2 6CDABFB1 2E30769F 5C5F86C9 FEEB1826
                        2B7FAC77 548B49C4 65D20C76 0120CF35 213493BA CEF7535A
                        """,
                        "e46c75f2-6968-4655-b751-3738547b5cc9",
                        "9d9b113a-94d4-4d0c-9ea6-540db7bb8fb8"
                    )
                )
            ).toList()
        }
    }
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