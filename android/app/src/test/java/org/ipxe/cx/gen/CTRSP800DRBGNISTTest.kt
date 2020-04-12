package org.ipxe.cx.gen

import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.Parameterized
import org.spongycastle.crypto.engines.AESEngine
import org.spongycastle.crypto.prng.drbg.CTRSP800DRBG
import org.spongycastle.util.encoders.Hex
import kotlin.test.assertEquals


/**
 * NIST tests for AES-128/AES-256 CTR_DRBG with DF
 *
 * Note: These are non-comprehensive tests and exist to demonstrate the usage of the SpongyCastle
 * SP80090DRBG implementation in compliance with the CX specification and reference implementation.
 *
 * These are the first tests for each strength (denoted by "Requested Security Strength = ") from
 *
 * https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/CTR_DRBG_withDF.pdf
 */
@RunWith(value = Parameterized::class)
class NISTTest(private val name: String, private val tv: NISTTestVector) {
    @Test
    fun `First random value`() {

        // Initialise DRBG directly
        val d = CTRSP800DRBG(
            AESEngine(),
            tv.type.keySize,
            tv.type.securityStrength,
            tv.eSource,
            null,
            tv.nonce
        )

        // Generate a single random value
        val output = ByteArray(tv.expected.size)
        d.generate(output, null, false)

        assertEquals(toHexString(tv.expected), toHexString(output))
    }

    companion object {
        @JvmStatic
        @Parameterized.Parameters(name = "{index}: {0}")
        fun data(): Iterable<Array<Any>> {
            return arrayListOf(
                arrayOf(
                    "NIST AES-128 CTR_DRBG with DF",
                    NISTTestVector(
                        Type1,
                        """
                                                            00010203 04050607
                        08090A0B 0C0D0E0F 10111213 14151617 18191A1B 1C1D1E1F
                        """,
                        "20212223 24252627",
                        """
                                                            8CF59C8C F6888B96
                        EB1C1E3E 79D82387 AF08A9E5 FF75E23F 1FBCD455 9B6B997E
                        """
                    )
                ),
                arrayOf(
                    "NIST AES-256 CTR_DRBG with DF",
                    NISTTestVector(
                        Type2,
                        """
                        00010203 04050607 08090A0B 0C0D0E0F 10111213 14151617
                        18191A1B 1C1D1E1F 20212223 24252627 28292A2B 2C2D2E2F
                        """,
                        "20212223 24252627 28292A2B 2C2D2E2F",
                        """
                                                            E686DD55 F758FD91
                        BA7CB726 FE0B573A 180AB674 39FFBDFE 5EC28FB3 7A16A53B
                        """
                    )
                )
            ).toList()
        }
    }
}


class NISTTestVector(
    val type: GeneratorType,
    entropy: String,
    nonce: String,
    expected: String
) {
    val nonce: ByteArray = Hex.decode(nonce)
    val expected: ByteArray = Hex.decode(expected)
    private val entropyBytes = Hex.decode(entropy)
    val eSource = FixedEntropySourceProvider(entropyBytes).get(entropyBytes.size * 8)
}
