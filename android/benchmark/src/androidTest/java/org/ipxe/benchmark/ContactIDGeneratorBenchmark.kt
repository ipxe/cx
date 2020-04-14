package org.ipxe.benchmark

import androidx.benchmark.junit4.BenchmarkRule
import androidx.benchmark.junit4.measureRepeated
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.ipxe.gen.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.spongycastle.util.encoders.Hex


/**
 * Benchmark Contact Identifier generation on a physical Android device.
 */
@RunWith(AndroidJUnit4::class)
class ContactIDGeneratorBenchmark {

    @get:Rule
    val benchmarkRule = BenchmarkRule()

    @Test
    fun type1FullIterationSequence() {
        benchmarkRule.measureRepeated {
            val gen = runWithTimingDisabled {
                cxGen1(
                    Hex.decode(
                        "00010203 04050607 08090a0b 0c0d0e0f 10111213 14151617"
                    )
                )
            }
            for (i in 0 until Type1.maxIterations) {
                gen.iterate()
            }
        }
    }

    @Test
    fun type2FullIterationSequence() {
        benchmarkRule.measureRepeated {
            val gen = runWithTimingDisabled {
                cxGen2(
                    Hex.decode(
                        """
                        00010203 04050607 08090A0B 0C0D0E0F 10111213 14151617
                        18191A1B 1C1D1E1F 20212223 24252627 28292A2B 2C2D2E2F
                        """
                    )
                )
            }
            for (i in 0 until Type2.maxIterations) {
                gen.iterate()
            }
        }
    }
}
