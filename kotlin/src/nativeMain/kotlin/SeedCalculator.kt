package org.ipxe.cx

import kotlinx.cinterop.*
import libcx.cx_seedcalc

/**
 * Seed calculator
 *
 * @param type Generator type
 * @param preseed Preseed value
 * @param key Preseed verification key
 */
public actual class SeedCalculator(
    type: GeneratorType,
    preseed: ByteArray,
    key: PublicKey
) : SeedCalculatorBase(type, preseed, key) {

    /** Seed value */
    public override val seed = ByteArray(type.seedLength)

    init {
        seed.usePinned { pinnedSeed ->
            if (cx_seedcalc(type.value.convert(), preseed.toCValues(),
                            preseed.size.convert(), key.pkey,
                            pinnedSeed.addressOf(0)) == 0) {
                throw UnknownGeneratorTypeException()
            }
        }
    }
}
