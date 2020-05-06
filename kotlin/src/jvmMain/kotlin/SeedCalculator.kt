package org.ipxe.cx

import java.security.PublicKey

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
        val drbg = GeneratorDrbg.fromType(type).instantiate(preseed, key)
        drbg.generate(seed, null, false)
    }
}
