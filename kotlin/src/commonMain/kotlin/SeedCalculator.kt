package org.ipxe.cx

/**
* Seed calculator base class
*
*/
public abstract class SeedCalculatorBase(
    /** Generator type */
    public val type: GeneratorType,
    /** Preseed value */
    public val preseed: ByteArray,
    /** Preseed verification key */
    public val key: PublicKey
) {

    init {
        preseed.size == type.seedLength || throw IncorrectSeedLengthException()
    }

    /** Seed value */
    public abstract val seed: ByteArray
}

public expect class SeedCalculator : SeedCalculatorBase
