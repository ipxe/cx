package org.ipxe.cx

import com.benasher44.uuid.Uuid

/** UUID length */
internal const val CX_ID_BYTES = 16

/** UUID variant is in MSBits of clk_seq_hi_and_reserved */
internal const val CX_ID_VARIANT_BYTE = 8

/** UUID variant byte mask */
internal const val CX_ID_VARIANT_MASK: Byte = 0x3f

/** UUID variant byte value */
internal const val CX_ID_VARIANT_RFC4122: Byte = -0x80 /* Don't ask */

/** UUID version is in MSBits of time_hi_and_version */
internal const val CX_ID_VERSION_BYTE = 6

/** UUID version byte mask */
internal const val CX_ID_VERSION_MASK: Byte = 0x0f

/** UUID version byte value */
internal const val CX_ID_VERSION_V4: Byte = 0x40

/** Unknown Generator Type exception */
public class UnknownGeneratorTypeException() : UnsupportedOperationException()

/** Incorrect Seed Value length exception */
public class IncorrectSeedLengthException() : IllegalArgumentException()

/**
 * Generator type
 *
 */
public enum class GeneratorType(
    /** Numeric generator type value */
    public val value: Int,
    /** Seed value length (in bytes) */
    public val seedLength: Int,
    /** Maximum number of iterations */
    public val maxIterations: Int
) {
    /** Type 1: CTR_DRBG using AES-128 with DF */
    Aes128Ctr2048(1, 24, 2048),
    /** Type 2: CTR_DRBG using AES-256 with DF */
    Aes256Ctr2048(2, 48, 2048);

    companion object {

        /** Generator types indexed by numeric generator type value */
        private val by_value = values().associateBy { it.value }

        /**
         * Get generator type from numeric type value
         *
         * @param value Numeric generator type value
         * @return Generator type
         * @throws UnknownGeneratorTypeException Unknown generator type value
         */
        public fun fromValue(value: Int) =
            by_value[value] ?: throw UnknownGeneratorTypeException()
    }
}

/**
 * Generator base class
 *
 */
public abstract class GeneratorBase(
    /** Generator type */
    public val type: GeneratorType,
    /** Seed value */
    public val seed: ByteArray
) : Iterator<Uuid> {

    init {
        seed.size == type.seedLength || throw IncorrectSeedLengthException()
    }

    /** Number of iterations remaining */
    public var remaining = type.maxIterations
    private set

    /** Check for remaining iterations */
    public override fun hasNext() = remaining > 0

    /** Generate next contact ID (with no iteration limit check) */
    protected abstract fun generate(): Uuid

    /** Generate next contact ID */
    public override fun next(): Uuid {

        /* Prevent generation beyond maximum iteration count */
        remaining > 0 || throw NoSuchElementException()
        remaining--

        /* Generate ID */
        return generate()
    }
}

public expect class Generator : GeneratorBase
