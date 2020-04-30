package org.ipxe.cx

import com.benasher44.uuid.Uuid

public enum class GeneratorType(val value: Int) {
    Aes128Ctr2048(1),
    Aes256Ctr2048(2);

    val seedLength = LibCx.genSeedLen(value)

    val maxIterations = LibCx.genMaxIterations(value)

}

public class Generator(
    val type: GeneratorType,
    val seed: ByteArray
) : Iterator<Uuid> {

    private val handle = LibCx.genInstantiate(type.value, seed)

    var remaining = type.maxIterations
	private set

    init {
	if (remaining == 0) {
	    throw IllegalArgumentException("Invalid generator type")
	}
	if (handle == 0L) {
	    throw IllegalStateException("Failed to construct generator")
	}
    }

    override fun hasNext() = remaining != 0

    override fun next() : Uuid {
	val id = LibCx.genIterate(handle) ?: throw NoSuchElementException()
	remaining--
	return id
    }

    protected fun finalize() {
	LibCx.genUninstantiate(handle)
    }

}
