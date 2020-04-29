package org.ipxe.cx

import com.benasher44.uuid.Uuid

internal expect class LibCx {

    companion object {
	fun genSeedLen(type: Int): Int;
	fun genMaxIterations(type: Int): Int;
	fun genInstantiate(type: Int, seed: ByteArray): Long
	fun genIterate(handle: Long): Uuid?
	fun genUninstantiate(handle: Long)
    }

}
