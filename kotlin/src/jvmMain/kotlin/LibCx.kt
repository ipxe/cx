package org.ipxe.cx
import java.util.UUID

internal class CxJni {

    companion object {

	init {
	    System.loadLibrary("cxjni")
	}

	@JvmStatic
	external fun genSeedLen(type: Int): Int

	@JvmStatic
	external fun genMaxIterations(type: Int): Int

	@JvmStatic
	external fun genInstantiate(type: Int, seed: ByteArray): Long

	@JvmStatic
	external fun genIterate(handle: Long): UUID?

	@JvmStatic
	external fun genUninstantiate(handle: Long)
    }

}

internal actual typealias LibCx = CxJni
