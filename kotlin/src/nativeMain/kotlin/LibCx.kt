package org.ipxe.cx

import interop.*
import kotlinx.cinterop.*
import com.benasher44.uuid.*

internal actual class LibCx {

    actual companion object {

	actual fun genSeedLen(type: Int): Int {
	    return cx_gen_seed_len(type.convert()).convert()
	}

	actual fun genMaxIterations(type: Int): Int {
	    return cx_gen_max_iterations(type.convert()).convert()
	}

	actual fun genInstantiate(type: Int, seed: ByteArray): Long {
	    return cx_gen_instantiate(type.convert(), seed.toCValues(),
				      seed.size.convert()).toLong()
	}

	actual fun genIterate(handle: Long): Uuid? {
	    memScoped {
		val id = alloc<cx_contact_id>()
		if (cx_gen_iterate(handle.toCPointer(), id.ptr) == 0) {
		    return null
		}
		return uuidOf(id.ptr.readBytes(cx_contact_id.size.convert()))
	    }
	}

	actual fun genUninstantiate(handle: Long) {
	    cx_gen_uninstantiate(handle.toCPointer())
	}

    }

}
