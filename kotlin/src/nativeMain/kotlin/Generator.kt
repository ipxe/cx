package org.ipxe.cx

import com.benasher44.uuid.Uuid
import com.benasher44.uuid.uuidOf
import kotlinx.cinterop.*
import libcx.cx_contact_id
import libcx.cx_gen_instantiate
import libcx.cx_gen_iterate
import libcx.cx_gen_uninstantiate
import libcx.cx_generator

/**
* Generator
*
* @param type Generator type
* @param seed Seed value
*/
public actual class Generator(
    type: GeneratorType,
    seed: ByteArray
) : GeneratorBase(type, seed) {

    /** C library generator */
    private val gen: CPointer<cx_generator>? =
        cx_gen_instantiate(
            type.value.convert(), seed.toCValues(), seed.size.convert()
        ) ?: throw UnknownGeneratorTypeException()

    /** Generate next contact ID */
    protected override fun generate(): Uuid {
        memScoped {
            val id = alloc<cx_contact_id>()
            cx_gen_iterate(gen, id.ptr) == 0 && throw IllegalStateException()
            return uuidOf(id.ptr.readBytes(CX_ID_BYTES))
        }
    }

    /* Uninstantiate generator when object is destroyed */
    protected fun finalize() = gen?.let { cx_gen_uninstantiate(gen) }
}
