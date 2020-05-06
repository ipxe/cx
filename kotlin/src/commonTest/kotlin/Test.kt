package org.ipxe.cx

import kotlin.test.*

fun ByteArray.toHexString() = joinToString("") { it.toString(16) }

fun assertHexEquals(
    expected: ByteArray,
    actual: ByteArray,
    message: String? = null
) {
    /* Assert hex string equality, since:
     *
     * - assertEquals() is incapable of comparing array contents
     * - there is no assertArrayEquals() or assertContentEquals()
     * - using the hex strings gives us meaningful failure messages
     *
     */
    assertEquals(expected.toHexString(), actual.toHexString(), message)
}
