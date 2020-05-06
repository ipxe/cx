package org.ipxe.cx

import kotlin.test.*

@kotlin.ExperimentalUnsignedTypes
class GeneratorTest {

    @Test fun typeTest() {
        assertEquals(1, GeneratorType.Aes128Ctr2048.value)
        assertEquals(24, GeneratorType.Aes128Ctr2048.seedLength)
        assertEquals(2048, GeneratorType.Aes128Ctr2048.maxIterations)
        assertEquals(GeneratorType.Aes128Ctr2048, GeneratorType.fromValue(1))
        assertEquals(2, GeneratorType.Aes256Ctr2048.value)
        assertEquals(48, GeneratorType.Aes256Ctr2048.seedLength)
        assertEquals(2048, GeneratorType.Aes256Ctr2048.maxIterations)
        assertEquals(GeneratorType.Aes256Ctr2048, GeneratorType.fromValue(2))
    }

    @Test fun exceptionTest() {
        assertFailsWith<UnknownGeneratorTypeException> {
            GeneratorType.fromValue(99)
        }
        assertFailsWith<IncorrectSeedLengthException> {
            Generator(GeneratorType.Aes128Ctr2048, byteArrayOf(1, 2, 3))
        }
    }

    fun specTest(
        type: GeneratorType,
        seed: UByteArray,
        first: String,
        count: Int,
        last: String
    ) {
        val gen = Generator(type, seed.asByteArray())
        assertEquals(count, gen.remaining)
        val ids = gen.asSequence().toList()
        assertEquals(count, ids.size)
        assertEquals(first, ids[0].toString())
        assertEquals(last, ids[ids.size - 1].toString())
        assertEquals(0, gen.remaining)
    }

    @Test fun specType1Test1() = specTest(
        GeneratorType.Aes128Ctr2048, ubyteArrayOf(
            0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
            0x08U, 0x09U, 0x0aU, 0x0bU, 0x0cU, 0x0dU, 0x0eU, 0x0fU,
            0x10U, 0x11U, 0x12U, 0x13U, 0x14U, 0x15U, 0x16U, 0x17U),
        "aeaa0891-03d8-400c-beb0-046a2dab8522", 2048,
        "61f3d4b4-844f-4516-9651-d2d2cf8af346"
    )

    @Test fun specType1Test2() = specTest(
        GeneratorType.Aes128Ctr2048, ubyteArrayOf(
            0x04U, 0xb4U, 0xe8U, 0x66U, 0xacU, 0x9eU, 0x39U, 0xc9U,
            0x2cU, 0x2dU, 0x8aU, 0xfeU, 0x68U, 0xcbU, 0x74U, 0x96U,
            0x0bU, 0xf9U, 0xccU, 0xfcU, 0x94U, 0x11U, 0xe3U, 0xdbU),
        "e3e6c75a-5b7b-43d2-973a-b8c3c55b27e4", 2048,
        "eb61bab8-b7b7-45e6-aaf8-8b3b6ac3c146"
    )

    @Test fun specType2Test1() = specTest(
        GeneratorType.Aes256Ctr2048, ubyteArrayOf(
            0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
            0x08U, 0x09U, 0x0aU, 0x0bU, 0x0cU, 0x0dU, 0x0eU, 0x0fU,
            0x10U, 0x11U, 0x12U, 0x13U, 0x14U, 0x15U, 0x16U, 0x17U,
            0x18U, 0x19U, 0x1aU, 0x1bU, 0x1cU, 0x1dU, 0x1eU, 0x1fU,
            0x20U, 0x21U, 0x22U, 0x23U, 0x24U, 0x25U, 0x26U, 0x27U,
            0x28U, 0x29U, 0x2aU, 0x2bU, 0x2cU, 0x2dU, 0x2eU, 0x2fU),
        "7ad7f061-2b3e-4f3e-91f8-b3517deca58d", 2048,
        "e8a1b8c3-3de6-4198-8650-2b4188aef12e"
    )

    @Test fun specType2Test2() = specTest(
        GeneratorType.Aes256Ctr2048, ubyteArrayOf(
            0xd1U, 0xadU, 0xd7U, 0x91U, 0xe8U, 0x2eU, 0x98U, 0xf2U,
            0x6cU, 0xdaU, 0xbfU, 0xb1U, 0x2eU, 0x30U, 0x76U, 0x9fU,
            0x5cU, 0x5fU, 0x86U, 0xc9U, 0xfeU, 0xebU, 0x18U, 0x26U,
            0x2bU, 0x7fU, 0xacU, 0x77U, 0x54U, 0x8bU, 0x49U, 0xc4U,
            0x65U, 0xd2U, 0x0cU, 0x76U, 0x01U, 0x20U, 0xcfU, 0x35U,
            0x21U, 0x34U, 0x93U, 0xbaU, 0xceU, 0xf7U, 0x53U, 0x5aU),
        "e46c75f2-6968-4655-b751-3738547b5cc9", 2048,
        "9d9b113a-94d4-4d0c-9ea6-540db7bb8fb8"
    )
}
