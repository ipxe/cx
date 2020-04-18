"""libcx C library definitions"""


cdef extern from "<cx.h>":

    cpdef enum cx_generator_type:
        CX_GEN_AES_128_CTR_2048
        CX_GEN_AES_256_CTR_2048

    cdef struct cx_contact_id:
        unsigned char bytes[0]


cdef extern from "<cx/generator.h>":

    struct cx_generator:
        pass

    cdef size_t cx_gen_seed_len(cx_generator_type type)

    cdef unsigned int cx_gen_max_iterations(cx_generator_type type)

    cdef cx_generator * cx_gen_instantiate(cx_generator_type type,
                                           const void *seed, size_t len)

    cdef bint cx_gen_iterate(cx_generator *gen, cx_contact_id *id)

    cdef void cx_gen_uninstantiate(cx_generator *gen)
