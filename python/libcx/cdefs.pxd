"""libcx C library definitions"""


cdef extern from "<openssl/crypto.h>":

    void OPENSSL_free(void *addr)


cdef extern from "<openssl/evp.h>":

    ctypedef struct EVP_PKEY

    void EVP_PKEY_free(EVP_PKEY *key)

    int i2d_PUBKEY(EVP_PKEY *a, unsigned char **pp)


cdef extern from "<openssl/x509.h>":

    EVP_PKEY * d2i_PUBKEY(EVP_PKEY **a, const unsigned char **pp, long length)


cdef extern from "<cx.h>":

    cpdef enum cx_generator_type:
        CX_GEN_AES_128_CTR_2048
        CX_GEN_AES_256_CTR_2048

    struct cx_contact_id:
        unsigned char bytes[0]


cdef extern from "<cx/generator.h>":

    struct cx_generator:
        pass

    size_t cx_gen_seed_len(cx_generator_type type)

    unsigned int cx_gen_max_iterations(cx_generator_type type)

    cx_generator * cx_gen_instantiate(cx_generator_type type,
                                      const void *seed, size_t len)

    bint cx_gen_iterate(cx_generator *gen, cx_contact_id *id)

    void cx_gen_uninstantiate(cx_generator *gen)


cdef extern from "<cx/seedcalc.h>":

    bint cx_seedcalc(cx_generator_type type, const void *preseed,
                     size_t len, EVP_PKEY *key, void *seed)


cdef extern from "<cx/preseed.h>":

    bint cx_preseed_value(cx_generator_type type, void *preseed,
                          size_t len)

    EVP_PKEY * cx_preseed_key()
