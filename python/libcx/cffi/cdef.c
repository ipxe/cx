/* <openssl/crypto.h> */

void OPENSSL_free ( void *addr );

/* <openssl/evp.h> */

typedef ... EVP_PKEY;

extern int EVP_PKEY_up_ref ( EVP_PKEY *key );

extern void EVP_PKEY_free ( EVP_PKEY *key );

int i2d_PrivateKey ( EVP_PKEY *a, unsigned char **pp );

int i2d_PublicKey ( EVP_PKEY *a, unsigned char **pp );

/* <cx.h> */

enum cx_generator_type {
	CX_GEN_AES_128_CTR_2048 = ...,
	CX_GEN_AES_256_CTR_2048 = ...,
};

struct cx_contact_id {
	unsigned char bytes[...];
};

/* <cx/generator.h> */

struct cx_generator;

extern size_t cx_gen_seed_len ( enum cx_generator_type type );

extern unsigned int cx_gen_max_iterations ( enum cx_generator_type type );

extern struct cx_generator * cx_gen_instantiate ( enum cx_generator_type type,
						  const void *seed,
						  size_t len );

extern int cx_gen_iterate ( struct cx_generator *gen,
			    struct cx_contact_id *id );

extern void cx_gen_invalidate ( struct cx_generator *gen );

extern void cx_gen_uninstantiate ( struct cx_generator *gen );

/* <cx/seedcalc.h> */

extern int cx_seedcalc ( enum cx_generator_type type, const void *preseed,
			 size_t len, EVP_PKEY *key, void *seed );

/* <cx/preseed.h> */

extern int cx_preseed_value ( enum cx_generator_type type, void *preseed,
			      size_t len );

extern EVP_PKEY * cx_preseed_key ( void );

