/* <openssl/bio.h> */

typedef ... BIO;

typedef ... BIO_METHOD;

extern const BIO_METHOD * BIO_s_mem ( void );

extern BIO * BIO_new ( const BIO_METHOD *method );

extern long BIO_get_mem_data ( BIO *bio, char **pp );

extern void BIO_free ( BIO *bio );

/* <openssl/crypto.h> */

extern void OPENSSL_free ( void *addr );

/* <openssl/evp.h> */

typedef ... EVP_MD;

typedef ... EVP_PKEY;

extern int EVP_PKEY_up_ref ( EVP_PKEY *key );

extern void EVP_PKEY_free ( EVP_PKEY *key );

extern int i2d_PrivateKey ( EVP_PKEY *a, unsigned char **pp );

extern int i2d_PublicKey ( EVP_PKEY *a, unsigned char **pp );

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


/* <cx/asn1.h> */

typedef ... ASN1_PCTX;

typedef ... CX_SEED_REPORT;

extern CX_SEED_REPORT * d2i_CX_SEED_REPORT ( CX_SEED_REPORT **report,
					     const unsigned char **der,
					     long len );

extern void CX_SEED_REPORT_free ( CX_SEED_REPORT *report );

extern int CX_SEED_REPORT_print_ctx ( BIO *out, CX_SEED_REPORT *report,
				      int indent, const ASN1_PCTX *pctx );

extern int PEM_write_bio_CX_SEED_REPORT ( BIO *out, CX_SEED_REPORT *report );

/* <cx/seedrep.h> */

struct cx_seed_descriptor {
	enum cx_generator_type type;
	const void *preseed;
	size_t len;
	EVP_PKEY *key;
	...;
};

struct cx_seed_report {
	const struct cx_seed_descriptor *desc;
	unsigned int count;
	const char *publisher;
	const char *challenge;
	...;
};

extern void * cx_seedrep_sign_der ( const struct cx_seed_report *report,
				    const EVP_MD *md, size_t *len );

extern struct cx_seed_report * cx_seedrep_verify_der ( const void *der,
						       size_t der_len );

extern void cx_seedrep_free ( struct cx_seed_report *report );
