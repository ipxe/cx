/*
 * Copyright (C) 2020 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following
 * disclaimer in the documentation and/or other materials provided
 * with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/** Include sample code verbatim
 *
 * We nullify "const" to allow for the patching required by the NIST
 * test vectors: see below.
 */
#define const
#include "gen_sample.c"
#undef const

/** Include test vectors */
#include "gen_type1_test1.c"
#include "gen_type1_test2.c"
#include "gen_type2_test1.c"
#include "gen_type2_test2.c"

/** Generator types */
#define GEN_TYPE_AES_128_CTR_DRBG_DF 1
#define GEN_TYPE_AES_256_CTR_DRBG_DF 2

/** A NIST test vector */
struct nist_test {
	/** Name */
	const char *name;
	/** Generator type */
	int type;
	/** Entropy input */
	const unsigned char *entropy_input;
	/** Entropy input length */
	size_t entropy_input_len;
	/** Nonce */
	const unsigned char *nonce;
	/** Nonce length */
	size_t nonce_len;
	/** Expected initial generated output */
	const unsigned char *expected;
	/** Expected initial generated output length */
	size_t expected_len;
};

/** NIST test for AES-128 CTR_DRBG with DF
 *
 * This is the first test with "Requested Security Strength = 128" from
 *
 * https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/CTR_DRBG_withDF.pdf
 *
 */
static const unsigned char nist_aes128_ctr_drbg_df_entropy_input[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
	0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};
static const unsigned char nist_aes128_ctr_drbg_df_nonce[] = {
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27
};
static const unsigned char nist_aes128_ctr_drbg_df_expected[] = {
	0x8c, 0xf5, 0x9c, 0x8c, 0xf6, 0x88, 0x8b, 0x96, 0xeb, 0x1c, 0x1e, 0x3e,
	0x79, 0xd8, 0x23, 0x87, 0xaf, 0x08, 0xa9, 0xe5, 0xff, 0x75, 0xe2, 0x3f,
	0x1f, 0xbc, 0xd4, 0x55, 0x9b, 0x6b, 0x99, 0x7e
};
static const struct nist_test nist_aes128_ctr_drbg_df = {
	.name = "AES-128 CTR_DRBG with DF",
	.type = GEN_TYPE_AES_128_CTR_DRBG_DF,
	.entropy_input = nist_aes128_ctr_drbg_df_entropy_input,
	.entropy_input_len = sizeof ( nist_aes128_ctr_drbg_df_entropy_input ),
	.nonce = nist_aes128_ctr_drbg_df_nonce,
	.nonce_len = sizeof ( nist_aes128_ctr_drbg_df_nonce ),
	.expected = nist_aes128_ctr_drbg_df_expected,
	.expected_len = sizeof ( nist_aes128_ctr_drbg_df_expected ),
};

/** NIST test for AES-256 CTR_DRBG with DF
 *
 * This is the first test with "Requested Security Strength = 256" from
 *
 * https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/CTR_DRBG_withDF.pdf
 *
 */
static const unsigned char nist_aes256_ctr_drbg_df_entropy_input[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
	0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
	0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f
};
static const unsigned char nist_aes256_ctr_drbg_df_nonce[] = {
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
	0x2c, 0x2d, 0x2e, 0x2f
};
static const unsigned char nist_aes256_ctr_drbg_df_expected[] = {
	0xe6, 0x86, 0xdd, 0x55, 0xf7, 0x58, 0xfd, 0x91, 0xba, 0x7c, 0xb7, 0x26,
	0xfe, 0x0b, 0x57, 0x3a, 0x18, 0x0a, 0xb6, 0x74, 0x39, 0xff, 0xbd, 0xfe,
	0x5e, 0xc2, 0x8f, 0xb3, 0x7a, 0x16, 0xa5, 0x3b
};
static const struct nist_test nist_aes256_ctr_drbg_df = {
	.name = "AES-256 CTR_DRBG with DF",
	.type = GEN_TYPE_AES_256_CTR_DRBG_DF,
	.entropy_input = nist_aes256_ctr_drbg_df_entropy_input,
	.entropy_input_len = sizeof ( nist_aes256_ctr_drbg_df_entropy_input ),
	.nonce = nist_aes256_ctr_drbg_df_nonce,
	.nonce_len = sizeof ( nist_aes256_ctr_drbg_df_nonce ),
	.expected = nist_aes256_ctr_drbg_df_expected,
	.expected_len = sizeof ( nist_aes256_ctr_drbg_df_expected ),
};

/** NIST-like test matching first AES-128 Contact Identifier test
 *
 * This is a test using the NIST test vector structure with a seed
 * value matching that used in the first Contact Identifier test.  It
 * is used to verify that the first 16 bytes output from
 * generator_iterate() matches (excepting the UUIDv4 fixed bits) the
 * first 16 bytes obtained by using the DRBG directly with the
 * intended entropy and nonce.
 */
static const unsigned char nist_cx_id_aes128_natural_expected[] = {
	0xae, 0xaa, 0x08, 0x91, 0x03, 0xd8, 0x10, 0x0c, 0xfe, 0xb0, 0x04, 0x6a,
        0x2d, 0xab, 0x85, 0x22
};
static const struct nist_test nist_cx_id_aes128_natural = {
	.name = "AES-128 (natural) (NIST-like)",
	.type = GEN_TYPE_AES_128_CTR_DRBG_DF,
	.entropy_input = &gen_type1_test1_seed[0],
	.entropy_input_len = 16,
	.nonce = &gen_type1_test1_seed[16],
	.nonce_len = 8,
	.expected = nist_cx_id_aes128_natural_expected,
	.expected_len = sizeof ( nist_cx_id_aes128_natural_expected ),
};

/** A Contact Identifier test vector */
struct cx_id_test {
	/** Name */
	const char *name;
	/** Generator type */
	int type;
	/** Seed value */
	const unsigned char *seed;
	/** Expected number of Contact Identifiers */
	int count;
	/** Expected initial Contact Identifier */
	const uuid_t *expected_first;
	/** Expected final Contact Identifier */
	const uuid_t *expected_last;
};

/** Contact Identifier test for AES-128 with natural numbers seed */
static const struct cx_id_test cx_id_aes128_natural = {
	.name = "AES-128 (natural)",
	.type = GEN_TYPE_AES_128_CTR_DRBG_DF,
	.seed = gen_type1_test1_seed,
	.count = 2048,
	.expected_first = &gen_type1_test1_first_id,
	.expected_last = &gen_type1_test1_last_id,
};

/** Contact Identifier test for AES-128 with random seed */
static const struct cx_id_test cx_id_aes128_random = {
	.name = "AES-128 (random)",
	.type = GEN_TYPE_AES_128_CTR_DRBG_DF,
	.seed = gen_type1_test2_seed,
	.count = 2048,
	.expected_first = &gen_type1_test2_first_id,
	.expected_last = &gen_type1_test2_last_id,
};

/** Contact Identifier test for AES-256 with natural numbers seed */
static const struct cx_id_test cx_id_aes256_natural = {
	.name = "AES-256 (natural)",
	.type = GEN_TYPE_AES_256_CTR_DRBG_DF,
	.seed = gen_type2_test1_seed,
	.count = 2048,
	.expected_first = &gen_type2_test1_first_id,
	.expected_last = &gen_type2_test1_last_id,
};

/** Contact Identifier test for AES-256 with random seed */
static const struct cx_id_test cx_id_aes256_random = {
	.name = "AES-256 (random)",
	.type = GEN_TYPE_AES_256_CTR_DRBG_DF,
	.seed = gen_type2_test2_seed,
	.count = 2048,
	.expected_first = &gen_type2_test2_first_id,
	.expected_last = &gen_type2_test2_last_id,
};

/**
 * Dump hex data
 *
 * @v name		C variable name
 * @v data		Data
 * @v len		Length of data
 */
static void hex_dump ( const char *name, const unsigned char *data,
		       size_t len ) {
	unsigned int offset;

	printf ( "const unsigned char %s[] = {", name );
	for ( offset = 0 ; offset < len ; offset++ ) {
		printf ( "%s0x%02x%s",
			 ( ( ( offset % 12 ) == 0 ) ? "\n\t" : " " ),
			 data[offset],
			 ( offset < ( len - 1 ) ) ? "," : "" );
	}
	printf ( "\n};\n" );
}

/**
 * Dump UUID data
 *
 * @v name		C variable name
 * @v id		UUID
 */
static void uuid_dump ( const char *name, const uuid_t *id ) {

	printf ( "// %s: %02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-"
		 "%02x%02x%02x%02x%02x%02x\n", name,
		 (*id)[0], (*id)[1], (*id)[2], (*id)[3], (*id)[4], (*id)[5],
		 (*id)[6], (*id)[7], (*id)[8], (*id)[9], (*id)[10], (*id)[11],
		 (*id)[12], (*id)[13], (*id)[14], (*id)[15] );
	hex_dump ( name, *id, sizeof ( *id ) );
}

/**
 * Perform NIST test
 *
 * @v test		NIST test vector
 * @ret ok		Success indicator
 */
static int nist_test ( const struct nist_test *test ) {
	unsigned char seed[test->entropy_input_len + test->nonce_len];
	unsigned char out[test->expected_len];
	int ok;

	/* Patch unused generator type 0 to match this test vector
	 *
	 * The NIST test vectors use entropy and nonce lengths that
	 * are larger than the required minimum values.  We patch the
	 * definition of the unused generator type 0 to match the
	 * lengths in the NIST test vectors.
	 *
	 * This allows us to test the exact sample code that is
	 * included within the specification document.
	 */
	type_nid[0] = type_nid[test->type];
	type_entropy_input_len[0] = test->entropy_input_len;
	type_nonce_len[0] = test->nonce_len;

	/* Construct seed */
	memcpy ( seed, test->entropy_input, test->entropy_input_len );
	memcpy ( ( seed + test->entropy_input_len ), test->nonce,
		 test->nonce_len );

	/* Instantiate the generator */
	generator_instantiate ( 0, seed );

	/* Generate output from the DRBG directly */
	RAND_DRBG_generate ( current_drbg, out, sizeof ( out ), 0, NULL, 0 );

	/* Verify output */
	ok = ( memcmp ( out, test->expected, sizeof ( out ) ) == 0 );

	/* Uninstantiate the generator */
	generator_uninstantiate();

	/* Report result */
	fprintf ( stderr, "NIST test %s %s\n", test->name,
		  ( ok ? "ok" : "failed" ) );
	if ( ! ok ) {
		hex_dump ( "seed", seed, sizeof ( seed ) );
		hex_dump ( "out", out, sizeof ( out ) );
	}

	return ok;
}

/**
 * Perform Contact Identifier test
 *
 * @v test		Contact identifier test vector
 * @ret ok		Success indicator
 */
static int cx_id_test ( const struct cx_id_test *test ) {
	const uuid_t *id;
	int first_ok;
	int last_ok;
	int max_ok;
	int i;

	/* Instantiate the generator */
	generator_instantiate ( test->type, ( unsigned char * ) test->seed );

	/* Generate the first Contact Identifier */
	id = generator_iterate();
	first_ok = ( memcmp ( id, test->expected_first, sizeof ( *id ) ) == 0 );
	fprintf ( stderr, "CX ID test %s first %s\n", test->name,
		  ( first_ok ? "ok" : "failed" ) );
	if ( ! first_ok ) {
		uuid_dump ( "id", id );
	}

	/* Generate and discard the intermediate Contact Identifiers */
	for ( i = 0 ; i < ( test->count - 2 ) ; i++ ) {
		generator_iterate();
	}

	/* Generate the last Contact Identifier */
	id = generator_iterate();
	last_ok = ( memcmp ( id, test->expected_last, sizeof ( *id ) ) == 0 );
	fprintf ( stderr, "CX ID test %s last %s\n", test->name,
		  ( last_ok ? "ok" : "failed" ) );
	if ( ! last_ok ) {
		uuid_dump ( "id", id );
	}

	/* Check that generator refuses to iterate further */
	id = generator_iterate();
	max_ok = ( id == NULL );
	fprintf ( stderr, "CX ID test %s max %s\n", test->name,
		  ( max_ok ? "ok" : "failed" ) );

	/* Uninstantiate the generator */
	generator_uninstantiate();

	/* Report result */
	return ( first_ok && last_ok && max_ok );
}

/**
 * Run tests
 *
 */
int main ( void ) {
	int ok = 1;

	/* Perform tests */
	ok &= nist_test ( &nist_aes128_ctr_drbg_df );
	ok &= nist_test ( &nist_aes256_ctr_drbg_df );
	ok &= nist_test ( &nist_cx_id_aes128_natural );
	ok &= cx_id_test ( &cx_id_aes128_natural );
	ok &= cx_id_test ( &cx_id_aes128_random );
	ok &= cx_id_test ( &cx_id_aes256_natural );
	ok &= cx_id_test ( &cx_id_aes256_random );

	return ( ok ? 0 : 1 );
}
