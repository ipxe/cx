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

/** Include sample code verbatim */
#include "seedcalc_sample.c"

/** Include test vectors */
#include "seedcalc_type1_test1.c"
#include "seedcalc_type1_test2.c"
#include "seedcalc_type1_test3.c"
#include "seedcalc_type2_test1.c"
#include "seedcalc_type2_test2.c"
#include "seedcalc_type2_test3.c"
#include "ipxe.pubkey.c"
#include "fensystems.pubkey.c"

/** Generator types */
#define GEN_TYPE_AES_128_CTR_DRBG_DF 1
#define GEN_TYPE_AES_256_CTR_DRBG_DF 2

/** A Seed Calculator test vector */
struct seedcalc_test {
	/** Name */
	const char *name;
	/** Generator type */
	int type;
	/** Preseed value */
	const unsigned char *preseed;
	/** SubjectPublicKeyInfo */
	const unsigned char *key;
	/** SubjectPublicKeyInfo length */
	unsigned int *key_len;
	/** Expected seed value */
	const unsigned char *expected;
	/** Expected seed length */
	size_t expected_len;
};

/** Seed Calculator test for AES-128 with natural preseed, Fen Systems key */
static const struct seedcalc_test seedcalc_aes128_natural_fensys = {
	.name = "AES-128 (natural) (Fen Systems)",
	.type = GEN_TYPE_AES_128_CTR_DRBG_DF,
	.preseed = type1_test1_preseed,
	.key = fensystems_pubkey_der,
	.key_len = &fensystems_pubkey_der_len,
	.expected = type1_test1_seed,
	.expected_len = sizeof ( type1_test1_seed ),
};

/** Seed Calculator test for AES-128 with natural preseed, iPXE key */
static const struct seedcalc_test seedcalc_aes128_natural_ipxe = {
	.name = "AES-128 (natural) (iPXE)",
	.type = GEN_TYPE_AES_128_CTR_DRBG_DF,
	.preseed = type1_test2_preseed,
	.key = ipxe_pubkey_der,
	.key_len = &ipxe_pubkey_der_len,
	.expected = type1_test2_seed,
	.expected_len = sizeof ( type1_test2_seed ),
};

/** Seed Calculator test for AES-128 with random preseed, iPXE key */
static const struct seedcalc_test seedcalc_aes128_random_ipxe = {
	.name = "AES-128 (random) (iPXE)",
	.type = GEN_TYPE_AES_128_CTR_DRBG_DF,
	.preseed = type1_test3_preseed,
	.key = ipxe_pubkey_der,
	.key_len = &ipxe_pubkey_der_len,
	.expected = type1_test3_seed,
	.expected_len = sizeof ( type1_test3_seed ),
};

/** Seed Calculator test for AES-256 with natural preseed, Fen Systems key */
static const struct seedcalc_test seedcalc_aes256_natural_fensys = {
	.name = "AES-256 (natural) (Fen Systems)",
	.type = GEN_TYPE_AES_256_CTR_DRBG_DF,
	.preseed = type2_test1_preseed,
	.key = fensystems_pubkey_der,
	.key_len = &fensystems_pubkey_der_len,
	.expected = type2_test1_seed,
	.expected_len = sizeof ( type2_test1_seed ),
};

/** Seed Calculator test for AES-256 with natural preseed, iPXE key */
static const struct seedcalc_test seedcalc_aes256_natural_ipxe = {
	.name = "AES-256 (natural) (iPXE)",
	.type = GEN_TYPE_AES_256_CTR_DRBG_DF,
	.preseed = type2_test2_preseed,
	.key = ipxe_pubkey_der,
	.key_len = &ipxe_pubkey_der_len,
	.expected = type2_test2_seed,
	.expected_len = sizeof ( type2_test2_seed ),
};

/** Seed Calculator test for AES-256 with random preseed, iPXE key */
static const struct seedcalc_test seedcalc_aes256_random_ipxe = {
	.name = "AES-256 (random) (iPXE)",
	.type = GEN_TYPE_AES_256_CTR_DRBG_DF,
	.preseed = type2_test3_preseed,
	.key = ipxe_pubkey_der,
	.key_len = &ipxe_pubkey_der_len,
	.expected = type2_test3_seed,
	.expected_len = sizeof ( type2_test3_seed ),
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
			 ( ( ( offset % 8 ) == 0 ) ? "\n\t" : " " ),
			 data[offset],
			 ( offset < ( len - 1 ) ) ? "," : "" );
	}
	printf ( "\n};\n" );
}

/**
 * Perform Seed Calculator test
 *
 * @v test		Seed Calculator test vector
 * @ret ok		Success indicator
 */
static int seedcalc_test ( const struct seedcalc_test *test ) {
	X509_PUBKEY *pubkey;
	const unsigned char *der;
	const unsigned char *seed;
	int ok;

	/* Parse DER key to X509_PUBKEY */
	der = test->key;
	pubkey = d2i_X509_PUBKEY ( NULL, &der, *test->key_len );
	if ( ! pubkey ) {
		fprintf ( stderr, "SEEDCALC test %s could not parse key\n",
			  test->name );
		hex_dump ( "key", test->key, *test->key_len );
		return 0;
	}

	/* Instantiate the seed calculator */
	seedcalc_instantiate ( test->type, test->preseed, pubkey );

	/* Generate the seed value */
	seed = seedcalc_generate();

	/* Verify output */
	ok = ( memcmp ( seed, test->expected, test->expected_len ) == 0 );

	/* Uninstantiate the seed calculator */
	seedcalc_uninstantiate();

	/* Report result */
	fprintf ( stderr, "SEEDCALC test %s %s\n", test->name,
		  ( ok ? "ok" : "failed" ) );
	if ( ! ok ) {
		hex_dump ( "seed", seed, test->expected_len );
	}

	return ok;
}

/**
 * Run tests
 *
 */
int main ( void ) {
	int ok = 1;

	/* Perform tests */
	ok &= seedcalc_test ( &seedcalc_aes128_natural_fensys );
	ok &= seedcalc_test ( &seedcalc_aes128_natural_ipxe );
	ok &= seedcalc_test ( &seedcalc_aes128_random_ipxe );
	ok &= seedcalc_test ( &seedcalc_aes256_natural_fensys );
	ok &= seedcalc_test ( &seedcalc_aes256_natural_ipxe );
	ok &= seedcalc_test ( &seedcalc_aes256_random_ipxe );

	return ( ok ? 0 : 1 );
}
