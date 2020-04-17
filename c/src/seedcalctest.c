/*
 * Copyright (C) 2020 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * In addition, as a special exception, the copyright holders of this
 * program give you permission to combine this program with code
 * included in the standard release of OpenSSL (or modified versions
 * of such code, with unchanged license).  You may copy and distribute
 * such a system following the terms of the GNU GPL for this program
 * and the licenses of the other code concerned.
 */

#include <string.h>
#include <stdio.h>
#include <cx/seedcalc.h>
#include "seedcalctest.h"

/* Include test vectors */
#include "tests/seedcalc_type1_test1.c"
#include "tests/seedcalc_type1_test2.c"
#include "tests/seedcalc_type1_test3.c"
#include "tests/seedcalc_type2_test1.c"
#include "tests/seedcalc_type2_test2.c"
#include "tests/seedcalc_type2_test3.c"
#include "tests/key_a.c"
#include "tests/key_b.c"

/**
 * Run a seed calculator self-test
 *
 * @v name		Test name
 * @v type		Generator type
 * @v preseed		Preseed value
 * @v len		Preseed value length
 * @v key_der		Preseed verification key in DER format
 * @v key_len		Preseed verification key length
 * @v expected		Expected seed value
 * @ret ok		Success indicator
 */
static int seedcalctest ( const char *name, enum cx_generator_type type,
			  const unsigned char *preseed, size_t len,
			  const unsigned char *key_der, size_t key_len,
			  const unsigned char *expected ) {
	const unsigned char *tmp_der;
	unsigned char seed[len];
	X509_PUBKEY *key;
	int ok;

	/* Parse DER key */
	tmp_der = key_der;
	key = d2i_X509_PUBKEY ( NULL, &tmp_der, key_len );
	if ( ! key ) {
		fprintf ( stderr, "SEEDCALC %s fail: could not parse key\n",
			  name );
		goto err_key;
	}

	/* Calculate seed value */
	if ( ! cx_seedcalc ( type, preseed, len, key, seed ) ) {
		fprintf ( stderr, "SEEDCALC %s fail: could not calculate "
			  "seed\n", name );
		goto err_seedcalc;
	}

	/* Verify seed value */
	ok = ( memcmp ( seed, expected, sizeof ( seed ) ) == 0 );
	if ( ! ok ) {
		fprintf ( stderr, "SEEDCALC %s fail: seed value mismatch\n",
			  name );
		goto err_seed;
	}

	/* Free key */
	X509_PUBKEY_free ( key );

	fprintf ( stderr, "SEEDCALC %s ok\n", name );
	return 1;

 err_seed:
 err_seedcalc:
	X509_PUBKEY_free ( key );
 err_key:
	return 0;
}

/**
 * Run a standard seed calculator self-test
 *
 * @v type		Generator type
 * @v prefix		Self-test variable prefix
 * @v key		Key prefix
 * @ret ok		Success indicator
 */
#define seedcalctest_std( type, prefix, key )			\
	seedcalctest ( #prefix, type, prefix ## _preseed,	\
		       sizeof ( prefix ## _preseed ),		\
		       key ## _der, sizeof ( key ## _der ),	\
		       prefix ## _seed )

/**
 * Run seed calculator self-tests
 *
 * @ret ok		Success indicator
 */
int seedcalctests ( void ) {
	int ok = 1;

	/* Run tests */
	ok &= seedcalctest_std ( CX_GEN_AES_128_CTR_2048, type1_test1, key_a );
	ok &= seedcalctest_std ( CX_GEN_AES_128_CTR_2048, type1_test2, key_b );
	ok &= seedcalctest_std ( CX_GEN_AES_128_CTR_2048, type1_test3, key_b );
	ok &= seedcalctest_std ( CX_GEN_AES_256_CTR_2048, type2_test1, key_a );
	ok &= seedcalctest_std ( CX_GEN_AES_256_CTR_2048, type2_test2, key_b );
	ok &= seedcalctest_std ( CX_GEN_AES_256_CTR_2048, type2_test3, key_b );

	return ok;
}
