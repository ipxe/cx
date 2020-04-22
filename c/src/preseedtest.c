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
#include <cx/preseed.h>
#include "cxtest.h"
#include "preseedtest.h"

/**
 * Run a preseed self-test
 *
 * @v name		Test name
 * @v type		Generator type
 * @v len		Preseed value length
 * @ret ok		Success indicator
 */
static int preseedtest ( const char *name, enum cx_generator_type type,
			 size_t len ) {
	unsigned char preseed[len];
	unsigned char seed[len];
	EVP_PKEY *key;

	/* Construct a preseed value */
	if ( ! cx_preseed_value ( type, preseed, len ) ) {
		fprintf ( stderr, "PRESEED %s fail: could not construct "
			  "value\n", name );
		goto err_value;
	}

	/* Construct a preseed key pair */
	key = cx_preseed_key();
	if ( ! key ) {
		fprintf ( stderr, "PRESEED %s fail: could not construct "
			  "key\n", name );
		goto err_key;
	}

	/* Verify that values can be used to calculate a seed value */
	if ( ! cx_seedcalc ( type, preseed, len, key, seed ) ) {
		fprintf ( stderr, "PRESEED %s fail: could not calculate "
			  "seed\n", name );
		goto err_seedcalc;
	}

	/* Free key */
	EVP_PKEY_free ( key );

	fprintf ( stderr, "PRESEED %s ok\n", name );
	return 1;

 err_seedcalc:
	EVP_PKEY_free ( key );
 err_key:
 err_value:
	return 0;
}

/**
 * Run preseed self-tests
 *
 * @ret ok		Success indicator
 */
int preseedtests ( void ) {
	int ok = 1;

	/* Run tests */
	ok &= preseedtest ( "type1", CX_GEN_AES_128_CTR_2048, 24 );
	ok &= preseedtest ( "type2", CX_GEN_AES_256_CTR_2048, 48 );

	return ok;
}
