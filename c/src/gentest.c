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
#include <cx/generator.h>
#include "cxtest.h"
#include "gentest.h"

/**
 * Run a generator self-test
 *
 * @v name		Test name
 * @v type		Generator type
 * @v seed		Seed value
 * @v len		Length of seed value
 * @v max		Expected maximum number of contact identifiers
 * @v first		Expected first contact identifier
 * @v last		Expected last contact identifier
 * @ret ok		Success indicator
 */
static int gentest ( const char *name, enum cx_generator_type type,
		     const unsigned char *seed, size_t len, unsigned int max,
		     const uuid_t *first, const uuid_t *last ) {
	struct cx_generator *gen;
	struct cx_contact_id id;
	const uuid_t *ref;
	unsigned int count;
	int ok;

	/* Test seed length */
	if ( len != cx_gen_seed_len ( type ) ) {
		fprintf ( stderr, "GEN %s fail: incorrect seed length\n",
			  name );
		goto err_seed_len;
	}

	/* Test maximum number of iterations */
	if ( max != cx_gen_max_iterations ( type ) ) {
		fprintf ( stderr, "GEN %s fail: incorrect maximum "
			  "iterations\n", name );
		goto err_max_iterations;
	}

	/* Instantiate generator */
	gen = cx_gen_instantiate ( type, seed, len );
	if ( ! gen ) {
		fprintf ( stderr, "GEN %s fail: could not instantiate\n",
			  name );
		goto err_instantiate;
	}

	/* Test iteration */
	for ( count = 0 ; count < max ; count++ ) {

		/* Iterate generator */
		ok = cx_gen_iterate ( gen, &id );
		if ( ! ok ) {
			fprintf ( stderr, "GEN %s fail: could not iterate "
				  "x%d\n", name, ( count + 1 ) );
			goto err_iterate;
		}

		/* Compare first/last */
		if ( count == 0 ) {
			ref = first;
		} else if ( count == ( max - 1 ) ) {
			ref = last;
		} else {
			ref = NULL;
		}
		if ( ref ) {
			ok = ( memcmp ( id.bytes, ref,
					sizeof ( id.bytes ) ) == 0 );
			if ( ! ok ) {
				fprintf ( stderr, "GEN %s fail: ID %d "
					  "mismatch\n", name, count );
				goto err_mismatch;
			}
		}
	}

	/* Test iteration limit */
	ok = cx_gen_iterate ( gen, &id );
	if ( ok ) {
		fprintf ( stderr, "GEN %s fail: could iterate over x%d\n",
			  name, max );
		goto err_limit;
	}

	/* Uninstantiate generator */
	cx_gen_uninstantiate ( gen );

	fprintf ( stderr, "GEN %s ok\n", name );
	return 1;

 err_limit:
 err_mismatch:
 err_iterate:
	cx_gen_uninstantiate ( gen );
 err_instantiate:
 err_max_iterations:
 err_seed_len:
	return 0;
}

/**
 * Run a standard generator self-test
 *
 * @v type		Generator type
 * @v prefix		Self-test variable prefix
 * @v max		Expected maximum number of contact identifiers
 * @ret ok		Success indicator
 */
#define gentest_std( type, prefix, max )				\
	gentest ( #prefix, type, prefix ## _seed,			\
		  sizeof ( prefix ## _seed ), max,			\
		  &prefix ## _first_id, &prefix ## _last_id )

/**
 * Run generator self-tests
 *
 * @ret ok		Success indicator
 */
int gentests ( void ) {
	int ok = 1;

	/* Run tests */
	ok &= gentest_std ( CX_GEN_AES_128_CTR_2048, gen_type1_test1, 2048 );
	ok &= gentest_std ( CX_GEN_AES_128_CTR_2048, gen_type1_test2, 2048 );
	ok &= gentest_std ( CX_GEN_AES_256_CTR_2048, gen_type2_test1, 2048 );
	ok &= gentest_std ( CX_GEN_AES_256_CTR_2048, gen_type2_test2, 2048 );

	return ok;
}
