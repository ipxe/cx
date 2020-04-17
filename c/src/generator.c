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

/******************************************************************************
 *
 * Generators
 *
 ******************************************************************************
 */

#include <stdlib.h>
#include <string.h>
#include <cx/drbg.h>
#include <cx/generator.h>
#include "debug.h"

/** UUID variant is in MSBits of clk_seq_hi_and_reserved */
#define CX_ID_VARIANT_BYTE 8

/** UUID variant byte mask */
#define CX_ID_VARIANT_MASK 0xc0

/** UUID variant byte value */
#define CX_ID_VARIANT_RFC4122 0x80

/** UUID version is in MSBits of time_hi_and_version */
#define CX_ID_VERSION_BYTE 6

/** UUID version byte mask */
#define CX_ID_VERSION_MASK 0xf0

/** UUID version byte value */
#define CX_ID_VERSION_V4 0x40

/** A generator */
struct cx_generator {
	/** Underlying DRBG */
	struct cx_drbg *drbg;
};

/**
 * Instantiate generator
 *
 * @v type		Generator type
 * @v seed		Seed value
 * @v len		Seed value length
 * @ret gen		Generator (or NULL on error)
 */
struct cx_generator * cx_gen_instantiate ( enum cx_generator_type type,
					   const void *seed, size_t len ) {
	struct cx_generator *gen;

	/* Allocate generator */
	gen = malloc ( sizeof ( *gen ) );
	if ( ! gen ) {
		DBG ( "GEN out of memory\n" );
		goto err_alloc;
	}
	memset ( gen, 0, sizeof ( *gen ) );

	/* Instantiate DRBG */
	gen->drbg = cx_drbg_instantiate ( type, seed, len, NULL );
	if ( ! gen->drbg ) {
		DBG ( "GEN %p could not instantiate DRBG type %d seed %zd "
		      "bytes\n", gen, type, len );
		goto err_drbg;
	}

	return gen;

	cx_drbg_uninstantiate ( gen->drbg );
 err_drbg:
	free ( gen );
 err_alloc:
	return NULL;
}

/**
 * Iterate generator
 *
 * @v gen		Generator
 * @v id		Contact ID to fill in
 * @ret ok		Success indicator
 */
int cx_gen_iterate ( struct cx_generator *gen, struct cx_contact_id *id ) {

	/* Generate random bytes */
	if ( ! cx_drbg_generate ( gen->drbg, id->bytes,
				  sizeof ( id->bytes ) ) ) {
		DBG ( "GEN %p could not generate bytes\n", gen );
		return 0;
	}

	/* Set reserved bits for an RFC 4122 version 4 UUID */
	id->bytes[CX_ID_VARIANT_BYTE] &= ~CX_ID_VARIANT_MASK;
	id->bytes[CX_ID_VARIANT_BYTE] |= CX_ID_VARIANT_RFC4122;
	id->bytes[CX_ID_VERSION_BYTE] &= ~CX_ID_VERSION_MASK;
	id->bytes[CX_ID_VERSION_BYTE] |= CX_ID_VERSION_V4;

	return 1;
}

/**
 * Invalidate generator
 *
 * @v gen		Generator
 */
void cx_gen_invalidate ( struct cx_generator *gen ) {

	/* Invalidate DRBG */
	cx_drbg_invalidate ( gen->drbg );
}

/**
 * Uninstantiate generator
 *
 * @v gen		Generator
 */
void cx_gen_uninstantiate ( struct cx_generator *gen ) {

	/* Uninstantiate DRBG */
	cx_drbg_uninstantiate ( gen->drbg );

	/* Free generator */
	free ( gen );
}
