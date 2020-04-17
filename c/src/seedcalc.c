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
 * Seed calculators
 *
 ******************************************************************************
 */

#include <cx/drbg.h>
#include <cx/seedcalc.h>
#include "debug.h"

/**
 * Calculate Seed Value
 *
 * @v type		Generator type
 * @v preseed		Preseed value
 * @v len		Length of preseed value
 * @v key		Preseed verification key
 * @v seed		Seed value to fill in
 * @ret ok		Success indicator
 */
int cx_seedcalc ( enum cx_generator_type type, const void *preseed, size_t len,
		  X509_PUBKEY *key, void *seed ) {
	struct cx_drbg *drbg;

	/* Instantiate DRBG */
	drbg = cx_drbg_instantiate ( type, preseed, len, key );
	if ( ! drbg ) {
		DBG ( "SEEDCALC could not instantiate type %d preseed %zd "
		      "bytes\n", type, len );
		goto err_instantiate;
	}

	/* Generate seed value */
	if ( ! cx_drbg_generate ( drbg, seed, len ) ) {
		DBG ( "SEEDCALC could not generate seed\n" );
		goto err_generate;
	}

	/* Uninstantiate DRBG */
	cx_drbg_uninstantiate ( drbg );

	return 1;

 err_generate:
	cx_drbg_uninstantiate ( drbg );
 err_instantiate:
	return 0;
}
