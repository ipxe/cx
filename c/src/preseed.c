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
 * Preseed Values
 *
 ******************************************************************************
 */

#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <cx/drbg.h>
#include <cx/preseed.h>
#include "debug.h"

/**
 * Construct a preseed value
 *
 * @v type		Generator type
 * @v preseed		Preseed value to fill in
 * @v len		Length of preseed value to fill in
 * @ret ok		Success indicator
 */
int cx_preseed_value ( enum cx_generator_type type, void *preseed,
		       size_t len ) {
	struct cx_drbg *drbg;
	size_t expected;

	/* Check length */
	expected = cx_drbg_seed_len ( type );
	if ( len != expected ) {
		DBG ( "PRESEED type %d incorrect seed length %zd\n",
		      type, len );
		goto err_len;
	}

	/* Instantiate DRBG */
	drbg = cx_drbg_instantiate_fresh ( type );
	if ( ! drbg ) {
		DBG ( "PRESEED type %d could not instantiate\n", type );
		goto err_instantiate;
	}

	/* Generate preseed value */
	if ( ! cx_drbg_generate ( drbg, preseed, len ) ) {
		DBG ( "PRESEED type %d could not generate %zd bytes\n",
		      type, len );
		goto err_generate;
	}

	/* Uninstantiate DRBG */
	cx_drbg_uninstantiate ( drbg );

	return 1;

 err_generate:
	cx_drbg_uninstantiate ( drbg );
 err_instantiate:
 err_len:
	return 0;
}

/**
 * Construct a preseed key pair using a default algorithm and parameters
 *
 * @ret key		Preseed key pair (or NULL on error)
 *
 * For more fine-grained control over the preseed key pair (such as
 * the ability to use a hardware security module), use
 * EVP_PKEY_keygen() directly.
 */
EVP_PKEY * cx_preseed_key ( void ) {
	EVP_PKEY_CTX *ctx;
	EVP_PKEY *key = NULL;

	/* Allocate context */
	ctx = EVP_PKEY_CTX_new_id ( EVP_PKEY_RSA, NULL );
	if ( ! ctx ) {
		DBG ( "PRESEED key could not allocate context\n" );
		goto err_new_id;
	}

	/* Initialise key generator */
	if ( EVP_PKEY_keygen_init ( ctx ) <= 0 ) {
		DBG ( "PRESEED key could not initialise context\n" );
		goto err_init;
	}

	/* Configure context */
	if ( EVP_PKEY_CTX_set_rsa_keygen_bits ( ctx, 2048 ) <= 0 ) {
		DBG ( "PRESEED key could not set size\n" );
		goto err_set_bits;
	}

	/* Generate key */
	if ( EVP_PKEY_keygen ( ctx, &key ) <= 0 ) {
		DBG ( "PRESEED key could not generate\n" );
		goto err_keygen;
	}

	/* Free context */
	EVP_PKEY_CTX_free ( ctx );

	return key;

 err_keygen:
 err_set_bits:
 err_init:
	EVP_PKEY_CTX_free ( ctx );
 err_new_id:
	return NULL;
}
