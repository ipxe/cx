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
 * Deterministic Random Bit Generators
 *
 ******************************************************************************
 */

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <openssl/rand_drbg.h>
#include <openssl/x509.h>
#include <cx/drbg.h>
#include "debug.h"

/** A DRBG */
struct cx_drbg {
	/** OpenSSL DRBG */
	RAND_DRBG *drbg;
	/** Entropy input */
	const void *entropy;
	/** Length of entropy input */
	size_t entropy_len;
	/** Nonce */
	const void *nonce;
	/** Length of nonce */
	size_t nonce_len;
	/** Remaining iteration count */
	unsigned int remaining;
};

/** DRBG information */
struct cx_drbg_info {
	/** Security strength (in bits) */
	unsigned int strength;
	/** OpenSSL type */
	int type;
	/** OpenSSL flags */
	unsigned int flags;
	/** Fixed entropy length */
	size_t entropy_len;
	/** Fixed nonce length */
	size_t nonce_len;
	/** Maximum iterations */
	unsigned int max;
};

/******************************************************************************
 *
 * Generator types
 *
 ******************************************************************************
 */

/** DRBG information */
static const struct cx_drbg_info cx_drbg_infos[] = {
	[CX_GEN_AES_128_CTR_2048] = {
		.strength = 128, /* from NIST SP800-57 */
		.type = NID_aes_128_ctr,
		.flags = 0,
		.entropy_len = 16,
		.nonce_len = 8,
		.max = 2048,
	},
	[CX_GEN_AES_256_CTR_2048] = {
		.strength = 256, /* from NIST SP800-57 */
		.type = NID_aes_256_ctr,
		.flags = 0,
		.entropy_len = 32,
		.nonce_len = 16,
		.max = 2048,
	},
};

/**
 * Get DRBG information
 *
 * @v type		Generator type
 * @ret info		DRBG information (or NULL on error)
 */
static const struct cx_drbg_info *
cx_drbg_info ( enum cx_generator_type type ) {
	const struct cx_drbg_info *info;

	/* Identify Generator type */
	if ( type >= ( sizeof ( cx_drbg_infos ) /
		       sizeof ( cx_drbg_infos[0] ) ) ) {
		DBG ( "DRBG type %d out of range\n", type );
		return NULL;
	}
	info = &cx_drbg_infos[type];
	if ( ! info->strength ) {
		DBG ( "DRBG type %d invalid\n", type );
		return NULL;
	}

	return info;
}

/******************************************************************************
 *
 * External data
 *
 * External data is used to associate an arbitrary state pointer with
 * a DRBG instance.
 *
 ******************************************************************************
 */

/** External data index */
static int cx_drbg_ex_idx = -1;

/**
 * Dummy external data new callback
 *
 * @v parent		DRBG
 * @v ptr		Current external data pointer
 * @v ad		External data field
 * @v idx		External data index
 * @v argl		Callback arbitrary long argument
 * @v argp		Callback arbitrary pointer argument
 */
static void cx_drbg_ex_new ( void *parent, void *ptr, CRYPTO_EX_DATA *ad,
			     int idx, long argl, void *argp ) {
	RAND_DRBG *drbg = ( RAND_DRBG * ) parent;

	( void ) ptr;
	( void ) ad;
	( void ) argl;
	( void ) argp;
	RAND_DRBG_set_ex_data ( drbg, idx, NULL );
}

/**
 * Dummy external data dup callback
 *
 * @v to		Destination external data structure
 * @v from		Source external data structure
 * @v from_p		Source external data
 * @v idx		External data index
 * @v argl		Callback arbitrary long argument
 * @v argp		Callback arbitrary pointer argument
 * @ret ok		Success indicator
 */
static int cx_drbg_ex_dup ( CRYPTO_EX_DATA *to, const CRYPTO_EX_DATA *from,
			    void *from_d, int idx, long argl, void *argp ) {

	( void ) to;
	( void ) from;
	( void ) from_d;
	( void ) idx;
	( void ) argl;
	( void ) argp;
	return 1;
}

/**
 * Dummy external data free callback
 *
 * @v parent		DRBG
 * @v ptr		Current external data pointer
 * @v ad		External data field
 * @v idx		External data index
 * @v argl		Callback arbitrary long argument
 * @v argp		Callback arbitrary pointer argument
 */
static void cx_drbg_ex_free ( void *parent, void *ptr, CRYPTO_EX_DATA *ad,
			      int idx, long argl, void *argp ) {
	RAND_DRBG *drbg = ( RAND_DRBG * ) parent;

	( void ) ptr;
	( void ) ad;
	( void ) argl;
	( void ) argp;
	RAND_DRBG_set_ex_data ( drbg, idx, NULL );
}

/**
 * Initialise external data
 *
 * @ret ok		Success indicator
 */
static int cx_drbg_ex_init ( void ) {

	/* Do nothing if already initialised */
	if ( cx_drbg_ex_idx >= 0 )
		return 1;

	/* Allocate external data index */
	cx_drbg_ex_idx = RAND_DRBG_get_ex_new_index ( 0, NULL, cx_drbg_ex_new,
						      cx_drbg_ex_dup,
						      cx_drbg_ex_free );
	if ( cx_drbg_ex_idx < 0 ) {
		DBG ( "DRBG could not allocate external data index\n" );
		return 0;
	}

	return 1;
}

/******************************************************************************
 *
 * Entropy input and nonce injection
 *
 ******************************************************************************
 */

/**
 * Get entropy input
 *
 * @v rdrbg		OpenSSL DRBG
 * @v pout		Pointer to returned entropy input
 * @v entropy		Number of bits of entropy required
 * @v min_len		Minimum entropy length
 * @v max_len		Maximum entropy length
 * @v predict_resist	Prediction resistance required
 * @ret len		Entropy length
 */
static size_t cx_drbg_get_entropy ( RAND_DRBG *rdrbg, unsigned char **pout,
				    int entropy, size_t min_len,
				    size_t max_len, int predict_resist ) {
	struct cx_drbg *drbg = RAND_DRBG_get_ex_data ( rdrbg, cx_drbg_ex_idx );
	size_t len;

	( void ) entropy;

	/* Validity checks */
	len = drbg->entropy_len;
	if ( len < min_len ) {
		DBG ( "DRBG %p entropy too short (%zd bytes, min %zd bytes)\n",
		      drbg, len, min_len );
		return 0;
	}
	if ( len > max_len ) {
		DBG ( "DRBG %p entropy too long (%zd bytes, max %zd bytes)\n",
		      drbg, len, max_len );
		return 0;
	}
	if ( predict_resist ) {
		DBG ( "DRBG %p cannot provide prediction resistance\n", drbg );
		return 0;
	}

	/* Copy predefined entropy */
	*pout = OPENSSL_secure_malloc ( len );
	if ( ! *pout ) {
		DBG ( "DRBG %p could not allocate entropy copy\n", drbg );
		return 0;
	}
	memcpy ( *pout, drbg->entropy, len );

	/* Mark entropy as consumed */
	drbg->entropy_len = 0;

	return len;
}

/**
 * Clean up entropy input
 *
 * @v rdrbg		OpenSSL DRBG
 * @v out		Entropy input
 * @v outlen		Length of entropy input
 */
static void cx_drbg_cleanup_entropy ( RAND_DRBG *rdrbg, unsigned char *out,
				      size_t outlen ) {
	struct cx_drbg *drbg = RAND_DRBG_get_ex_data ( rdrbg, cx_drbg_ex_idx );

	/* Zero and free copy of entropy */
	OPENSSL_secure_clear_free ( out, outlen );

	/* Mark entropy as consumed */
	drbg->entropy_len = 0;
}

/**
 * Get nonce
 *
 * @v rdrbg		OpenSSL DRBG
 * @v pout		Pointer to returned nonce
 * @v entropy		Number of bits of entropy required
 * @v min_len		Minimum nonce length
 * @v max_len		Maximum nonce length
 * @ret len		Nonce length
 */
static size_t cx_drbg_get_nonce ( RAND_DRBG *rdrbg, unsigned char **pout,
				  int entropy, size_t min_len,
				  size_t max_len ) {
	struct cx_drbg *drbg = RAND_DRBG_get_ex_data ( rdrbg, cx_drbg_ex_idx );
	size_t len;

	( void ) entropy;

	/* Validity checks */
	len = drbg->nonce_len;
	if ( len < min_len ) {
		DBG ( "DRBG %p nonce too short (%zd bytes, min %zd bytes)\n",
		      drbg, len, min_len );
		return 0;
	}
	if ( len > max_len ) {
		DBG ( "DRBG %p nonce too long (%zd bytes, max %zd bytes)\n",
		      drbg, len, max_len );
		return 0;
	}

	/* Copy predefined nonce */
	*pout = OPENSSL_secure_malloc ( len );
	if ( ! *pout ) {
		DBG ( "DRBG %p could not allocate nonce copy\n", drbg );
		return 0;
	}
	memcpy ( *pout, drbg->nonce, len );

	/* Mark nonce as consumed */
	drbg->nonce_len = 0;

	return len;
}

/**
 * Clean up nonce
 *
 * @v rdrbg		OpenSSL DRBG
 * @v out		Nonce
 * @v outlen		Length of nonce
 */
static void cx_drbg_cleanup_nonce ( RAND_DRBG *rdrbg, unsigned char *out,
				    size_t outlen ) {
	struct cx_drbg *drbg = RAND_DRBG_get_ex_data ( rdrbg, cx_drbg_ex_idx );

	/* Zero and free copy of nonce */
	OPENSSL_secure_clear_free ( out, outlen );

	/* Mark nonce as consumed */
	drbg->nonce_len = 0;
}

/******************************************************************************
 *
 * External API
 *
 ******************************************************************************
 */

/**
 * Instantiate DRBG with explicitly split entropy, nonce, and personalization
 *
 * @v type		Generator type
 * @v entropy		Entropy input
 * @v entropy_len	Length of entropy input
 * @v nonce		Nonce
 * @v nonce_len		Length of nonce
 * @v personal		Personalization string (or NULL)
 * @v personal_len	Length of personalization string
 * @ret drbg		DRBG (or NULL on error)
 */
struct cx_drbg * cx_drbg_instantiate_split ( enum cx_generator_type type,
					     const void *entropy,
					     size_t entropy_len,
					     const void *nonce,
					     size_t nonce_len,
					     const void *personal,
					     size_t personal_len ) {
	const struct cx_drbg_info *info;
	struct cx_drbg *drbg;

	/* Identify Generator type */
	info = cx_drbg_info ( type );
	if ( ! info )
		goto err_info;

	/* Initialise external data */
	if ( ! cx_drbg_ex_init() )
		goto err_ex_init;

	/* Allocate DRBG */
	drbg = malloc ( sizeof ( *drbg ) );
	if ( ! drbg ) {
		DBG ( "DRBG out of memory\n" );
		goto err_alloc;
	}
	memset ( drbg, 0, sizeof ( *drbg ) );
	drbg->entropy = entropy;
	drbg->entropy_len = entropy_len;
	drbg->nonce = nonce;
	drbg->nonce_len = nonce_len;
	drbg->remaining = info->max;

	/* Allocate OpenSSL DRBG */
	drbg->drbg = RAND_DRBG_new ( info->type, info->flags, NULL );
	if ( ! drbg->drbg ) {
		DBG ( "DRBG %p could not allocate\n", drbg );
		goto err_new;
	}

	/* Set external data */
	if ( ! RAND_DRBG_set_ex_data ( drbg->drbg, cx_drbg_ex_idx, drbg ) ) {
		DBG ( "DRBG %p could not set external data\n", drbg );
		goto err_set_ex_data;
	}

	/* Disable reseeding */
	if ( ! RAND_DRBG_set_reseed_interval ( drbg->drbg, 0 ) ) {
		DBG ( "DRBG %p could not set reseed interval\n", drbg );
		goto err_set_reseed_interval;
	}
	if ( ! RAND_DRBG_set_reseed_time_interval ( drbg->drbg, 0 ) ) {
		DBG ( "DRBG %p could not set reseed time interval\n", drbg );
		goto err_set_reseed_time_interval;
	}

	/* Prepare for instantiation */
	if ( ! RAND_DRBG_set_callbacks ( drbg->drbg, cx_drbg_get_entropy,
					 cx_drbg_cleanup_entropy,
					 cx_drbg_get_nonce,
					 cx_drbg_cleanup_nonce ) ) {
		DBG ( "DRBG %p could not set callbacks\n", drbg );
		goto err_set_callbacks;
	}

	/* Instantiate DRBG */
	if ( ! RAND_DRBG_instantiate ( drbg->drbg, personal, personal_len ) ) {
		DBG ( "DRBG %p could not instantiate\n", drbg );
		goto err_instantiate;
	}

	/* Clear any unconsumed entropy or nonce */
	drbg->entropy = NULL;
	drbg->entropy_len = 0;
	drbg->nonce = NULL;
	drbg->nonce_len = 0;

	return drbg;

	RAND_DRBG_uninstantiate ( drbg->drbg );
 err_instantiate:
 err_set_callbacks:
 err_set_reseed_time_interval:
 err_set_reseed_interval:
 err_set_ex_data:
	RAND_DRBG_free ( drbg->drbg );
 err_new:
	free ( drbg );
 err_alloc:
 err_ex_init:
 err_info:
	return NULL;
}

/**
 * Instantiate DRBG with fixed-length input and optional verification key
 *
 * @v type		Generator type
 * @v input		Combined entropy and nonce input
 * @v len		Combined entropy and nonce input length
 * @v key		Verification key (or NULL)
 * @ret drbg		DRBG (or NULL on error)
 */
struct cx_drbg * cx_drbg_instantiate ( enum cx_generator_type type,
				       const void *input, size_t len,
				       X509_PUBKEY *key ) {
	const struct cx_drbg_info *info;
	struct cx_drbg *drbg;
	const void *entropy;
	const void *nonce;
	size_t expected_len;
	unsigned char *personal;
	int personal_len;

	/* Identify Generator type */
	info = cx_drbg_info ( type );
	if ( ! info )
		return NULL;

	/* Validity checks */
	expected_len = ( info->entropy_len + info->nonce_len );
	if ( len != expected_len ) {
		DBG ( "DRBG type %d incorrect length (%zd bytes, expected "
		      "%zd bytes)\n", type, len, expected_len );
		return NULL;
	}

	/* Split out entropy and nonce */
	entropy = input;
	nonce = ( input + info->entropy_len );

	/* Get personalization string */
	if ( key ) {
		personal = NULL;
		personal_len = i2d_X509_PUBKEY ( key, &personal );
		if ( personal_len < 0 ) {
			DBG ( "DRBG could not encode public key\n" );
			return NULL;
		}
	} else {
		personal = NULL;
		personal_len = 0;
	}

	/* Instantiate DRBG */
	drbg = cx_drbg_instantiate_split ( type, entropy, info->entropy_len,
					   nonce, info->nonce_len,
					   personal, personal_len );
	if ( personal )
		OPENSSL_free ( personal );
	return drbg;
}

/**
 * Instantiate DRBG with fresh entropy
 *
 * @v type		Generator type
 * @ret drbg		DRBG (or NULL on error)
 */
struct cx_drbg * cx_drbg_instantiate_fresh ( enum cx_generator_type type ) {
	const struct cx_drbg_info *info;
	struct cx_drbg *drbg;
	const char *errstr;
	void *input;
	size_t len;

	/* Identify Generator type */
	info = cx_drbg_info ( type );
	if ( ! info )
		goto err_info;

	/* Allocate input buffer */
	len = ( info->entropy_len + info->nonce_len );
	input = OPENSSL_secure_malloc ( len );
	if ( ! input ) {
		DBG ( "DRBG could not allocate %zd bytes for input\n", len );
		goto err_alloc;
	}

	/* Generate entropy */
	if ( RAND_priv_bytes ( input, len ) != 1 ) {
		errstr = ERR_error_string ( ERR_get_error(), NULL );
		DBG ( "DRBG could not generate %zd random bytes: %s\n",
		      len, ( errstr ? errstr : "<unknown>" ) );
		goto err_bytes;
	}

	/* Instantiate DRBG */
	drbg = cx_drbg_instantiate ( type, input, len, NULL );
	if ( ! drbg )
		goto err_instantiate;

	/* Discard entropy */
	OPENSSL_secure_clear_free ( input, len );

	return drbg;

	cx_drbg_uninstantiate ( drbg );
 err_instantiate:
 err_bytes:
	OPENSSL_secure_clear_free ( input, len );
 err_alloc:
 err_info:
	return NULL;
}

/**
 * Generate random bytes
 *
 * @v drbg		DRBG
 * @v output		Output buffer
 * @v len		Length of output buffer
 * @ret ok		Success indicator
 */
int cx_drbg_generate ( struct cx_drbg *drbg, void *output, size_t len ) {

	/* Fail if maximum iteration count has been exceeded */
	if ( ! drbg->remaining ) {
		DBG ( "DRBG %p maximum iteration count exceeded\n", drbg );
		return 0;
	}

	/* Decrement maximum iteration count */
	drbg->remaining--;

	/* Generate random bytes */
	if ( ! RAND_DRBG_generate ( drbg->drbg, output, len, 0, NULL, 0 ) ) {
		DBG ( "DRBG %p could not generate %zd bytes\n", drbg, len );
		/* No idea of the resulting DRBG state: make this a
		 * permanent failure to avoid silently generating
		 * incorrect values.
		 */
		cx_drbg_invalidate ( drbg );
		return 0;
	}

	return 1;
}

/**
 * Invalidate DRBG
 *
 * @v drbg		DRBG
 */
void cx_drbg_invalidate ( struct cx_drbg *drbg ) {

	/* Inhibit generation of any further random bytes */
	drbg->remaining = 0;
}

/**
 * Uninstantiate DRBG
 *
 * @v drbg		DRBG
 */
void cx_drbg_uninstantiate ( struct cx_drbg *drbg ) {

	/* Uninstantiate DRBG */
	if ( ! RAND_DRBG_uninstantiate ( drbg->drbg ) ) {
		DBG ( "DRBG %p could not uninstantiate\n", drbg );
		/* Continue anyway; there is no alternative */
	}

	/* Free OpenSSL DRBG */
	RAND_DRBG_free ( drbg->drbg );

	/* Free DRBG */
	free ( drbg );
}
