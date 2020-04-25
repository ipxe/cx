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
 * Self-tests
 *
 ******************************************************************************
 */

#include <stdio.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include "cxtest.h"
#include "gentest.h"
#include "seedcalctest.h"
#include "preseedtest.h"
#include "seedreptest.h"

/* Test keys */
EVP_PKEY *key_a;
EVP_PKEY *key_b;
EVP_PKEY *keypair_c;
EVP_PKEY *keypair_d;

/** A test key descriptor */
struct cxtest_key {
	/** Key name */
	const char *name;
	/** Key parser */
	EVP_PKEY * ( * d2i ) ( EVP_PKEY **a, const unsigned char **der,
			       long len );
	/** Key in DER format */
	const unsigned char *der;
	/** Key length */
	unsigned int *len;
	/** Key variable */
	EVP_PKEY **key;
};

/** A standard test key descriptor */
#define CXTEST_KEY( name, d2i ) \
	{ #name, d2i, name ## _der, &name ## _der_len, &name }

/** Test key descriptors */
static struct cxtest_key cxtest_keys[] = {
	CXTEST_KEY ( key_a, d2i_PUBKEY ),
	CXTEST_KEY ( key_b, d2i_PUBKEY ),
	CXTEST_KEY ( keypair_c, d2i_AutoPrivateKey ),
	CXTEST_KEY ( keypair_d, d2i_AutoPrivateKey ),
};

/**
 * Parse test key
 *
 * @v key		Test key
 * @ret ok		Success indicator
 */
static int cxtest_parse_key ( struct cxtest_key *key ) {
	const unsigned char *tmp;

	/* Parse DER key */
	tmp = key->der;
	*(key->key) = key->d2i ( NULL, &tmp, *(key->len) );
	if ( ! *(key->key) ) {
		fprintf ( stderr, "CXTEST %s fail: could not parse key\n",
			  key->name );
		return 0;
	}

	return 1;
}

/**
 * Free test key
 *
 * @v key		Test key
 */
static void cxtest_free_key ( struct cxtest_key *key ) {

	/* Free key */
	EVP_PKEY_free ( *(key->key) );
	*(key->key) = NULL;
}

/**
 * Parse all test keys
 *
 * @ret ok		Succes indicator
 */
static int cxtest_parse_keys ( void ) {
	int i;

	/* Parse keys */
	for ( i = 0 ; i < ( ( int ) ( sizeof ( cxtest_keys ) /
				      sizeof ( cxtest_keys[0] ) ) ) ; i++ ) {
		if ( ! cxtest_parse_key ( &cxtest_keys[i] ) )
			goto err_key;
	}

	return 1;

 err_key:
	for ( i-- ; i >= 0 ; i-- )
		cxtest_free_key ( &cxtest_keys[i] );
	return 0;
}

/**
 * Free all test keys
 *
 */
static void cxtest_free_keys ( void ) {
	unsigned int i;

	/* Parse keys */
	for ( i = 0 ; i < ( sizeof ( cxtest_keys ) /
			    sizeof ( cxtest_keys[0] ) ) ; i++ ) {
		cxtest_free_key ( &cxtest_keys[i] );
	}
}

/**
 * Main entry point
 *
 * @ret exit		Exit status
 */
int main ( void ) {
	int ok = 1;

	/* Prepare keys */
	if ( ! cxtest_parse_keys() )
		goto err_keys;

	/* Run generator self-tests */
	ok &= gentests();

	/* Run seed calculator self-tests */
	ok &= seedcalctests();

	/* Run preseed self-tests */
	ok &= preseedtests();

	/* Run seed report self-tests */
	ok &= seedreptests();

	/* Report failure */
	if ( ! ok )
		goto err_fail;

	/* Free keys */
	cxtest_free_keys();

	fprintf ( stderr, "Self-tests passed\n" );
	return 0;

 err_fail:
	cxtest_free_keys();
 err_keys:
	fprintf ( stderr, "Self-tests failed\n" );
	return 1;
}
