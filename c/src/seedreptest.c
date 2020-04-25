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
#include <stdarg.h>
#include <stdio.h>
#include <cx/seedrep.h>
#include "cxtest.h"
#include "seedreptest.h"

/** Seed report test descriptor parameter */
#define seedreptestdesc( type, preseed, key ) \
	type, preseed, sizeof ( preseed ), key

/**
 * Populate a seed report
 *
 * @v report		Seed report
 * @v desc		Seed descriptors
 * @v publisher		Publisher name
 * @v challenge		Seed report challenge
 * @v count		Number of seed descriptors
 * @v args		Seed descriptor values
 */
static void seedreptest_populate ( struct cx_seed_report *report,
				   struct cx_seed_descriptor *desc,
				   const char *publisher,
				   const char *challenge,
				   unsigned int count, va_list args ) {
	unsigned int i;

	/* Populate report */
	report->desc = desc;
	report->count = count;
	report->publisher = publisher;
	report->challenge = challenge;
	for ( i = 0 ; i < report->count ; i++ ) {
		desc[i].type = va_arg ( args, enum cx_generator_type );
		desc[i].preseed = va_arg ( args, const void * );
		desc[i].len = va_arg ( args, size_t );
		desc[i].key = va_arg ( args, EVP_PKEY * );
	}
}

/**
 * Check a seed report
 *
 * @v name		Test name
 * @v subname		Test subname
 * @v report		Seed report
 * @v expected		Expected seed report
 * @ret ok		Success indicator
 */
static int seedreptest_check ( const char *name, const char *subname,
			       const struct cx_seed_report *report,
			       const struct cx_seed_report *expected ) {
	unsigned int i;

	/* Check publisher name */
	if ( strcmp ( report->publisher, expected->publisher ) != 0 ) {
		fprintf ( stderr, "SEEDREPTEST %s %s publisher name "
			  "mismatch\n", name, subname );
		return 0;
	}

	/* Check seed report challenge */
	if ( strcmp ( report->challenge, expected->challenge ) != 0 ) {
		fprintf ( stderr, "SEEDREPTEST %s %s seed report challenge "
			  "mismatch\n", name, subname );
		return 0;
	}

	/* Check descriptor count */
	if ( report->count != expected->count ) {
		fprintf ( stderr, "SEEDREPTEST %s %s descriptor count "
			  "mismatch\n", name, subname );
		return 0;
	}

	/* Check descriptors */
	for ( i = 0 ; i < report->count ; i++ ) {

		/* Check generator type */
		if ( report->desc[i].type != expected->desc[i].type ) {
			fprintf ( stderr, "SEEDREPTEST %s %s descriptor %d "
				  "generator type mismatch\n",
				  name, subname, i );
			return 0;
		}

		/* Check preseed value */
		if ( ( report->desc[i].len != expected->desc[i].len ) ||
		     ( memcmp ( report->desc[i].preseed,
				expected->desc[i].preseed,
				expected->desc[i].len ) != 0 ) ) {
			fprintf ( stderr, "SEEDREPTEST %s %s descriptor %d "
				  "preseed value mismatch\n",
				  name, subname, i );
			return 0;
		}

		/* Check preseed key */
		if ( EVP_PKEY_cmp ( report->desc[i].key,
				    expected->desc[i].key ) != 1 ) {
			fprintf ( stderr, "SEEDREPTEST %s %s descriptor %d "
				  "key mismatch\n", name, subname, i );
			return 0;
		}
	}

	return 1;
}

/**
 * Run a seed report test
 *
 * @v name		Test name
 * @v publisher		Publisher name
 * @v challenge		Seed report challenge
 * @v count		Number of seed descriptors
 * @v ...		Seed descriptor values
 * @ret ok		Success indicator
 */
static int seedreptest ( const char *name, const char *publisher,
			 const char *challenge, unsigned int count, ... ) {
	struct cx_seed_report report;
	struct cx_seed_descriptor desc[count];
	struct cx_seed_report *check_asn1;
	struct cx_seed_report *check_der;
	struct cx_seed_report *fail;
	CX_SEED_REPORT *seedReport;
	va_list args;
	void *der;
	size_t len;

	/* Populate report */
	va_start ( args, count );
	seedreptest_populate ( &report, desc, publisher, challenge,
			       count, args );
	va_end ( args );

	/* Construct and sign report */
	seedReport = cx_seedrep_sign_asn1 ( &report, NULL );
	if ( ! seedReport ) {
		fprintf ( stderr, "SEEDREPTEST %s ASN.1 could not sign\n",
			  name );
		goto err_sign_asn1;
	}

	/* Verify and parse report */
	check_asn1 = cx_seedrep_verify_asn1 ( seedReport );
	if ( ! check_asn1 ) {
		fprintf ( stderr, "SEEDREPTEST %s ASN.1 could not verify\n",
			  name );
		goto err_verify_asn1;
	}

	/* Check parsed report */
	if ( ! seedreptest_check ( name, "ASN.1", check_asn1, &report ) )
		goto err_check_asn1;

	/* Ensure verification fails if report is modified */
	CX_SEED_REPORT_set1_challenge ( seedReport, "Someone else" );
	fail = cx_seedrep_verify_asn1 ( seedReport );
	if ( fail ) {
		cx_seedrep_free ( fail );
		fprintf ( stderr, "SEEDREPTEST %s ASN.1 verified after "
			  "modification\n", name );
		goto err_fail_asn1;
	}

	/* Construct and sign report in DER format */
	der = cx_seedrep_sign_der ( &report, NULL, &len );
	if ( ! der ) {
		fprintf ( stderr, "SEEDREPTEST %s DER could not sign\n",
			  name );
		goto err_sign_der;
	}

	/* Verify and parse report in DER format */
	check_der = cx_seedrep_verify_der ( der, len );
	if ( ! check_der ) {
		fprintf ( stderr, "SEEDREPTEST %s DER could not verify\n",
			  name );
		goto err_verify_der;
	}

	/* Check parsed report */
	if ( ! seedreptest_check ( name, "DER", check_der, &report ) )
		goto err_check_der;

	/* Ensure verification fails if report is modified */
	*( ( ( char * ) der ) + 21 ) ^= 'X';
	fail = cx_seedrep_verify_der ( der, len );
	if ( fail ) {
		cx_seedrep_free ( fail );
		fprintf ( stderr, "SEEDREPTEST %s DER verified after "
			  "modification\n", name );
		goto err_fail_der;
	}

	/* Free reports */
	cx_seedrep_free ( check_der );
	OPENSSL_free ( der );
	cx_seedrep_free ( check_asn1 );
	CX_SEED_REPORT_free ( seedReport );

	return 1;

 err_fail_der:
 err_check_der:
	cx_seedrep_free ( check_der );
 err_verify_der:
	OPENSSL_free ( der );
 err_sign_der:
 err_fail_asn1:
 err_check_asn1:
	cx_seedrep_free ( check_asn1 );
 err_verify_asn1:
	CX_SEED_REPORT_free ( seedReport );
 err_sign_asn1:
	return 0;
}

/**
 * Run seed report self-tests
 *
 * @ret ok		Success indicator
 */
int seedreptests ( void ) {
	int ok = 1;

	/* Run tests */
	ok &= seedreptest ( "test1", "NHS", "4528 6597 3365 2261", 1,
			    seedreptestdesc ( CX_GEN_AES_128_CTR_2048,
					      seedcalc_type1_test1_preseed,
					      keypair_c ) );
	ok &= seedreptest ( "test2", "CDC", "these three words", 2,
			    seedreptestdesc ( CX_GEN_AES_128_CTR_2048,
					      seedcalc_type1_test2_preseed,
					      keypair_c ),
			    seedreptestdesc ( CX_GEN_AES_128_CTR_2048,
					      seedcalc_type1_test3_preseed,
					      keypair_d ) );
	ok &= seedreptest ( "test3", "国家医疗保障局", "样品123", 3,
			    seedreptestdesc ( CX_GEN_AES_128_CTR_2048,
					      seedcalc_type1_test2_preseed,
					      keypair_c ),
			    seedreptestdesc ( CX_GEN_AES_256_CTR_2048,
					      seedcalc_type2_test1_preseed,
					      keypair_c ),
			    seedreptestdesc ( CX_GEN_AES_256_CTR_2048,
					      seedcalc_type2_test3_preseed,
					      keypair_d ) );

	return ok;
}
