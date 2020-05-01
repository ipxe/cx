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
 * Seed reports
 *
 ******************************************************************************
 */

#include <string.h>
#include <stdlib.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <cx/asn1.h>
#include <cx/seedrep.h>
#include "debug.h"

/**
 * Construct a signed seed report
 *
 * @v report		Seed report
 * @v md		Digest type (or NULL to use default)
 * @ret seedReport	Seed report ASN.1 object (or NULL on error)
 *
 * The caller is responsible for calling CX_SEED_REPORT_free() on the
 * returned ASN.1 object.
 *
 * The functions PEM_write_CX_SEED_REPORT() and
 * CX_SEED_REPORT_print_fp() may be used to dump the contents of the
 * returned ASN.1 object for inspection.
 */
CX_SEED_REPORT * cx_seedrep_sign_asn1 ( const struct cx_seed_report *report,
					const EVP_MD *md ) {
	const struct cx_seed_descriptor *desc;
	CX_SEED_REPORT *seedReport;
	CX_SEED_DESCRIPTOR *seedDescriptor;
	CX_GENERATOR_TYPE generatorType;
	unsigned int i;

	/* Allocate and initialise structure */
	seedReport = CX_SEED_REPORT_new();
	if ( ! seedReport ) {
		DBG ( "SEEDREP could not allocate report\n" );
		goto err_alloc;
	}
	if ( ! CX_SEED_REPORT_set1 ( seedReport, 0, report->publisher,
				     report->challenge ) ) {
		DBG ( "SEEDREP could not set fields\n" );
		DBG_SEEDREP ( seedReport );
		goto err_set;
	}
	for ( i = 0 ; i < report->count ; i++ ) {
		desc = &report->desc[i];

		/* Append descriptor */
		seedDescriptor = CX_SEED_REPORT_add0_descriptor ( seedReport );
		if ( ! seedDescriptor ) {
			DBG ( "SEEDREP could not add descriptor %d\n", i );
			DBG_SEEDREP ( seedReport );
			goto err_add_descriptor;
		}

		/* Set descriptor fields */
		generatorType = ( ( CX_GENERATOR_TYPE ) desc->type );
		if ( ! CX_SEED_DESCRIPTOR_set1 ( seedDescriptor, generatorType,
						 desc->preseed, desc->len,
						 desc->key ) ) {
			DBG ( "SEEDREP could not set descriptor %d fields\n",
			      i );
			DBG_SEEDREP ( seedReport );
			goto err_set_descriptor;
		}
	}

	/* Add signatures */
	if ( ! CX_SEED_REPORT_sign ( seedReport, md ) ) {
		DBG ( "SEEDREP could not sign\n" );
		DBG_SEEDREP ( seedReport );
		goto err_sign;
	}

	return seedReport;

 err_sign:
 err_set_descriptor:
 err_add_descriptor:
 err_set:
	CX_SEED_REPORT_free ( seedReport );
 err_alloc:
	return NULL;
}

/**
 * Construct a signed seed report in DER format
 *
 * @v report		Seed report
 * @v md		Digest type (or NULL to use default)
 * @v len		Length of DER data to fill in (or NULL)
 * @ret der		Seed report in DER format (or NULL on error)
 *
 * The caller is reponsible for calling OPENSSL_free() on the returned
 * DER format data.
 */
void * cx_seedrep_sign_der ( const struct cx_seed_report *report,
			     const EVP_MD *md, size_t *len ) {
	CX_SEED_REPORT *seedReport;
	unsigned char *der;
	int der_len;

	/* Construct signed seed report */
	seedReport = cx_seedrep_sign_asn1 ( report, md );
	if ( ! seedReport ) {
		DBG ( "SEEDREP could not construct and sign\n" );
		goto err_sign;
	}

	/* Encode as DER */
	der = NULL;
	der_len = i2d_CX_SEED_REPORT ( seedReport, &der );
	if ( der_len < 0 ) {
		DBG ( "SEEDREP could not encode\n" );
		DBG_SEEDREP ( seedReport );
		goto err_i2d;
	}

	/* Record length */
	if ( len )
		*len = der_len;

	/* Free ASN.1 object */
	CX_SEED_REPORT_free ( seedReport );

	return der;

	OPENSSL_free ( der );
 err_i2d:
	CX_SEED_REPORT_free ( seedReport );
 err_sign:
	return NULL;
}

/**
 * Verify and parse a signed seed report
 *
 * @v seedReport	Seed report ASN.1 object
 * @ret report		Seed report (or NULL on error)
 *
 * The caller is responsible for calling cx_seedrep_free() on the
 * returned seed report.
 */
struct cx_seed_report * cx_seedrep_verify_asn1 ( CX_SEED_REPORT *seedReport ) {
	CX_SEED_DESCRIPTOR *seedDescriptor;
	CX_GENERATOR_TYPE generatorType;
	struct cx_seed_report *report;
	struct cx_seed_descriptor *desc;
	unsigned int count;
	unsigned int i;
	const void *preseed0;
	void *preseed;
	size_t len;

	/* Verify signatures */
	if ( ! CX_SEED_REPORT_verify ( seedReport ) ) {
		DBG ( "SEEDREP could not verify\n" );
		DBG_SEEDREP ( seedReport );
		goto err_verify;
	}

	/* Allocate report */
	count = CX_SEED_REPORT_num_descriptors ( seedReport );
	len = ( sizeof ( *report ) + ( count * sizeof ( *desc ) ) );
	report = malloc ( len );
	if ( ! report ) {
		DBG ( "SEEDREP could not allocate report\n" );
		DBG_SEEDREP ( seedReport );
		goto err_alloc;
	}
	memset ( report, 0, len );
	desc = ( ( struct cx_seed_descriptor * )
		 ( ( ( char * ) report ) + sizeof ( *report ) ) );
	report->desc = desc;
	report->count = count;

	/* Get publisher name */
	report->publisher = CX_SEED_REPORT_get1_publisher ( seedReport );
	if ( ! report->publisher ) {
		DBG ( "SEEDREP could not get publisher name\n" );
		DBG_SEEDREP ( seedReport );
		goto err_publisher;
	}

	/* Get seed report challenge */
	report->challenge = CX_SEED_REPORT_get1_challenge ( seedReport );
	if ( ! report->challenge ) {
		DBG ( "SEEDREP could not get seed report challenge\n" );
		DBG_SEEDREP ( seedReport );
		goto err_challenge;
	}

	/* Get seed descriptors */
	for ( i = 0 ; i < count ; i++ ) {

		/* Get seed descriptor */
		seedDescriptor =
			CX_SEED_REPORT_get0_descriptor ( seedReport, i );
		if ( ! seedDescriptor ) {
			DBG ( "SEEDREP could not get descriptor %d\n", i );
			DBG_SEEDREP ( seedReport );
			goto err_desc;
		}

		/* Get generator type */
		generatorType = CX_SEED_DESCRIPTOR_get_type ( seedDescriptor );
		desc[i].type = ( ( enum cx_generator_type ) generatorType );
		if ( ! desc[i].type ) {
			DBG ( "SEEDREP could not get descriptor %d type\n",
			      i );
			DBG_SEEDREP ( seedReport );
			goto err_desc_type;
		}

		/* Get preseed value */
		if ( ! CX_SEED_DESCRIPTOR_get0_preseed ( seedDescriptor,
							 &preseed0,
							 &desc[i].len ) ) {
			DBG ( "SEEDREP could not get descriptor %d preseed\n",
			      i );
			DBG_SEEDREP ( seedReport );
			goto err_preseed;
		}

		/* Duplicate preseed value */
		preseed = malloc ( desc[i].len );
		if ( ! preseed ) {
			DBG ( "SEEDREP could not allocate descriptor %d "
			      "preseed\n", i );
			DBG_SEEDREP ( seedReport );
			goto err_preseed_alloc;
		}
		memcpy ( preseed, preseed0, desc[i].len );

		/* Transfer preseed value copy to descriptor */
		desc[i].preseed = preseed;
		preseed = NULL;

		/* Get preseed key */
		desc[i].key = CX_SEED_DESCRIPTOR_get1_key ( seedDescriptor );
		if ( ! desc[i].key ) {
			DBG ( "SEEDREP could not get descriptor %d key\n", i );
			DBG_SEEDREP ( seedReport );
			goto err_key;
		}
	}

	return report;

 err_key:
	free ( preseed );
 err_preseed_alloc:
 err_preseed:
 err_desc_type:
 err_desc:
 err_challenge:
 err_publisher:
	cx_seedrep_free ( report );
 err_alloc:
 err_verify:
	return NULL;
}

/**
 * Verify and parse a signed seed report in DER format
 *
 * @v der		Seed report in DER format
 * @v len		Length of DER data
 * @ret report		Seed report (or NULL on error)
 *
 * The caller is responsible for calling cx_seedrep_free() on the
 * returned seed report.
 */
struct cx_seed_report * cx_seedrep_verify_der ( const void *der,
						size_t der_len ) {
	CX_SEED_REPORT *seedReport;
	const unsigned char *der_tmp;
	struct cx_seed_report *report;

	/* Decode DER data */
	der_tmp = der;
	seedReport = d2i_CX_SEED_REPORT ( NULL, &der_tmp, der_len );
	if ( ! seedReport ) {
		DBG ( "SEEDREP could not decode\n" );
		goto err_d2i;
	}

	/* Verify and parse seed report */
	report = cx_seedrep_verify_asn1 ( seedReport );
	if ( ! report ) {
		DBG ( "SEEDREP could not verify and parse\n" );
		DBG_SEEDREP ( seedReport );
		goto err_verify;
	}

	/* Free ASN.1 object */
	CX_SEED_REPORT_free ( seedReport );

	return report;

 err_verify:
	CX_SEED_REPORT_free ( seedReport );
 err_d2i:
	return NULL;
}

/**
 * Free seed report
 *
 * @v report		Seed report
 *
 * This must be used only for seed reports returned by
 * cx_seedrep_verify() or cx_seedrep_verify_der().
 */
void cx_seedrep_free ( struct cx_seed_report *report ) {
	unsigned int i;

	/* Do nothing if freeing a NULL pointer */
	if ( ! report )
		return;

	/* Free descriptors */
	for ( i = 0 ; i < report->count ; i++ ) {

		/* Free preseed value */
		free ( ( void * ) report->desc[i].preseed );

		/* Free preseed key */
		EVP_PKEY_free ( report->desc[i].key );
	}

	/* Free seed report challenge */
	OPENSSL_free ( ( void * ) report->challenge );

	/* Free publisher name */
	OPENSSL_free ( ( void * ) report->publisher );

	/* Free report */
	free ( report );
}
