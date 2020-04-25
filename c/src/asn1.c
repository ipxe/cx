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
 * ASN.1 helpers
 *
 ******************************************************************************
 */

#include <openssl/asn1t.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <cx/asn1.h>
#include "debug.h"

/**
 * Implement structure print to file pointer function
 *
 * @v type		Structure type
 *
 * An equivalent generic function is not (yet?) present in OpenSSL.
 */
#define IMPLEMENT_ASN1_PRINT_FUNCTION_fp( type )			\
	int type ## _print_fp ( FILE *fp, type *x ) {			\
		BIO *btmp;						\
		int ret;						\
		btmp = BIO_new_fp ( fp, BIO_NOCLOSE );			\
		if ( ! btmp )						\
			return -1;					\
		ret = type ## _print_ctx ( btmp, x, 0, NULL );		\
		BIO_free ( btmp );					\
		return ret;						\
	}

/******************************************************************************
 *
 * Signatures
 *
 ******************************************************************************
 */

/** Signature */
struct CX_SIGNATURE_st {
	/** Signature algorithm */
	X509_ALGOR signatureAlgorithm;
	/** Signature value */
	ASN1_OCTET_STRING signatureValue;
};

/* Signature ASN.1 item descriptor */
ASN1_SEQUENCE ( CX_SIGNATURE ) = {
	ASN1_EMBED ( CX_SIGNATURE, signatureAlgorithm, X509_ALGOR ),
	ASN1_EMBED ( CX_SIGNATURE, signatureValue, ASN1_OCTET_STRING ),
} ASN1_SEQUENCE_END ( CX_SIGNATURE );
IMPLEMENT_ASN1_FUNCTIONS ( CX_SIGNATURE );

/* Signatures ASN.1 item descriptor */
ASN1_ITEM_TEMPLATE ( CX_SIGNATURES ) =
	ASN1_EX_TEMPLATE_TYPE ( ASN1_TFLG_SEQUENCE_OF, 0, signatureValues,
				CX_SIGNATURE )
	ASN1_ITEM_TEMPLATE_END ( CX_SIGNATURES );
IMPLEMENT_ASN1_FUNCTIONS ( CX_SIGNATURES );

/**
 * Create signature
 *
 * @v signature		Signature
 * @v item		ASN.1 item descriptor
 * @v algor		ASN.1 embedded signatureAlgorithm (or NULL if none)
 * @v value		ASN.1 value
 * @v key		Signing key
 * @v md		Digest type (or NULL to use default)
 * @ret ok		Success indicator
 */
int CX_SIGNATURE_sign ( CX_SIGNATURE *signature, const ASN1_ITEM *item,
			X509_ALGOR *algor, void *value, EVP_PKEY *key,
			const EVP_MD *md ) {
	size_t len;

	/* Sanity checks */
	if ( ! signature )
		return 0;

	/* Create ASN.1 signature */
	len = ASN1_item_sign ( item, algor, &signature->signatureAlgorithm,
			       &signature->signatureValue, value, key, md );
	if ( ! len ) {
		DBG ( "CX_SIGNATURE could not sign\n" );
		return 0;
	}

	return 1;
}

/**
 * Verify signature
 *
 * @v signature		Signature
 * @v item		ASN.1 item descriptor
 * @v algor		ASN.1 embedded signatureAlgorithm (or NULL if none)
 * @v value		ASN.1 value
 * @v key		Verification key
 * @ret ok		Success indicator
 */
int CX_SIGNATURE_verify ( CX_SIGNATURE *signature, const ASN1_ITEM *item,
			  X509_ALGOR *algor, void *value, EVP_PKEY *key ) {
	int rv;

	/* Sanity checks */
	if ( ! signature )
		return 0;

	/* Verify ASN.1 signature */
	rv = ASN1_item_verify ( item, &signature->signatureAlgorithm,
				&signature->signatureValue, value, key );
	if ( rv != 1 ) {
		DBG ( "CX_SIGNATURE verification failed\n" );
		return 0;
	}

	/* Verify embedded signatureAlgorithm, if any */
	if ( algor && ( X509_ALGOR_cmp ( &signature->signatureAlgorithm,
					 algor ) != 0 ) ) {
		DBG ( "CX_SIGNATURE verification algorithm mismatch\n" );
		return 0;
	}

	return 1;
}

/******************************************************************************
 *
 * Seed descriptors
 *
 ******************************************************************************
 */

/** Seed descriptor */
struct CX_SEED_DESCRIPTOR_st {
	/** Generator type */
	uint32_t generatorType;
	/** Preseed value */
	ASN1_OCTET_STRING preseedValue;
	/** Preseed verification key */
	X509_PUBKEY *preseedVerificationKey;
	/** Preseed key
	 *
	 * This will be either the preseed key pair or the preseed
	 * verification key, depending on how the seed descriptor was
	 * constructed.
	 *
	 * Since only the preseed verification key appears within the
	 * ASN.1 object, construction from an ASN.1 serialisation will
	 * always produce just a preseed verification key.
	 */
	EVP_PKEY *key;
};

/**
 * Seed descriptor callback
 *
 * @v operation		Callback operation
 * @v value		ASN.1 value
 * @v item		ASN.1 item descriptor
 * @v exarg		Extended argument
 * @ret ok		Success indicator
 */
static int cx_seed_descriptor_cb ( int operation, ASN1_VALUE **value,
				   const ASN1_ITEM *item, void *exarg ) {
	CX_SEED_DESCRIPTOR *desc;

	( void ) item;
	( void ) exarg;

	switch ( operation ) {

	case ASN1_OP_FREE_POST:
		/* Free preseed key */
		desc = ( ( CX_SEED_DESCRIPTOR * ) *value );
		EVP_PKEY_free ( desc->key );
		break;

	case ASN1_OP_D2I_POST:
		/* Record preseed verification key */
		desc = ( ( CX_SEED_DESCRIPTOR * ) *value );
		EVP_PKEY_free ( desc->key );
		desc->key = X509_PUBKEY_get ( desc->preseedVerificationKey );
		break;

	}

	return 1;
}

/* SeedDescriptor ASN.1 item descriptor */
ASN1_SEQUENCE_cb ( CX_SEED_DESCRIPTOR, cx_seed_descriptor_cb ) = {
	ASN1_EMBED ( CX_SEED_DESCRIPTOR, generatorType, UINT32 ),
	ASN1_EMBED ( CX_SEED_DESCRIPTOR, preseedValue, ASN1_OCTET_STRING ),
	ASN1_SIMPLE ( CX_SEED_DESCRIPTOR, preseedVerificationKey,
		      X509_PUBKEY ),
} ASN1_SEQUENCE_END_cb ( CX_SEED_DESCRIPTOR, CX_SEED_DESCRIPTOR );
IMPLEMENT_ASN1_FUNCTIONS ( CX_SEED_DESCRIPTOR );

/* SeedDescriptors ASN.1 item descriptor */
ASN1_ITEM_TEMPLATE ( CX_SEED_DESCRIPTORS ) =
	ASN1_EX_TEMPLATE_TYPE ( ASN1_TFLG_SEQUENCE_OF, 0, seedDescriptors,
				CX_SEED_DESCRIPTOR )
	ASN1_ITEM_TEMPLATE_END ( CX_SEED_DESCRIPTORS );
IMPLEMENT_ASN1_FUNCTIONS ( CX_SEED_DESCRIPTORS );

/**
 * Get generator type
 *
 * @v desc		Seed descriptor
 * @ret type		Generator type (or 0 on error)
 */
CX_GENERATOR_TYPE CX_SEED_DESCRIPTOR_get_type ( CX_SEED_DESCRIPTOR *desc ) {

	/* Sanity checks */
	if ( ! desc )
		return 0;

	/* Get type */
	return desc->generatorType;
}

/**
 * Set generator type
 *
 * @v desc		Seed descriptor
 * @v type		Generator type
 * @ret ok		Success indicator
 */
int CX_SEED_DESCRIPTOR_set_type ( CX_SEED_DESCRIPTOR *desc,
				  CX_GENERATOR_TYPE type ) {

	/* Sanity checks */
	if ( ! desc )
		return 0;

	/* Set type */
	desc->generatorType = type;

	return 1;
}

/**
 * Get preseed value and length
 *
 * @v desc		Seed descriptor
 * @v preseed		Preseed value to fill in (or NULL)
 * @v len		Preseed length to fill in (or NULL)
 * @ret ok		Success indicator
 */
int CX_SEED_DESCRIPTOR_get0_preseed ( CX_SEED_DESCRIPTOR *desc,
				      const void **preseed, size_t *len ) {

	/* Avoid returning uninitialised results */
	if ( preseed )
		*preseed = NULL;
	if ( len )
		*len = 0;

	/* Sanity checks */
	if ( ! desc )
		return 0;

	/* Get preseed value */
	if ( preseed )
		*preseed = ASN1_STRING_get0_data ( &desc->preseedValue );

	/* Get preseed length */
	if ( len )
		*len = ASN1_STRING_length ( &desc->preseedValue );

	return 1;
}

/**
 * Set preseed value
 *
 * @v desc		Seed descriptor
 * @v preseed		Preseed value
 * @v len		Length of preseed value
 * @ret ok		Success indicator
 */
int CX_SEED_DESCRIPTOR_set1_preseed ( CX_SEED_DESCRIPTOR *desc,
				      const void *preseed, size_t len ) {

	/* Sanity checks */
	if ( ! desc )
		return 0;

	/* Set preseed value */
	if ( ! ASN1_STRING_set ( &desc->preseedValue, preseed, len ) )
		return 0;

	return 1;
}

/**
 * Get preseed key
 *
 * @v desc		Seed descriptor
 * @ret key		Preseed key (or NULL on error)
 */
EVP_PKEY * CX_SEED_DESCRIPTOR_get0_key ( CX_SEED_DESCRIPTOR *desc ) {

	/* Sanity checks */
	if ( ! desc )
		return NULL;

	/* Get stored preseed key */
	return desc->key;
}

/**
 * Get preseed key
 *
 * @v desc		Seed descriptor
 * @ret key		Preseed key (or NULL on error)
 *
 * The caller is responsible for calling EVP_PKEY_free() on the
 * returned preseed key.
 */
EVP_PKEY * CX_SEED_DESCRIPTOR_get1_key ( CX_SEED_DESCRIPTOR *desc ) {
	EVP_PKEY *key;

	/* Get preseed key */
	key = CX_SEED_DESCRIPTOR_get0_key ( desc );
	if ( ! key )
		goto err_get0;

	/* Obtain an extra reference */
	if ( ! EVP_PKEY_up_ref ( key ) )
		goto err_up_ref;

	return key;

 err_up_ref:
 err_get0:
	return NULL;
}

/**
 * Set preseed key
 *
 * @v desc		Seed descriptor
 * @v key		Preseed key
 * @ret ok		Success indicator
 */
int CX_SEED_DESCRIPTOR_set1_key ( CX_SEED_DESCRIPTOR *desc, EVP_PKEY *key ) {

	/* Sanity checks */
	if ( ! desc )
		goto err_sanity;

	/* Obtain an extra reference */
	if ( ! EVP_PKEY_up_ref ( key ) )
		goto err_up_ref;

	/* Clear existing preseed key */
	EVP_PKEY_free ( desc->key );
	desc->key = NULL;

	/* Set preseedVerificationKey */
	if ( ! X509_PUBKEY_set ( &desc->preseedVerificationKey, key ) )
		goto err_pubkey;

	/* Set preseed key */
	desc->key = key;

	return 1;

 err_pubkey:
	EVP_PKEY_free ( key );
 err_up_ref:
 err_sanity:
	return 0;
}

/**
 * Set all seed descriptor fields
 *
 * @v desc		Seed descriptor
 * @v type		Generator type
 * @v preseed		Preseed value
 * @v len		Length of preseed value
 * @ret ok		Success indicator
 */
int CX_SEED_DESCRIPTOR_set1 ( CX_SEED_DESCRIPTOR *desc,
			      CX_GENERATOR_TYPE type, const void *preseed,
			      size_t len, EVP_PKEY *key ) {

	/* Set generator type */
	if ( ! CX_SEED_DESCRIPTOR_set_type ( desc, type ) )
		return 0;

	/* Set preseed value */
	if ( ! CX_SEED_DESCRIPTOR_set1_preseed ( desc, preseed, len ) )
		return 0;

	/* Set preseed key */
	if ( ! CX_SEED_DESCRIPTOR_set1_key ( desc, key ) )
		return 0;

	return 1;
}

/******************************************************************************
 *
 * Seed report content
 *
 ******************************************************************************
 */

/** Seed report content */
struct CX_SEED_REPORT_CONTENT_st {
	/** Version */
	uint32_t version;
	/** Seed descriptors */
	CX_SEED_DESCRIPTORS *seedDescriptors;
	/** Publisher name */
	ASN1_UTF8STRING publisherName;
	/** Seed report challenge */
	ASN1_UTF8STRING seedReportChallenge;
};

/** To-be-signed seed report content */
struct CX_TBS_SEED_REPORT_CONTENT_st {
	/** Seed report content */
	CX_SEED_REPORT_CONTENT *content;
	/** Signature algorithm */
	X509_ALGOR *signatureAlgorithm;
};

/**
 * Seed report content callback
 *
 * @v operation		Callback operation
 * @v value		ASN.1 value
 * @v item		ASN.1 item descriptor
 * @v exarg		Extended argument
 * @ret ok		Success indicator
 */
static int cx_seed_report_content_cb ( int operation, ASN1_VALUE **value,
				       const ASN1_ITEM *item, void *exarg ) {
	CX_SEED_REPORT_CONTENT *content;

	( void ) item;
	( void ) exarg;

	switch ( operation ) {

	case ASN1_OP_NEW_POST:
		/* Default to the only defined version */
		content = ( ( CX_SEED_REPORT_CONTENT * ) *value );
		content->version = CX_SEED_REPORT_VERSION_v1;
		break;

	}

	return 1;
}

/* SeedReportContent ASN.1 item descriptor */
ASN1_SEQUENCE_cb ( CX_SEED_REPORT_CONTENT, cx_seed_report_content_cb ) = {
	ASN1_EMBED ( CX_SEED_REPORT_CONTENT, version, UINT32 ),
	ASN1_SIMPLE ( CX_SEED_REPORT_CONTENT, seedDescriptors,
		      CX_SEED_DESCRIPTORS ),
	ASN1_EMBED ( CX_SEED_REPORT_CONTENT, publisherName, ASN1_UTF8STRING ),
	ASN1_EMBED ( CX_SEED_REPORT_CONTENT, seedReportChallenge,
		     ASN1_UTF8STRING ),
} ASN1_SEQUENCE_END_cb ( CX_SEED_REPORT_CONTENT, CX_SEED_REPORT_CONTENT );
IMPLEMENT_ASN1_FUNCTIONS ( CX_SEED_REPORT_CONTENT );

/* TBSSeedReportContent ASN.1 item descriptor */
ASN1_SEQUENCE ( CX_TBS_SEED_REPORT_CONTENT ) = {
	ASN1_SIMPLE ( CX_TBS_SEED_REPORT_CONTENT, content,
		      CX_SEED_REPORT_CONTENT ),
	ASN1_SIMPLE ( CX_TBS_SEED_REPORT_CONTENT, signatureAlgorithm,
		      X509_ALGOR ),
} ASN1_SEQUENCE_END ( CX_TBS_SEED_REPORT_CONTENT );
IMPLEMENT_ASN1_FUNCTIONS ( CX_TBS_SEED_REPORT_CONTENT );

/**
 * Create seed report content signature
 *
 * @v content		Seed report content
 * @v signature		Signature
 * @v key		Preseed signing key
 * @v md		Digest type (or NULL to use default)
 * @ret ok		Success indicator
 */
static int CX_SEED_REPORT_CONTENT_sign ( CX_SEED_REPORT_CONTENT *content,
					 CX_SIGNATURE *signature,
					 EVP_PKEY *key, const EVP_MD *md ) {
	CX_TBS_SEED_REPORT_CONTENT *tbs;
	CX_SEED_REPORT_CONTENT *saved_content;
	const ASN1_ITEM *item;

	/* Sanity checks */
	if ( ! content )
		return 0;
	if ( ! signature )
		return 0;

	/* Construct temporary TbsSeedReportContent */
	tbs = CX_TBS_SEED_REPORT_CONTENT_new();
	if ( ! tbs ) {
		DBG ( "CX_SEED_REPORT_CONTENT could not allocate "
		      "TbsSeedReportContent\n" );
		goto err_alloc;
	}

	/* Borrow a copy of the seed report content */
	saved_content = tbs->content;
	tbs->content = content;

	/* Create signature */
	item = ASN1_ITEM_rptr ( CX_TBS_SEED_REPORT_CONTENT );
	if ( ! CX_SIGNATURE_sign ( signature, item, tbs->signatureAlgorithm,
				   tbs, key, md ) ) {
		goto err_sign;
	}

	/* Release copy of the seed report content */
	tbs->content = saved_content;

	/* Free temporary TbsSeedReportContent */
	CX_TBS_SEED_REPORT_CONTENT_free ( tbs );

	return 1;

 err_sign:
	tbs->content = saved_content;
 err_alloc:
	CX_TBS_SEED_REPORT_CONTENT_free ( tbs );
	return 0;
}

/**
 * Verify seed report content signature
 *
 * @v content		Seed report content
 * @v signature		Signature
 * @v key		Preseed verification key
 * @ret ok		Success indicator
 */
static int CX_SEED_REPORT_CONTENT_verify ( CX_SEED_REPORT_CONTENT *content,
					   CX_SIGNATURE *signature,
					   EVP_PKEY *key ) {
	CX_TBS_SEED_REPORT_CONTENT *tbs;
	CX_SEED_REPORT_CONTENT *saved_content;
	X509_ALGOR *saved_algor;
	const ASN1_ITEM *item;

	/* Sanity checks */
	if ( ! content )
		return 0;
	if ( ! signature )
		return 0;

	/* Construct temporary TbsSeedReportContent */
	tbs = CX_TBS_SEED_REPORT_CONTENT_new();
	if ( ! tbs ) {
		DBG ( "CX_SEED_REPORT_CONTENT could not allocate "
		      "TbsSeedReportContent\n" );
		goto err_alloc;
	}

	/* Borrow a copy of the seed report content */
	saved_content = tbs->content;
	tbs->content = content;

	/* Borrow a copy of the signature algorithm */
	saved_algor = tbs->signatureAlgorithm;
	tbs->signatureAlgorithm = &signature->signatureAlgorithm;

	/* Create signature */
	item = ASN1_ITEM_rptr ( CX_TBS_SEED_REPORT_CONTENT );
	if ( ! CX_SIGNATURE_verify ( signature, item, NULL, tbs, key ) )
		goto err_verify;

	/* Release copy of the signature algorithm */
	tbs->signatureAlgorithm = saved_algor;

	/* Release copy of the seed report content */
	tbs->content = saved_content;

	/* Free temporary TbsSeedReportContent */
	CX_TBS_SEED_REPORT_CONTENT_free ( tbs );

	return 1;

 err_verify:
	tbs->signatureAlgorithm = saved_algor;
	tbs->content = saved_content;
 err_alloc:
	CX_TBS_SEED_REPORT_CONTENT_free ( tbs );
	return 0;
}

/******************************************************************************
 *
 * Seed reports
 *
 ******************************************************************************
 */

/** Seed report */
struct CX_SEED_REPORT_st {
	/** Seed report content */
	CX_SEED_REPORT_CONTENT content;
	/** Signatures */
	CX_SIGNATURES *signatures;
	/** ASN.1 encoding */
	ASN1_ENCODING enc;
};

/** SeedReport ASN.1 item descriptor */
ASN1_SEQUENCE_enc ( CX_SEED_REPORT, enc, NULL ) = {
	ASN1_EMBED ( CX_SEED_REPORT, content, CX_SEED_REPORT_CONTENT ),
	ASN1_SIMPLE ( CX_SEED_REPORT, signatures, CX_SIGNATURES ),
} ASN1_SEQUENCE_END_enc ( CX_SEED_REPORT, CX_SEED_REPORT );
IMPLEMENT_ASN1_FUNCTIONS ( CX_SEED_REPORT );
IMPLEMENT_ASN1_PRINT_FUNCTION ( CX_SEED_REPORT );
IMPLEMENT_ASN1_PRINT_FUNCTION_fp ( CX_SEED_REPORT );
IMPLEMENT_PEM_rw ( CX_SEED_REPORT, CX_SEED_REPORT, "CX SEED REPORT",
		   CX_SEED_REPORT );

/**
 * Get version
 *
 * @v report		Seed report
 * @ret version		Version (or 0 on error)
 */
CX_SEED_REPORT_VERSION CX_SEED_REPORT_get_version ( CX_SEED_REPORT *report ) {
	CX_SEED_REPORT_CONTENT *content;

	/* Sanity checks */
	if ( ! report )
		return 0;
	content = &report->content;

	/* Get version */
	return content->version;
}

/**
 * Set version
 *
 * @v report		Seed report
 * @v version		Version (or 0 to use default)
 * @ret ok		Success indicator
 */
int CX_SEED_REPORT_set_version ( CX_SEED_REPORT *report,
				 CX_SEED_REPORT_VERSION version ) {
	CX_SEED_REPORT_CONTENT *content;

	/* Sanity checks */
	if ( ! report )
		return 0;
	content = &report->content;

	/* Set version */
	content->version = ( version ? version : CX_SEED_REPORT_VERSION_v1 );

	return 1;
}

/**
 * Get publisher name
 *
 * @v report		Seed report
 * @ret publisher	Publisher name (or NULL on error)
 *
 * The caller is responsible for calling OPENSSL_free() on the
 * returned publisher name.
 */
char * CX_SEED_REPORT_get1_publisher ( CX_SEED_REPORT *report ) {
	CX_SEED_REPORT_CONTENT *content;
	unsigned char *publisher;
	int len;

	/* Sanity checks */
	if ( ! report )
		return NULL;
	content = &report->content;

	/* Get publisher name */
	len = ASN1_STRING_to_UTF8 ( &publisher,  &content->publisherName );
	if ( len < 0 )
		return NULL;

	return ( ( char * ) publisher );
}

/**
 * Set publisher name
 *
 * @v report		Seed report
 * @v publisher		Publisher name
 * @ret ok		Success indicator
 */
int CX_SEED_REPORT_set1_publisher ( CX_SEED_REPORT *report,
				    const char *publisher ) {
	CX_SEED_REPORT_CONTENT *content;

	/* Sanity checks */
	if ( ! report )
		return 0;
	content = &report->content;

	/* Set publisher name */
	if ( ! ASN1_STRING_set ( &content->publisherName, publisher, -1 ) )
		return 0;

	return 1;
}

/**
 * Get seed report challenge
 *
 * @v report		Seed report
 * @ret challenge	Seed report challenge
 *
 * The caller is responsible for calling OPENSSL_free() on the
 * returned seed report challenge.
 */
char * CX_SEED_REPORT_get1_challenge ( CX_SEED_REPORT *report ) {
	CX_SEED_REPORT_CONTENT *content;
	unsigned char *challenge;
	int len;

	/* Sanity checks */
	if ( ! report )
		return 0;
	content = &report->content;

	/* Get seed report challenge */
	len = ASN1_STRING_to_UTF8 ( &challenge,
				    &content->seedReportChallenge );
	if ( len < 0 )
		return 0;

	return ( ( char * ) challenge );
}

/**
 * Set seed report challenge
 *
 * @v report		Seed report
 * @v challenge		Seed report challenge
 * @ret ok		Success indicator
 */
int CX_SEED_REPORT_set1_challenge ( CX_SEED_REPORT *report,
				    const char *challenge ) {
	CX_SEED_REPORT_CONTENT *content;

	/* Sanity checks */
	if ( ! report )
		return 0;
	content = &report->content;

	/* Set seed report challenge */
	if ( ! ASN1_STRING_set ( &content->seedReportChallenge,
				 challenge, -1 ) ) {
		return 0;
	}

	return 1;
}

/**
 * Set all seed report fields
 *
 * @v report		Seed report
 * @v version		Version (or 0 to use default)
 * @v publisher		Publisher name
 * @v challenge		Seed report challenge
 * @ret ok		Success indicator
 */
int CX_SEED_REPORT_set1 ( CX_SEED_REPORT *report,
			  CX_SEED_REPORT_VERSION version,
			  const char *publisher, const char *challenge ) {

	/* Set version */
	if ( ! CX_SEED_REPORT_set_version ( report, version ) )
		return 0;

	/* Set publisher name */
	if ( ! CX_SEED_REPORT_set1_publisher ( report, publisher ) )
		return 0;

	/* Set seed report challenge */
	if ( ! CX_SEED_REPORT_set1_challenge ( report, challenge ) )
		return 0;

	return 1;
}

/**
 * Get seed descriptors
 *
 * @v report		Seed report
 * @ret descs		Seed descriptors (or NULL on error)
 */
CX_SEED_DESCRIPTORS *
CX_SEED_REPORT_get0_descriptors ( CX_SEED_REPORT *report ) {
	CX_SEED_REPORT_CONTENT *content;

	/* Sanity checks */
	if ( ! report )
		return NULL;
	content = &report->content;

	/* Get seed descriptors */
	return content->seedDescriptors;
}

/**
 * Get seed descriptor
 *
 * @v report		Seed report
 * @v idx		Seed descriptor index
 * @ret desc		Seed descriptor (or NULL on error)
 */
CX_SEED_DESCRIPTOR * CX_SEED_REPORT_get0_descriptor ( CX_SEED_REPORT *report,
						      unsigned int idx ) {
	CX_SEED_DESCRIPTORS *descs;

	/* Sanity checks */
	descs = CX_SEED_REPORT_get0_descriptors ( report );
	if ( ! descs )
		return NULL;

	/* Get indexed seed descriptor */
	return sk_CX_SEED_DESCRIPTOR_value ( descs, idx );
}

/**
 * Get number of seed descriptors
 *
 * @v report		Seed report
 * @ret num		Number of seed descriptors
 */
unsigned int CX_SEED_REPORT_num_descriptors ( CX_SEED_REPORT *report ) {
	CX_SEED_DESCRIPTORS *descs;

	/* Sanity checks */
	descs = CX_SEED_REPORT_get0_descriptors ( report );
	if ( ! descs )
		return 0;

	/* Get number of seed descriptors */
	return sk_CX_SEED_DESCRIPTOR_num ( descs );
}

/**
 * Add new seed descriptor
 *
 * @v report		Seed report
 * @ret desc		Seed descriptor (or NULL on error)
 */
CX_SEED_DESCRIPTOR *
CX_SEED_REPORT_add0_descriptor ( CX_SEED_REPORT *report ) {
	CX_SEED_DESCRIPTORS *descs;
	CX_SEED_DESCRIPTOR *desc;

	/* Sanity checks */
	descs = CX_SEED_REPORT_get0_descriptors ( report );
	if ( ! descs )
		goto err_sanity;

	/* Allocate new seed descriptor */
	desc = CX_SEED_DESCRIPTOR_new();
	if ( ! desc )
		goto err_new;

	/* Append to seed descriptors */
	if ( ! sk_CX_SEED_DESCRIPTOR_push ( descs,  desc ) )
		goto err_push;

	return desc;

 err_push:
	CX_SEED_DESCRIPTOR_free ( desc );
 err_new:
 err_sanity:
	return NULL;
}

/**
 * Sign seed report
 *
 * @v report		Seed report
 * @v md		Digest type (or NULL to use default)
 * @ret ok		Success indicator
 */
int CX_SEED_REPORT_sign ( CX_SEED_REPORT *report, const EVP_MD *md ) {
	CX_SEED_REPORT_CONTENT *content;
	CX_SEED_DESCRIPTOR *desc;
	CX_SIGNATURES *signatures;
	CX_SIGNATURE *signature;
	EVP_PKEY *key;
	unsigned int num;
	unsigned int i;

	/* Sanity checks */
	if ( ! report )
		goto err_sanity;
	content = &report->content;
	signatures = report->signatures;
	if ( ! signatures )
		goto err_sanity;

	/* Remove any existing signatures */
	while ( ( signature = sk_CX_SIGNATURE_pop ( signatures ) ) )
		CX_SIGNATURE_free ( signature );

	/* Reserve space in signature stack */
	num = CX_SEED_REPORT_num_descriptors ( report );
	if ( ! sk_CX_SIGNATURE_reserve ( signatures, num ) ) {
		DBG ( "CX_SEED_REPORT could not reserve\n" );
		goto err_reserve;
	}

	/* Add a signature for each descriptor */
	for ( i = 0 ; i < num ; i++ ) {

		/* Get seed descriptor */
		desc = CX_SEED_REPORT_get0_descriptor ( report, i );
		if ( ! desc ) {
			DBG ( "CX_SEED_REPORT missing descriptor %d\n", i );
			goto err_descriptor;
		}

		/* Get signing key */
		key = CX_SEED_DESCRIPTOR_get0_key ( desc );
		if ( ! key ) {
			DBG ( "CX_SEED_REPORT missing key %d\n", i );
			goto err_key;
		}

		/* Allocate new signature */
		signature = CX_SIGNATURE_new();
		if ( ! signature ) {
			DBG ( "CX_SEED_REPORT could not allocate signature "
			      "%d\n", i );
			goto err_new;
		}

		/* Create signature */
		if ( ! CX_SEED_REPORT_CONTENT_sign ( content, signature,
						     key, md ) ) {
			DBG ( "CX_SEED_REPORT could not sign using key %d\n",
			      i );
			goto err_sign;
		}

		/* Append signature */
		if ( ! sk_CX_SIGNATURE_push ( signatures, signature ) ) {
			DBG ( "CX_SEED_REPORT could not append signature "
			      "%d\n", i );
			goto err_push;
		}

		/* Disown signature */
		signature = NULL;
	}

	/* Verify created signatures */
	if ( ! CX_SEED_REPORT_verify ( report ) )
		goto err_verify;

	return 1;

 err_verify:
 err_push:
 err_sign:
	CX_SIGNATURE_free ( signature );
 err_new:
 err_key:
 err_descriptor:
 err_reserve:
 err_sanity:
	return 0;
}

/**
 * Verify seed report
 *
 * @v report		Seed report
 * @ret ok		Success indicator
 */
int CX_SEED_REPORT_verify ( CX_SEED_REPORT *report ) {
	CX_SEED_REPORT_CONTENT *content;
	CX_SEED_DESCRIPTOR *desc;
	CX_SIGNATURES *signatures;
	CX_SIGNATURE *signature;
	EVP_PKEY *key;
	unsigned int num;
	unsigned int i;

	/* Sanity checks */
	if ( ! report )
		goto err_sanity;
	content = &report->content;
	signatures = report->signatures;
	if ( ! signatures )
		goto err_sanity;

	/* Check that at least one seed descriptor exists */
	num = CX_SEED_REPORT_num_descriptors ( report );
	if ( ! num )
		goto err_num;

	/* Verify signature for each descriptor */
	for ( i = 0 ; i < num ; i++ ) {

		/* Get seed descriptor */
		desc = CX_SEED_REPORT_get0_descriptor ( report, i );
		if ( ! desc ) {
			DBG ( "CX_SEED_REPORT missing descriptor %d\n", i );
			goto err_descriptor;
		}

		/* Get verification key */
		key = CX_SEED_DESCRIPTOR_get0_key ( desc );
		if ( ! key ) {
			DBG ( "CX_SEED_REPORT missing key %d\n", i );
			goto err_key;
		}

		/* Get signature */
		signature = sk_CX_SIGNATURE_value ( signatures, i );
		if ( ! signature ) {
			DBG ( "CX_SEED_REPORT missing signature %d\n", i );
			goto err_signature;
		}

		/* Verify signature */
		if ( ! CX_SEED_REPORT_CONTENT_verify ( content, signature,
						       key ) ) {
			DBG ( "CX_SEED_REPORT signature %d incorrect\n", i );
			goto err_verify;
		}
	}

	return 1;

 err_verify:
 err_signature:
 err_key:
 err_descriptor:
 err_num:
 err_sanity:
	return 0;
}
