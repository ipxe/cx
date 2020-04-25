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

#ifndef _CX_ASN1_H
#define _CX_ASN1_H

#include <stddef.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <cx.h>

/******************************************************************************
 *
 * OpenSSL conventions
 *
 * ASN.1 data types and functions follow the OpenSSL naming
 * conventions.  As a caller, the basic rule is:
 *
 * - if you successfully call a function with _get0 or _set0 in the
 *   name, then you do not own the pointer and must not free it
 *
 * - if you successfully call a function with _get1 in the name, then
 *   you have ownership of a new pointer and must therefore eventually
 *   free it
 *
 * - if you successfully call a function with _set1 in the name, then
 *   you still have ownership of your original pointer
 *
 * - if a call fails, then your pointer ownership situation is always
 *   unchanged from immediately prior to the call
 *
 * - if a function has a bare _get or _set in the name with no 0 or 1
 *   suffix, then it deals with non-pointer values
 *
 *****************************************************************************
 */

/**
 * Declare structure print to file pointer function
 *
 * @v type		Structure type
 *
 * An equivalent generic function is not (yet?) present in OpenSSL.
 */
#define DECLARE_ASN1_PRINT_FUNCTION_fp( type ) \
	extern int type ## _print_fp ( FILE *fp, type *x );

/* GeneratorType */
typedef enum {
	CX_GENERATOR_TYPE_v1 = CX_GEN_AES_128_CTR_2048,
	CX_GENERATOR_TYPE_v2 = CX_GEN_AES_256_CTR_2048,
} CX_GENERATOR_TYPE;

/* SeedReportVersion */
typedef enum {
	CX_SEED_REPORT_VERSION_v1 = 1,
} CX_SEED_REPORT_VERSION;

/* Signature */
typedef struct CX_SIGNATURE_st CX_SIGNATURE;
DECLARE_ASN1_FUNCTIONS ( CX_SIGNATURE );

/* Signatures */
typedef STACK_OF ( CX_SIGNATURE ) CX_SIGNATURES;
DEFINE_STACK_OF ( CX_SIGNATURE );
DECLARE_ASN1_FUNCTIONS ( CX_SIGNATURES );

/* SeedDescriptor */
typedef struct CX_SEED_DESCRIPTOR_st CX_SEED_DESCRIPTOR;
DECLARE_ASN1_FUNCTIONS ( CX_SEED_DESCRIPTOR );

/* SeedDescriptors */
typedef STACK_OF ( CX_SEED_DESCRIPTOR ) CX_SEED_DESCRIPTORS;
DEFINE_STACK_OF ( CX_SEED_DESCRIPTOR );
DECLARE_ASN1_FUNCTIONS ( CX_SEED_DESCRIPTORS );

/* SeedReportContent */
typedef struct CX_SEED_REPORT_CONTENT_st CX_SEED_REPORT_CONTENT;
DECLARE_ASN1_FUNCTIONS ( CX_SEED_REPORT_CONTENT );

/* TBSSeedReportContent */
typedef struct CX_TBS_SEED_REPORT_CONTENT_st CX_TBS_SEED_REPORT_CONTENT;
DECLARE_ASN1_FUNCTIONS ( CX_TBS_SEED_REPORT_CONTENT );

/* SeedReport */
typedef struct CX_SEED_REPORT_st CX_SEED_REPORT;
DECLARE_ASN1_FUNCTIONS ( CX_SEED_REPORT );
DECLARE_ASN1_PRINT_FUNCTION ( CX_SEED_REPORT );
DECLARE_ASN1_PRINT_FUNCTION_fp ( CX_SEED_REPORT );
DECLARE_PEM_rw ( CX_SEED_REPORT, CX_SEED_REPORT );

extern int CX_SIGNATURE_sign ( CX_SIGNATURE *signature, const ASN1_ITEM *item,
			       X509_ALGOR *algor, void *value, EVP_PKEY *key,
			       const EVP_MD *md );

extern int CX_SIGNATURE_verify ( CX_SIGNATURE *signature,
				 const ASN1_ITEM *item, X509_ALGOR *algor,
				 void *value, EVP_PKEY *key );

extern CX_GENERATOR_TYPE
CX_SEED_DESCRIPTOR_get_type ( CX_SEED_DESCRIPTOR *desc );

extern int CX_SEED_DESCRIPTOR_set_type ( CX_SEED_DESCRIPTOR *desc,
					 CX_GENERATOR_TYPE type );

extern int CX_SEED_DESCRIPTOR_get0_preseed ( CX_SEED_DESCRIPTOR *desc,
					     const void **preseed,
					     size_t *len );

extern int CX_SEED_DESCRIPTOR_set1_preseed ( CX_SEED_DESCRIPTOR *desc,
					     const void *preseed, size_t len );

extern EVP_PKEY * CX_SEED_DESCRIPTOR_get0_key ( CX_SEED_DESCRIPTOR *desc );

extern EVP_PKEY * CX_SEED_DESCRIPTOR_get1_key ( CX_SEED_DESCRIPTOR *desc );

extern int CX_SEED_DESCRIPTOR_set1_key ( CX_SEED_DESCRIPTOR *desc,
					 EVP_PKEY *key );

extern int CX_SEED_DESCRIPTOR_set1 ( CX_SEED_DESCRIPTOR *desc,
				     CX_GENERATOR_TYPE type,
				     const void *preseed, size_t len,
				     EVP_PKEY *key );

extern CX_SEED_REPORT_VERSION
CX_SEED_REPORT_get_version ( CX_SEED_REPORT *report );

extern int CX_SEED_REPORT_set_version ( CX_SEED_REPORT *report,
					CX_SEED_REPORT_VERSION version );

extern char * CX_SEED_REPORT_get1_publisher ( CX_SEED_REPORT *report );

extern int CX_SEED_REPORT_set1_publisher ( CX_SEED_REPORT *report,
					   const char *publisher );

extern char * CX_SEED_REPORT_get1_challenge ( CX_SEED_REPORT *report );

extern int CX_SEED_REPORT_set1_challenge ( CX_SEED_REPORT *report,
					   const char *challenge );

extern int CX_SEED_REPORT_set1 ( CX_SEED_REPORT *report,
				 CX_SEED_REPORT_VERSION version,
				 const char *publisher,
				 const char *challenge );

extern CX_SEED_DESCRIPTORS *
CX_SEED_REPORT_get0_descriptors ( CX_SEED_REPORT *report );

extern CX_SEED_DESCRIPTOR *
CX_SEED_REPORT_get0_descriptor ( CX_SEED_REPORT *report, unsigned int idx );

extern unsigned int CX_SEED_REPORT_num_descriptors ( CX_SEED_REPORT *report );

extern CX_SEED_DESCRIPTOR *
CX_SEED_REPORT_add0_descriptor ( CX_SEED_REPORT *report );

extern int CX_SEED_REPORT_sign ( CX_SEED_REPORT *report, const EVP_MD *md );

extern int CX_SEED_REPORT_verify ( CX_SEED_REPORT *report );

#endif /* _CX_ASN1_H */
