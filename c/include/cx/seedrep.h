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

#ifndef _CX_SEEDREP_H
#define _CX_SEEDREP_H

#include <stddef.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <cx.h>
#include <cx/asn1.h>

/** A seed descriptor */
struct cx_seed_descriptor {
	/** Generator type */
	enum cx_generator_type type;
	/** Preseed value */
	const void *preseed;
	/** Length of preseed value */
	size_t len;
	/** Preseed verification key */
	EVP_PKEY *key;
};

/** A seed report */
struct cx_seed_report {
	/** Seed descriptors */
	const struct cx_seed_descriptor *desc;
	/** Number of seed descriptors */
	unsigned int count;
	/** Publisher name */
	const char *publisher;
	/** Seed report challenge */
	const char *challenge;
};

extern CX_SEED_REPORT *
cx_seedrep_sign_asn1 ( const struct cx_seed_report *report, const EVP_MD *md );

extern void * cx_seedrep_sign_der ( const struct cx_seed_report *report,
				    const EVP_MD *md, size_t *len );

extern struct cx_seed_report *
cx_seedrep_verify_asn1 ( CX_SEED_REPORT *seedReport );

extern struct cx_seed_report * cx_seedrep_verify_der ( const void *der,
						       size_t der_len );

extern void cx_seedrep_free ( struct cx_seed_report *report );

#endif /* _CX_SEEDREP_H */
