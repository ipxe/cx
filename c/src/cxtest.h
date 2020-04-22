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

#ifndef _CX_TEST_H
#define _CX_TEST_H

typedef unsigned char uuid_t[16];

#define DECL_GEN_TEST( name, seed_len )				\
	extern const unsigned char name ## _seed[seed_len];	\
	extern const uuid_t name ## _first_id;			\
	extern const uuid_t name ## _last_id;

#define DECL_SEEDCALC_TEST( name, seed_len )			\
	extern const unsigned char name ## _preseed[seed_len];	\
	extern const unsigned char name ## _seed[seed_len];

#define DECL_KEY( name )					\
	extern unsigned char name ## _der[];			\
	extern unsigned int name ## _der_len;

DECL_GEN_TEST ( gen_type1_test1, 24 );
DECL_GEN_TEST ( gen_type1_test2, 24 );
DECL_GEN_TEST ( gen_type2_test1, 48 );
DECL_GEN_TEST ( gen_type2_test2, 48 );

DECL_SEEDCALC_TEST ( seedcalc_type1_test1, 24 );
DECL_SEEDCALC_TEST ( seedcalc_type1_test2, 24 );
DECL_SEEDCALC_TEST ( seedcalc_type1_test3, 24 );
DECL_SEEDCALC_TEST ( seedcalc_type2_test1, 48 );
DECL_SEEDCALC_TEST ( seedcalc_type2_test2, 48 );
DECL_SEEDCALC_TEST ( seedcalc_type2_test3, 48 );

DECL_KEY ( key_a );
DECL_KEY ( key_b );

#endif /* _CX_TEST_H */
