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

#ifndef _CX_GENERATOR_H
#define _CX_GENERATOR_H

#include <stddef.h>
#include <cx.h>

struct cx_generator;

extern size_t cx_gen_seed_len ( enum cx_generator_type type );

extern unsigned int cx_gen_max_iterations ( enum cx_generator_type type );

extern struct cx_generator * cx_gen_instantiate ( enum cx_generator_type type,
						  const void *seed,
						  size_t len );

extern int cx_gen_iterate ( struct cx_generator *gen,
			    struct cx_contact_id *id );

extern void cx_gen_invalidate ( struct cx_generator *gen );

extern void cx_gen_uninstantiate ( struct cx_generator *gen );

#endif /* _CX_GENERATOR_H */
