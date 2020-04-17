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

#ifndef _CX_H
#define _CX_H

/** Generator type */
enum cx_generator_type {
	CX_GEN_AES_128_CTR_2048 = 1,
	CX_GEN_AES_256_CTR_2048 = 2,
};

/**
 * A contact identifier
 *
 * Each contact identifier is an opaque RFC 4122 version 4 UUID,
 * represented as sixteen bytes in network byte order.
 */
struct cx_contact_id {
	/** Raw bytes */
	unsigned char bytes[16];
};

#endif /* _CX_H */
