/* format.h
 *
 * Create a packet from a format string and arguments.
 *
 * $Id$ */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998 Niels Möller
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef LSH_FORMAT_H_INCLUDED
#define LSH_FORMAT_H_INCLUDED

#include <stdarg.h>

#include "atoms.h"
#include "bignum.h"

/* Format strings can contain the following %-specifications:
 *
 * %%  Insert a %-sign
 *
 * %c  Insert an 8-bit character
 *
 * %i  Insert an 32-bit integer, in network byte order
 *
 * %s  Insert a string, given by a length and a pointer.
 *
 * %S  Insert a string, given as a struct lsh_string pointer.
 *
 * %z  Insert a string, using a null-terminated argument.
 *
 * %r  Reserves space in the string, and stores a pointer to this space
 *     into the given UINT8 ** argument.
 *
 * %a  Insert a string containing one atom.
 *
 * %A  Insert a string containing a list of atoms. The corresponding
 *     argument sublist should be a int* pointing to a list of atoms,
 *     terminated with -1.
 *
 * %X  Insert a string containing a list of atoms. The corresponding
 *     argument sublist should be terminated with a zero. (Not used)
 *
 * %n  Insert a string containing a bignum.
 *
 * There are two valid modifiers:
 *
 * "l" (as in literal). It is applicable to the s, a, A, n and r
 * specifiers, and outputs strings *without* a length field.
 *
 * "f" (as in free). Frees the input string after it has been copied.
 * Applicable to %S only. */

UINT32 ssh_vformat_length(char *format, va_list args);
UINT32 ssh_vformat(char *format, UINT8 *buffer, va_list args);
struct lsh_string *ssh_format(char *format, ...);

/* Short cut */
#define lsh_string_dup(s) (ssh_format("%lS", (s)))

#endif /* LSH_FORMAT_H_INCLUDED */
