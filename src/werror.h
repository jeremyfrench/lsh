/* werror.h
 *
 *
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

#ifndef LSH_ERROR_H_INCLUDED
#define LSH_ERROR_H_INCLUDED

#include "lsh_types.h"

#include "bignum.h"

/* Global variables */
extern int debug_flag;
extern int quiet_flag;
extern int verbose_flag;

void werror(CONST char *format, ...) PRINTF_STYLE(1,2);
void debug(CONST char *format, ...) PRINTF_STYLE(1,2);
void verbose(CONST char *format, ...) PRINTF_STYLE(1,2);

/* For outputting data recieved from the other end */
void werror_safe(UINT32 length, UINT8 *msg);
void debug_safe(UINT32 length, UINT8 *msg);
void verbose_safe(UINT32 length, UINT8 *msg);

void werror_utf8(UINT32 length, UINT8 *msg);
void debug_utf8(UINT32 length, UINT8 *msg);
void verbose_utf8(UINT32 length, UINT8 *msg);

void fatal(CONST char *format, ...) PRINTF_STYLE(1,2) NORETURN;

void werror_hex(UINT32 length, UINT8 *data);
void debug_hex(UINT32 length, UINT8 *data);
void verbose_hex(UINT32 length, UINT8 *data);

void werror_mpz(mpz_t n);
void debug_mpz(mpz_t n);
void verbose_mpz(mpz_t n);

#endif /* LSH_ERROR_H_INCLUDED */
