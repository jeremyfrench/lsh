/* xalloc.h
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

#ifndef LSH_XALLOC_H_INCLUDED
#define LSH_XALLOC_H_INCLUDED

#include <stdlib.h>
#include "lsh_types.h"

void *xalloc(size_t size);

/* Allocation */

/* The memory allocation model (for strings) is as follows:
 *
 * Packets are allocated when the are needed. A packet may be passed
 * through a chain of processing functions, until it is finally
 * discarded or transmitted, at which time it is deallocated.
 * Processing functions may deallocate their input packets and
 * allocate fresh packets to pass on; therefore, any data from a
 * packet that is needed later must be copied into some other storage.
 *
 * At any time, each packet is own by a a particular processing
 * function. Pointers into a packet are valid only while you own it.
 * */

struct lsh_string *lsh_string_alloc(UINT32 size);
void lsh_string_free(struct lsh_string *packet);

#ifdef DEBUG_ALLOC

void *debug_malloc(size_t size);
void debug_free(void *m);
void debug_check_object(void *m, UINT32 size);

#define lsh_free debug_free
#define lsh_malloc debug_malloc
#define MDEBUG(x) debug_check_object(x, sizeof(*(x)))

#else   /* !DEBUG_ALLOC */

#define lsh_free free
#define lsh_malloc malloc
#define MDEBUG(x)
#endif  /* !DEBUG_ALLOC */

#endif /* LSH_XALLOC_H_INCLUDED */
