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

#include "lsh_types.h"
#include <stdlib.h>

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

void *lsh_object_alloc(size_t size);
void lsh_object_free(void *p);

void *lsh_space_alloc(size_t size);
void lsh_space_free(void *p);


#ifdef DEBUG_ALLOC

void lsh_object_check(void *m, size_t size);
void lsh_object_check_subtype(void *m, size_t size);

#define MDEBUG(x) lsh_object_check((x), sizeof(*(x)))
#define MDEBUG_SUBTYPE(x) lsh_object_check_subtype((x), sizeof(*(x)))

#else   /* !DEBUG_ALLOC */

#define MDEBUG(x)
#define MDEBUG_SUBTYPE(x)

#endif  /* !DEBUG_ALLOC */

#define NEW(x) ((x) = lsh_object_alloc(sizeof(*(x))))
#define NEW_SPACE(x) ((x) = lsh_space_alloc(sizeof(*(x))))


#endif /* LSH_XALLOC_H_INCLUDED */
