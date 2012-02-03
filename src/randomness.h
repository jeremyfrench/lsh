/* randomness.h
 *
 */

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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef LSH_RANDOMNESS_H_INCLUDED
#define LSH_RANDOMNESS_H_INCLUDED

#include "lsh.h"

enum random_source_type
  {
    /* Trivial data such as timing info and pids. */
    RANDOM_SOURCE_TRIVIA,
    /* Remote end padding. */
    RANDOM_SOURCE_REMOTE,
    /* Data occasionally read from /dev/random or similar. */
    RANDOM_SOURCE_DEVICE,
    /* Data that is secret but not terribly random, such as user
     * passwords or private keys. */
    RANDOM_SOURCE_SECRET,
    /* For reread seed files. */
    RANDOM_SOURCE_NEW_SEED,
    RANDOM_NSOURCES
  };

void
random_generate(uint32_t length, uint8_t *dst);

void
random_add(enum random_source_type type, uint32_t length,
	   const uint8_t *data);

/* This is not really a constructor, as the randomness collector uses
 * global state. */
int
random_init(const struct lsh_string *seed_file_name);

int
random_init_user(const char *home);

int
random_init_system(void);

/* Randomness function matching nettle's expectations. */
void
lsh_random(void *ctx, unsigned length, uint8_t *data);

#endif /* LSH_RANDOMNESS_H_INCLUDED */
