/* yarrow256.c
 *
 * The yarrow pseudo-randomness generator.
 */

/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2001 Niels M�ller
 *  
 * The nettle library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 * 
 * The nettle library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with the nettle library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 */

#include "yarrow.h"

#include "macros.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#ifndef YARROW_DEBUG
#define YARROW_DEBUG 0
#endif

#if YARROW_DEBUG
#include <stdio.h>
#endif

/* Parameters */

/* An upper limit on the entropy (in bits) in one octet of sample
 * data. */
#define YARROW_MULTIPLIER 4

/* Entropy threshold for reseeding from the fast pool */
#define YARROW_FAST_THRESHOLD 100

/* Entropy threshold for reseeding from the fast pool */
#define YARROW_SLOW_THRESHOLD 160

/* Number of sources that must exceed the threshold for slow reseed */
#define YARROW_SLOW_K 2

/* The number of iterations when reseeding, P_t in the yarrow paper.
 * Should be chosen so that reseeding takes on the order of 0.1-1
 * seconds. */
#define YARROW_RESEED_ITERATIONS 1500

/* Entropy estimates sticks to this value, it is treated as infinity
 * in calculations. It should fit comfortably in an uint32_t, to avoid
 * overflows. */
#define YARROW_MAX_ENTROPY 0x100000

/* Forward declarations */

static void
yarrow_fast_reseed(struct yarrow256_ctx *ctx);

static void
yarrow_gate(struct yarrow256_ctx *ctx);

void
yarrow256_init(struct yarrow256_ctx *ctx,
	       unsigned n,
	       struct yarrow_source *s)
{
  unsigned i;

  sha256_init(&ctx->pools[0]);
  sha256_init(&ctx->pools[1]);
  
  ctx->seeded = 0;

  ctx->nsources = n;
  ctx->sources = s;

  for (i = 0; i<n; i++)
    {
      ctx->sources[i].estimate[YARROW_FAST] = 0;
      ctx->sources[i].estimate[YARROW_SLOW] = 0;
      ctx->sources[i].next = YARROW_FAST;
    }
}

void
yarrow256_seed(struct yarrow256_ctx *ctx,
	       unsigned length,
	       uint8_t *seed_file)
{
  /* FIXME: Perhaps it's better to use assert ? */
  if (!length)
    return;

  sha256_update(&ctx->pools[YARROW_FAST], length, seed_file);
  yarrow_fast_reseed(ctx);

  ctx->seeded = 1;
}

/* FIXME: Generalize so that it generates a few more blocks at a
 * time. */
static void
yarrow_generate_block(struct yarrow256_ctx *ctx,
		      uint8_t *block)
{
  unsigned i;
  
  aes_encrypt(&ctx->key, sizeof(ctx->counter), block, ctx->counter);

  /* Increment counter, treating it as a big-endian number. This is
   * machine independent, and follows appendix B of the NIST
   * specification of cipher modes of operation.
   *
   * We could keep a representation of thy counter as 4 32-bit values,
   * and write entire words (in big-endian byteorder) into the counter
   * block, whenever they change. */
  for (i = sizeof(ctx->counter); i--; )
    {
      if (++ctx->counter[i])
	break;
    }
}

static void
yarrow_iterate(uint8_t *digest)
{
  uint8_t v0[SHA256_DIGEST_SIZE];
  unsigned i;
  
  memcpy(v0, digest, SHA256_DIGEST_SIZE);
  
  /* When hashed inside the loop, i should run from 1 to
   * YARROW_RESEED_ITERATIONS */
  for (i = 0; ++i < YARROW_RESEED_ITERATIONS; )
    {
      uint8_t count[4];
      struct sha256_ctx hash;
  
      sha256_init(&hash);

      /* Hash v_i | v_0 | i */
      WRITE_UINT32(count, i);
      sha256_update(&hash, SHA256_DIGEST_SIZE, digest);
      sha256_update(&hash, sizeof(v0), v0);
      sha256_update(&hash, sizeof(count), count);

      sha256_final(&hash);
      sha256_digest(&hash, SHA256_DIGEST_SIZE, digest);
    }
}

/* NOTE: The SHA-256 digest size equals the AES key size, so we need
 * no "size adaptor". */

static void
yarrow_fast_reseed(struct yarrow256_ctx *ctx)
{
  uint8_t digest[SHA256_DIGEST_SIZE];
  unsigned i;
  
#if YARROW_DEBUG
  fprintf(stderr, "yarrow_fast_reseed\n");
#endif
  
  /* We feed two block of output using the current key into the pool
   * before emptying it. */
  if (ctx->seeded)
    {
      uint8_t blocks[AES_BLOCK_SIZE * 2];
      
      yarrow_generate_block(ctx, blocks);
      yarrow_generate_block(ctx, blocks + AES_BLOCK_SIZE);
      sha256_update(&ctx->pools[YARROW_FAST], sizeof(blocks), blocks);
    }
  
  sha256_final(&ctx->pools[YARROW_FAST]);
  sha256_digest(&ctx->pools[YARROW_FAST], sizeof(digest), digest);
  sha256_init(&ctx->pools[YARROW_FAST]);

  /* Iterate */
  yarrow_iterate(digest);

  aes_set_key(&ctx->key, sizeof(digest), digest);

  /* Derive new counter value */
  memset(ctx->counter, 0, sizeof(ctx->counter));
  aes_encrypt(&ctx->key, sizeof(ctx->counter), ctx->counter, ctx->counter);
  
  /* Reset estimates. */
  for (i = 0; i<ctx->nsources; i++)
    ctx->sources[i].estimate[YARROW_FAST] = 0;

  /* New seed file. */
  /* FIXME: Extract this into a function of its own. */
  for (i = 0; i < sizeof(ctx->seed_file); i+= AES_BLOCK_SIZE)
    yarrow_generate_block(ctx, ctx->seed_file + i);

  yarrow_gate(ctx);
}

static void
yarrow_slow_reseed(struct yarrow256_ctx *ctx)
{
  uint8_t digest[SHA256_DIGEST_SIZE];
  unsigned i;

#if YARROW_DEBUG
  fprintf(stderr, "yarrow_slow_reseed\n");
#endif

  /* Get digest of the slow pool*/
  
  sha256_final(&ctx->pools[YARROW_SLOW]);
  sha256_digest(&ctx->pools[YARROW_SLOW], sizeof(digest), digest);
  sha256_init(&ctx->pools[YARROW_SLOW]);

  /* Feed it into the fast pool */
  sha256_update(&ctx->pools[YARROW_SLOW], sizeof(digest), digest);

  yarrow_fast_reseed(ctx);
  
  /* Reset estimates. */
  for (i = 0; i<ctx->nsources; i++)
    ctx->sources[i].estimate[YARROW_SLOW] = 0;
}

int
yarrow256_update(struct yarrow256_ctx *ctx,
		 unsigned source_index, unsigned entropy,
		 unsigned length, const uint8_t *data)
{
  enum yarrow_pool_id current;
  struct yarrow_source *source;
  
  assert(source_index < ctx->nsources);

  if (!length)
    /* Nothing happens */
    return 0;

  source = &ctx->sources[source_index];
  
  if (!ctx->seeded)
    /* While seeding, use the slow pool */
    current = YARROW_SLOW;
  else
    {
      current = source->next;
      source->next = !source->next;
    }

  sha256_update(&ctx->pools[current], length, data);
 
  /* NOTE: We should be careful to avoid overflows in the estimates. */
  if (source->estimate[current] < YARROW_MAX_ENTROPY)
    {
      if (entropy > YARROW_MAX_ENTROPY)
	entropy = YARROW_MAX_ENTROPY;

      if ( (length < (YARROW_MAX_ENTROPY / YARROW_MULTIPLIER))
	   && (entropy > YARROW_MULTIPLIER * length) )
	entropy = YARROW_MULTIPLIER * length;

      /* FIXME: Calling a more sophisticated estimater should be done
       * here. */

      entropy += source->estimate[current];
      if (entropy > YARROW_MAX_ENTROPY)
	entropy = YARROW_MAX_ENTROPY;

      source->estimate[current] = entropy;
    }

  /* Check for seed/reseed */
  switch(current)
    {
    case YARROW_FAST:
#if YARROW_DEBUG
      fprintf(stderr,
              "yarrow256_update: source_index = %d,\n"
              "            fast pool estimate = %d\n",
              source_index, source->estimate[YARROW_FAST]);
#endif
      if (source->estimate[YARROW_FAST] >= YARROW_FAST_THRESHOLD)
	{
	  yarrow_fast_reseed(ctx);
	  return 1;
	}
      else
	return 0;

    case YARROW_SLOW:
      {
	/* FIXME: This is somewhat inefficient. It would be better to
	 * either maintain the count, or do this loop only if the
	 * current source just crossed the threshold. */
        
        if (!yarrow256_needed_sources(ctx))
	  {
	    yarrow_slow_reseed(ctx);
	    ctx->seeded = 1;

	    return 1;
	  }
	else
	  return 0;
      }
    default:
      abort();
    }
}

static void
yarrow_gate(struct yarrow256_ctx *ctx)
{
  uint8_t key[AES_MAX_KEY_SIZE];
  unsigned i;

  for (i = 0; i < sizeof(key); i+= AES_BLOCK_SIZE)
    yarrow_generate_block(ctx, key + i);

  aes_set_key(&ctx->key, sizeof(key), key);
}

void
yarrow256_random(struct yarrow256_ctx *ctx, unsigned length, uint8_t *dst)
{
  assert(ctx->seeded);

  while (length >= AES_BLOCK_SIZE)
    {
      yarrow_generate_block(ctx, dst);
      dst += AES_BLOCK_SIZE;
      length -= AES_BLOCK_SIZE;
    }
  if (length)
    {
      uint8_t buffer[AES_BLOCK_SIZE];
      
      assert(length < AES_BLOCK_SIZE);
      yarrow_generate_block(ctx, buffer);
      memcpy(dst, buffer, length);
    }
  yarrow_gate(ctx);
}

int
yarrow256_is_seeded(struct yarrow256_ctx *ctx)
{
  return ctx->seeded;
}

unsigned
yarrow256_needed_sources(struct yarrow256_ctx *ctx)
{
  /* FIXME: This is somewhat inefficient. It would be better to
   * either maintain the count, or do this loop only if the
   * current source just crossed the threshold. */
  unsigned k, i;

  for (i = k = 0; i < ctx->nsources; i++)
    if (ctx->sources[i].estimate[YARROW_SLOW] >= YARROW_SLOW_THRESHOLD)
      k++;

#if YARROW_DEBUG
  fprintf(stderr,
          "yarrow256_needed_sources: source_index = %d,\n"
          "                    slow pool estimate = %d,\n"
          "     number of sources above threshold = %d\n",
          source_index, source->estimate[YARROW_SLOW], k);
#endif
  
  return (k < YARROW_SLOW_K) ? (YARROW_SLOW_K - k) : 0;
}
