/* sha.h
 *
 * The sha1 and sha256 hash functions.
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
 
#ifndef NETTLE_SHA_H_INCLUDED
#define NETTLE_SHA_H_INCLUDED

#include "nettle-types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Name mangling */
#define sha1_init nettle_sha1_init
#define sha1_update nettle_sha1_update
#define sha1_digest nettle_sha1_digest
#define sha256_init nettle_sha256_init
#define sha256_update nettle_sha256_update
#define sha256_digest nettle_sha256_digest
#define sha384_init nettle_sha384_init
#define sha384_digest nettle_sha384_digest
#define sha512_init nettle_sha512_init
#define sha512_update nettle_sha512_update
#define sha512_digest nettle_sha512_digest

/* SHA1 */

#define SHA1_DIGEST_SIZE 20
#define SHA1_DATA_SIZE 64

/* Digest is kept internally as 5 32-bit words. */
#define _SHA1_DIGEST_LENGTH 5

struct sha1_ctx
{
  uint32_t digest[_SHA1_DIGEST_LENGTH];   /* Message digest */
  uint32_t count_low, count_high;         /* 64-bit block count */
  uint8_t block[SHA1_DATA_SIZE];          /* SHA1 data buffer */
  unsigned int index;                     /* index into buffer */
};

void
sha1_init(struct sha1_ctx *ctx);

void
sha1_update(struct sha1_ctx *ctx,
	    unsigned length,
	    const uint8_t *data);

void
sha1_digest(struct sha1_ctx *ctx,
	    unsigned length,
	    uint8_t *digest);

/* Internal compression function. STATE points to 5 uint32_t words,
   and DATA points to 64 bytes of input data, possibly unaligned. */
void
_nettle_sha1_compress(uint32_t *state, const uint8_t *data);

/* SHA256 */

#define SHA256_DIGEST_SIZE 32
#define SHA256_DATA_SIZE 64

/* Digest is kept internally as 8 32-bit words. */
#define _SHA256_DIGEST_LENGTH 8

struct sha256_ctx
{
  uint32_t state[_SHA256_DIGEST_LENGTH];    /* State variables */
  uint32_t count_low, count_high;           /* 64-bit block count */
  uint8_t block[SHA256_DATA_SIZE];          /* SHA256 data buffer */
  unsigned int index;                       /* index into buffer */
};

void
sha256_init(struct sha256_ctx *ctx);

void
sha256_update(struct sha256_ctx *ctx,
	      unsigned length,
	      const uint8_t *data);

void
sha256_digest(struct sha256_ctx *ctx,
	      unsigned length,
	      uint8_t *digest);

/* Internal compression function. STATE points to 8 uint32_t words,
   DATA points to 64 bytes of input data, possibly unaligned, and K
   points to the table of constants. */
void
_nettle_sha256_compress(uint32_t *state, const uint8_t *data, const uint32_t *k);

/* SHA512 */

#define SHA512_DIGEST_SIZE 64
#define SHA512_DATA_SIZE 128

/* Digest is kept internally as 8 64-bit words. */
#define _SHA512_DIGEST_LENGTH 8

struct sha512_ctx
{
  uint64_t state[_SHA512_DIGEST_LENGTH];    /* State variables */
  uint64_t count_low, count_high;           /* 128-bit block count */
  uint8_t block[SHA512_DATA_SIZE];          /* SHA512 data buffer */
  unsigned int index;                       /* index into buffer */
};

void
sha512_init(struct sha512_ctx *ctx);

void
sha512_update(struct sha512_ctx *ctx,
	      unsigned length,
	      const uint8_t *data);

void
sha512_digest(struct sha512_ctx *ctx,
	      unsigned length,
	      uint8_t *digest);

/* Internal compression function. STATE points to 8 uint64_t words,
   DATA points to 128 bytes of input data, possibly unaligned, and K
   points to the table of constants. */
void
_nettle_sha512_compress(uint64_t *state, const uint8_t *data, const uint64_t *k);

/* SHA384. */
/* This is the same algorithm as SHA512, but with different initial
   state and truncated output. */

#define SHA384_DIGEST_SIZE 48
#define SHA384_DATA_SIZE SHA512_DATA_SIZE
#define sha384_ctx sha512_ctx

void
sha384_init(struct sha512_ctx *ctx);

#define sha384_update nettle_sha512_update

void
sha384_digest(struct sha512_ctx *ctx,
	      unsigned length,
	      uint8_t *digest);

#ifdef __cplusplus
}
#endif

#endif /* NETTLE_SHA_H_INCLUDED */
