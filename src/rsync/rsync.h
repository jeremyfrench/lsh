/* rsync.h
 *
 * $Id$
 */

/* 
   Copyright (C) Andrew Tridgell 1996
   Copyright (C) Paul Mackerras 1996
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

/* Hacked by Niels Möller */
#ifndef RSYNC_H_INCLUDED
#define RSYNC_H_INCLUDED

#if LSH
# include "lsh_types.h"
#else
# if HAVE_CONFIG_H
#  include "config.h"
# endif
#endif

#include "md5.h"

#include <stdlib.h>

/* FIXME: replace with proper autoconf check */
#define OFF_T size_t

#define RSYNC_SUM_LENGTH MD5_DIGESTSIZE

/* Constant used in checksum calculation */
#define RSYNC_CHAR_OFFSET 0

struct rsync_sum_buf
{
  OFF_T offset;			/* offset in file of this chunk */
  unsigned len;			/* length of chunk of file */
  unsigned i;			/* index of this chunk */
  UINT32 sum1;	        	/* simple checksum */
  char sum2[RSYNC_SUM_LENGTH];  /* checksum */
};

/* Initial checksum calculations (by the receiver) */
#define RSYNC_INTERNAL_BUF_SIZE 20

/* NOTE: Unlike zlib, we want to know the file size before we start.
 * This could be relxed, but requires some modifications to the
 * protocol. */
struct rsync_generate_state
{
  /* Public fields */
  UINT8 *next_in;
  UINT32 avail_in;
  UINT8 *next_out;
  UINT32 avail_out;

  UINT32 block_size;
  UINT32 total_length;
  UINT32 offset; /* Current offset in input file. */

  /* Weak check sum */
  unsigned a_sum;
  unsigned c_sum;
  
  struct md5_ctx block_sum;

  /* Internal state */
  UINT8 buf[RSYNC_INTERNAL_BUF_SIZE];
  UINT8 buf_length; /* Zero means no buffered data. */
  UINT8 buf_pos;

  UINT32 left; /* Amount left of current block */
};

/* Return values */
/* Things are working fine */
#define RSYNC_PROGRESS    0
/* All data is flushed to the output */
#define RSYNC_DONE        1
/* No progress possible */
#define RSYNC_BUF_ERROR   2
/* Invalid input */
#define RSYNC_INPUT_ERROR 3

int rsync_generate(struct rsync_generate_state *state);
int rsync_generate_init(struct rsync_generate_state *state,
			UINT32 block_size,
			UINT32 size);


/* Receiving a file. */

/* The receiver calls this function to copy at most LENGTH octets of
 * local data to the output buffer.
 *
 * OPAQUE is state private to the lookup function. DST and LENGTH give
 * the location of the destination buffer. INDEX is the block to read,
 * and OFFSET is a location within that block.
 *
 * The function should return
 *
 * -1 on failure (and it has to check INDEX and OFFSET for validity).
 * 0 if copying succeeds, but not all of the block was copied.
 * 1 if copying succeeds, and the final octet of the data swas copied.
 *
 * On success, the function should set *DONE to the amount of data copied.
 */

typedef int (*rsync_lookup_read_t)(void *opaque,
				   UINT8 *dst, UINT32 length,
				   UINT32 index, UINT32 offset, UINT32 *done);

enum rsync_receive_mode;

struct rsync_receive_state
{
  /* Public fields */
  UINT8 *next_in;
  UINT32 avail_in;
  UINT8 *next_out;
  UINT32 avail_out;

  UINT32 block_size;
  /* UINT32 offset; */ /* Current offset in output file. */

  rsync_lookup_read_t lookup;
  void *opaque;
  
  struct md5_ctx full_sum; /* Sum of all input data */

  /* Private state */

  int state;
  
  UINT32 token; 
  UINT32 i;

  UINT8 buf[MD5_DIGESTSIZE];
};

int rsync_receive(struct rsync_receive_state *state);
void rsync_receive_init(struct rsync_receive_state *state);

#endif /* RSYNC_H_INCLUDED */
