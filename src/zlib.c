/* zlib.c
 *
 * zlib compression algorithm
 * 
 * $Id$ */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998 Balazs Scheidler, Niels Möller
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

#include "compress.h"
#include "format.h"
#include "string_buffer.h"
#include "werror.h"
#include "xalloc.h"

#if HAVE_ZLIB_H
#include <zlib.h>
#else
#error zlib.h not present
#endif

static void do_free_zstream(z_stream *z);
  
#include "zlib.c.x"

/* CLASS:
   (class
     (name zlib_instance)
     (super compress_instance)
     (vars
       ;; Fail before producing larger packets than this
       (max . UINT32)
       (f pointer (function int "z_stream *" int))
       (z special-struct z_stream
          #f do_free_zstream)))
*/

/* CLASS:
   (class
     (name zlib_algorithm)
     (super compress_algorithm)
     (vars
       (level . int)))
*/

/* I'm reworking the zlib stuff a little. So it doesn't work at all now.
 * /nisse */

#if 0 && WITH_ZLIB

/* zlib memory functions */
static void *zlib_alloc(void *opaque UNUSED, unsigned int items, unsigned int size)
{
  return lsh_space_alloc(items * size);
}

static void zlib_free(void *opaque UNUSED, void *address)
{
  lsh_space_free(address);
}

static void do_free_zstream(z_stream *z)
{
  /* Call deflateEnd() or inflateEnd(). But which? We use the opague
   * pointer, as we don't use that for anything else. */

  int (*free)(z_stream *z) = z->opaque;
  int res = free(z);

  if (res != Z_OK)
    werror("do_free_zstream: Freeing failed: %z\n",
	   z->msg ? z->msg : "No error");
}

/* Compress incoming data */
static struct lsh_string *do_zlib_deflate(struct compress_instance *c,
					  struct lsh_string *packet,
					  int free)
{
  CAST(zlib_instance, self, c);
  struct string_buffer buffer;
  UINT32 limit = self->max;
  
  if (!packet->length)
    {
      werror("do_zlib_deflate: Compressing empty packet.\n");
      return free ? packet : lsh_string_dup(packet);
    }
  
  /* FIXME: This will break if the total_* counters ever overflow. Is
   * that a problem? */
  float rate = (self->z->total_in
		? (float) self->z->total_out / self->z->total_in + 0.1
		: 1.0);
  
  string_buffer_init(&buffer, 
		     /* This value is somewhat arbitrary */
		     MIN(self->max, (UINT32) (rate * packet->length) + 100));

  limit -= buffer->partial->length;
  
  self->z->next_in = packet->data;
  self->z->avail_in = packet->length;

  for (;;)
    {
      int rc;
      
      assert(self->z->avail_in);
      
      self->z->next_out = buffer.current;
      self->z->avail_out = buffer.left;

      rc = deflate(&self->z, Z_SYNC_FLUSH);

      if (rc != Z_OK)
	{
	  werror("do_zlib_deflate: deflate() failed: %z\n",
		 z->msg ? z->msg : "No error(?)");
	  if (free)
	    lsh_string_free(packet);

	  return NULL;
	}

      if (!self->z->avail_in)
	{ /* Compressed entire packet */
	  if (free)
	    lsh_string_free(packet);

	  return string_buffer_final(&buffer, buffer->left - self->z->avail_out);
	}
      else
	{ /* All output space consumed */
	  assert(!self->z->avail_out);
	  
	  if (!limit)
	    {
	      werror("do_zlib_deflate: Packet grew too large!\n");
	      if (free)
		lsh_string_free(packet);

	      string_buffer_vlear(buffer);
	      return NULL;
	    }

	  string_buffer_grow(&buffer, MIN(limit, packet->length + 100));
	  limit -= buffer->partial->length;
	}
    }
}

/* Decompress incoming data */
static struct lsh_string *do_zlib_inflate(struct compress_instance *c,
					  struct lsh_string *packet,
					  int free)
{
  CAST(zlib_instance, self, c);
  struct string_buffer buffer;

  if (!packet->length)
    {
      werror("do_zlib_deflate: Compressing empty packet.\n");
      return free ? packet : lsh_string_dup(packet);
    }
  
  /* FIXME: This will break if the total_* counters ever overflow. Is
   * that a problem? */
  float rate = (self->z->total_in
		? (float) self->z->total_out / self->z->total_in + 0.1
		: 1.0);
  
  string_buffer_init(&buffer, 
		     /* This value is somewhat arbitrary */
		     (UINT32) (rate * packet->length) + 100);

  self->z->next_in = packet->data;
  self->z->avail_in = packet->length;

  for (;;)
    {
      int rc;
      
      assert(self->z->avail_in);
      
      self->z->next_out = buffer.current;
      self->z->avail_out = buffer.left;

      rc = deflate(&self->z, Z_SYNC_FLUSH);

      if (rc != Z_OK)
	{
	  werror("do_zlib_deflate: deflate() failed: %z\n",
		 z->msg ? z->msg : "No error(?)");
	  return NULL;
	}

      if (!self->z->avail_in)
	{ /* Compressed entire packet */
	  if (free)
	    lsh_string_free(packet);

	  return string_buffer_final(&buffer, buffer->left - self->z->avail_out);
	}
      else
	{ /* All output space consumed */
	  assert(!self->z->avail_out);

	  string_buffer_grow(&buffer, packet->length + 100);
	}
    }
}

#if 0
static struct lsh_string *do_zlib_deflate(struct compress_instance *c,
					  struct lsh_string *data,
					  int free)
{
  CAST(zlib_instance, self, c);
  struct lsh_string *chunk, *compressed;
  int rc;

  /* deflated packet may be longer */  
  chunk = lsh_string_alloc(2 * data->length + 10);
  
  self->zstream.next_in = (char *) &data->data;
  self->zstream.avail_in = data->length;
  compressed = NULL;
  
  while (self->zstream.avail_in)
    {
      self->zstream.next_out = (char *) &chunk->data;
      self->zstream.avail_out = 2 * data->length + 10;
      self->zstream.total_out = 0;
      rc = deflate(&self->zstream, Z_SYNC_FLUSH);
      if (compressed) {
        compressed = ssh_format("%lfS%ls", compressed,
				self->zstream.total_out, chunk->data);
      }
      else {
        compressed = ssh_format("%ls", self->zstream.total_out, chunk->data);
      }
    }
    
  lsh_string_free(chunk);

  if (free)
    lsh_string_free(data);
  
  return compressed;
}
#endif

/* decompress incoming data */
static struct lsh_string *do_zlib_inflate(struct compress_instance *c,
					  struct lsh_string *data,
					  int free)
{
  CAST(zlib_instance, self, c);
  struct lsh_string *chunk, *uncompressed;
  int rc;

  /* let's assume data can be compressed to 50% */
  
  chunk = lsh_string_alloc(2 * data->length + 10); 
  self->zstream.next_in = (char *) &data->data;
  self->zstream.avail_in = data->length;
  uncompressed = NULL;
  
  while (self->zstream.avail_in)
    {
      self->zstream.next_out = (char *) &chunk->data;
      self->zstream.avail_out = 2 * data->length + 10;
      self->zstream.total_out = 0;
      rc = inflate(&self->zstream, Z_SYNC_FLUSH);
      if (uncompressed) {
        uncompressed = ssh_format("%lfS%ls", uncompressed,
				  self->zstream.total_out, chunk->data);
      }
      else {
        uncompressed = ssh_format("%ls", self->zstream.total_out, chunk->data);
      }
    }
    
  lsh_string_free(chunk);
  if (free)
    lsh_string_free(data);
    
  return uncompressed;  
}

static struct compress_instance *
make_zlib_instance(struct compress_algorithm *c, int mode)
{
  CAST(zlib_algorithm, closure, c);
  NEW(zlib_instance, res);

  res->zstream.zalloc = zlib_alloc;
  res->zstream.zfree = zlib_free;
  switch (mode)
    {
      case COMPRESS_DEFLATE:
	res->zstream.opaque = foo_deflate;
        res->super.codec = do_zlib_deflate;
        deflateInit(&res->zstream, closure->level);
        break;
      case COMPRESS_INFLATE:
	res->zstream.opaque = foo_inflate;
        res->super.codec = do_zlib_inflate;
        inflateInit(&res->zstream);
        break;
    }
  return &res->super;
}

struct compress_algorithm *make_zlib_algorithm(int level)
{
  if ( (level != Z_DEFAULT_COMPRESSION)
       && ( (level < Z_NO_COMPRESSION)
	    || (level > Z_BEST_COMPRESSION) ))
    return NULL;
  else
    {
      NEW(zlib_algorithm, closure);
      
      closure->super.make_compress = make_zlib_instance;
      closure->level = level;

      return &closure->super;
    }
}

struct compress_algorithm *make_zlib(void)
{
  return make_zlib_algorithm(Z_DEFAULT_COMPRESSION);
}

#endif /* 0 */
