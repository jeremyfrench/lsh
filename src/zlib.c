/* zlib.c
 *
 * zlib compression algorithm
 * 
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998 Balázs Scheidler, Niels Möller
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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include "compress.h"
#include "format.h"
#include "lsh_string.h"
#include "ssh.h"
#include "werror.h"
#include "xalloc.h"

#if WITH_ZLIB

#if HAVE_ZLIB_H
#include <zlib.h>
#endif

#include <assert.h>

static void do_free_zstream(z_stream *z);
  
#include "zlib.c.x"

/* GABA:
   (class
     (name zlib_instance)
     (super compress_instance)
     (vars
       (f pointer (function int "z_stream *" int))
       (z indirect-special z_stream
          #f do_free_zstream)))
*/

/* GABA:
   (class
     (name zlib_algorithm)
     (super compress_algorithm)
     (vars
       (level . int)))
*/

/* Stored in the opaque pointer. */
struct zlib_type
{
  int (*free_func)(z_stream *z);
  const char *operation;
};

#define ZLIB_TYPE(z) ((struct zlib_type *)((z)->opaque))

static const struct zlib_type
zlib_inflate = {  inflateEnd, "inflate" };

static const struct zlib_type
zlib_deflate = {  deflateEnd, "deflate" };

/* zlib memory functions */
static void *
zlib_alloc(void *opaque UNUSED, unsigned int items, unsigned int size)
{
  return lsh_space_alloc(items * size);
}

static void
zlib_free(void *opaque UNUSED, void *address)
{
  lsh_space_free(address);
}

static void
do_free_zstream(z_stream *z)
{
  /* We use the opaque pointer, as there's nothing else to help us
   * figure if we should be calling inflateEnd or deflateEnd. */

  const struct zlib_type *type = ZLIB_TYPE(z);
  
  int res = type->free_func(z);

  if (res != Z_OK)
    debug("do_free_zstream (%z): Freeing failed: %z\n",
	  type->operation, z->msg ? z->msg : "No error");
}

/* Compress incoming data */
static uint32_t
do_zlib(struct compress_instance *c,
	struct lsh_string *output, uint32_t start,
	uint32_t length, const uint8_t *input)
{
  CAST(zlib_instance, self, c);
  uint32_t space;
  int rc;

  assert(length > 0);
  
  /* The cast is needed because zlib, at least version 1.1.4, doesn't
     use const */
  self->z.next_in = (uint8_t *) input;
  self->z.avail_in = length;

  space = lsh_string_length(output) - start;
  
  rc = lsh_string_zlib(output, start,
		       self->f, &self->z, Z_SYNC_FLUSH,
		       space);
  switch (rc)
    {
    case Z_BUF_ERROR:
      /* If avail_in is zero, this just means that all data have
       * been flushed. */
      if (self->z.avail_in)
	werror("do_zlib (%z): Z_BUF_ERROR (probably harmless),\n"
	       "  avail_in = %i, avail_out = %i\n",
	       ZLIB_TYPE(&self->z)->operation,
	       self->z.avail_in, self->z.avail_out);
      /* Fall through */
    case Z_OK:
      break;
    default:
      werror("do_zlib: %z failed: %z\n",
	     ZLIB_TYPE(&self->z)->operation,
	     self->z.msg ? self->z.msg : "No error(?)");
      
      return 0;
    }
      
  /* NOTE: It's not enough to check that avail_in is zero to determine
     that all data have been flushed. avail_in == 0 and avail_out > 0
     implies that all data has been flushed, but if avail_in ==
     avail_out == 0, we have to allocate more output space. */
	 
  if (!self->z.avail_out)
    {
      /* All output space consumed. This is an error, since the
	 available space is one byte more than the maximum packet
	 size */
      return 0;
    }

  /* Output space available, and no error. Then we must have processed all input. */
  assert(!self->z.avail_in);

  return space - self->z.avail_out;

}

static struct compress_instance *
make_zlib_instance(struct compress_algorithm *c, int mode)
{
  CAST(zlib_algorithm, closure, c);
  NEW(zlib_instance, res);

  res->z.zalloc = zlib_alloc;
  res->z.zfree = zlib_free;

  switch (mode)
    {
      case COMPRESS_DEFLATE:
	res->z.opaque = (void *) &zlib_deflate;
	res->f = deflate;
        res->super.codec = do_zlib;

        if (deflateInit(&res->z, closure->level) != Z_OK)
          {
            werror("deflateInit failed: %z\n",
                   res->z.msg ? res->z.msg : "No error(?)");
            KILL(res);
            return NULL;
          }
        break;

    case COMPRESS_INFLATE:
	res->z.opaque = (void *) &zlib_inflate;
	res->f = inflate;
        res->super.codec = do_zlib;

        if (inflateInit(&res->z) != Z_OK)
          {
            werror("inflateInit failed: %z\n",
                   res->z.msg ? res->z.msg : "No error(?)");
            KILL(res);
            return NULL;
          }
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

#endif /* WITH_ZLIB */
