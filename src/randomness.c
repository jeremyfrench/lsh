/* randomness.c
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

#include "randomness.h"

#include "werror.h"

#include "crypto.h"
#include "xalloc.h"

#include <errno.h>

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <string.h>

#define CLASS_DEFINE
#include "randomness.h.x"
#undef CLASS_DEFINE

#include "randomness.c.x"

/* Random */
/* CLASS:
   (class
     (name poor_random)
     (super randomness)
     (vars
       (hash object hash_instance)
       (pos simple UINT32)
       (buffer space UINT8)))
*/

static void do_poor_random(struct randomness *r, UINT32 length, UINT8 *dst)
{
  CAST(poor_random, self, r);

  while(length)
    {
      UINT32 available = self->hash->hash_size - self->pos;
      UINT32 to_copy;
      
      if (!available)
	{
	  time_t now = time(NULL); /* To avoid cycles */
	  HASH_UPDATE(self->hash, sizeof(now), (UINT8 *) &now);
	  HASH_UPDATE(self->hash, self->hash->hash_size,
		      self->buffer);
	  HASH_DIGEST(self->hash, self->buffer);

	  available = self->hash->hash_size;
	  self->pos = 0;
	}
      to_copy = MIN(available, length);

      memcpy(dst, self->buffer + self->pos, to_copy);
      length -= to_copy;
      dst += to_copy;
      self->pos += to_copy;
    }
}

struct randomness *make_poor_random(struct hash_algorithm *hash,
				    struct lsh_string *init)
{
  NEW(poor_random, self);
  time_t now = time(NULL); 
  pid_t pid = getpid();
  
  self->super.random = do_poor_random;
  self->super.quality = 0;
  
  self->hash = MAKE_HASH(hash);
  self->buffer = lsh_space_alloc(hash->hash_size);
  
  HASH_UPDATE(self->hash, sizeof(now), (UINT8 *) &now);
  HASH_UPDATE(self->hash, sizeof(pid), (UINT8 *) &pid);
  
  if (init)
    {
      HASH_UPDATE(self->hash, init->length, init->data);
      lsh_string_free(init);
    }
  HASH_DIGEST(self->hash, self->buffer);

  self->pos = 0;

  return &self->super;
}

/* CLASS:
   (class
     (name device_random)
     (super randomness)
     (vars
       (fd . int)))
*/

static void do_device_random(struct randomness *r, UINT32 length, UINT8 *dst)
{
  CAST(device_random, self, r);

  while(length)
    {
      int n = read(self->fd, dst, length);

      if (!n)
	fatal("do_device_random: EOF on random source.\n");

      if (n<0)
	switch(errno)
	  {
	  case EINTR:
	    break;
	  default:
	    fatal("Read from random device failed (errno = %d): %s\n",
		  errno, strerror(errno));
	  }
      else
	{
	  length -= n;
	  dst += n;
	}
    }
}

/* NOTE: In most cases, blocking while waiting for more entropy to
 * arrive is not acceptable. So use /dev/urandom, not /dev/random. The
 * alternative is to read a smaller seed from /dev/random at startup,
 * and use an internal pseudorandom generator. That
 * would be friendlier to other applications, but would not buy as
 * more security, as /dev/urandom should degenerate to a fairly strong
 * pseudorandom generator when it runs out of entropy. */

struct randomness *make_device_random(const char *device)
{
  int fd = open(device, O_RDONLY);

  if (fd < 0)
    {
      werror("make_device_random: Failed to open '%s' (errno = %d): %s\n",
	     device, errno, strerror(errno));
      return NULL;
    }
  else
    {
      NEW(device_random, self);
      
      self->super.random = do_device_random;

      /* The quality depends on the used device. */
      self->super.quality = 0;
      self->fd = fd;
      
      return &self->super;
    }
}

struct randomness *make_reasonably_random(void)
{
  struct randomness *r = make_device_random("/dev/urandom");

  if (r)
    r->quality = 1;
  else
    {
      werror("Warning: Falling back to an insecure pseudorandom generator.\n");
      r = make_poor_random(&sha_algorithm, NULL);
    }

  return r;
}
