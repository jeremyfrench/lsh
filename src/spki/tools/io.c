/* io.c */

/* libspki
 *
 * Copyright (C) 2003 Niels Möller
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

#include "io.h"

#include <stdlib.h>

#define BUFSIZE 1000

/* NOTE: More or less the same as as nettle/examples/io.c */
int
hash_file(const struct nettle_hash *hash, void *ctx, FILE *f)
{
  for (;;)
    {
      char buffer[BUFSIZE];
      size_t res = fread(buffer, 1, sizeof(buffer), f);
      if (ferror(f))
	return 0;
      
      hash->update(ctx, res, buffer);
      if (feof(f))
	return 1;
    }  
}

/* If size is > 0, read at most that many bytes. If size == 0,
 * read until EOF. Allocates the buffer dynamically. */
unsigned
read_file(FILE *f, unsigned max_size, char **contents)
{
  unsigned size;
  unsigned done;
  char *buffer;
  buffer = NULL;

  if (max_size && max_size < 100)
    size = max_size;
  else
    size = 100;
  
  for (size = 100, done = 0;
       (!max_size || done < max_size) && !feof(f);
       size *= 2)
    {
      char *p;

      if (max_size && size > max_size)
	size = max_size;

      /* Space for terminating NUL */
      p = realloc(buffer, size + 1);

      if (!p)
	{
	fail:
	  fclose(f);
	  free(buffer);
	  *contents = NULL;
	  return 0;
	}

      buffer = p;
      done += fread(buffer + done, 1, size - done, f);

      if (ferror(f))
	goto fail;
    }
  
  /* NUL-terminate the data. */
  buffer[done] = '\0';
  *contents = buffer;
  
  return done;
}

/* If size is > 0, read at most that many bytes. If size == 0,
 * read until EOF. Allocates the buffer dynamically. */
unsigned
read_file_by_name(const char *name, unsigned max_size, char **contents)
{
  unsigned done;
  FILE *f;
    
  f = fopen(name, "rb");
  if (!f)
    return 0;

  done = read_file(f, max_size, contents);
  fclose(f);

  return done;
}

int
write_file(FILE *f, unsigned size, const char *buffer)
{
  unsigned res;
  
  res = fwrite(buffer, 1, size, f);
  
  if (res < size || ferror(f))
    res = 0;

  return res > 0;
}
