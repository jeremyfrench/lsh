/* read_scan.c
 *
 * Buffered reader, which passes characters one at a time to a
 * scanner.
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <assert.h>
#include "read_scan.h"

#include "xalloc.h"

#define GABA_DEFINE
#include "read_scan.h.x"
#undef GABA_DEFINE

#include "read_scan.c.x"

/* GABA:
   (class
     (name read_scan)
     (super read_handler)
     (vars
       (buffer_size . size_t)
       (scanner object scanner)))
*/

/* FIXME: Keep track of lines and characters processed, do provide
 * decent error messages. */
static int do_read_scan(struct read_handler **h,
			struct abstract_read *read)
{
  CAST(read_scan, closure, *h);

  UINT8 *buffer = alloca(closure->buffer_size);
  int n;
  int i;
  assert(closure->buffer_size > 0);
  n = A_READ(read, closure->buffer_size, buffer);
  
  switch(n)
    {
    case 0:
      return LSH_OK | LSH_GOON;
    case A_FAIL:
      (void) SCAN(closure->scanner, TOKEN_ERROR);
      return LSH_FAIL | LSH_DIE;
    case A_EOF:
      return LSH_CLOSE | SCAN(closure->scanner, TOKEN_EOF);
    }
  
  for (i = 0; i<n; i++)
    {
      int res;
#if 0
      if (!closure->scanner)
	return LSH_CLOSE;
#endif
      res = SCAN(closure->scanner, buffer[i]);
      if (LSH_FAILUREP(res))
	return res | LSH_DIE;

      if (!closure->scanner)
	return res | LSH_CLOSE;
    }

  return LSH_OK | LSH_GOON;
}

struct read_handler *make_read_scan(size_t buffer_size, struct scanner *scanner)
{
  NEW(read_scan, closure);

  closure->buffer_size = buffer_size;
  closure->scanner = scanner;

  closure->super.handler = do_read_scan;

  return &closure->super;
}
