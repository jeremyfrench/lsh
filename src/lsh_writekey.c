/* lsh_writekey.c
 *
 * Reads a (private) key on stdin, and saves it a private and a public file.
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

#include "blocking_write.h"
#include "format.h"
#include "io.h"
#include "sexp.h"
#include "werror.h"
#include "xalloc.h"

#include <errno.h>
#include <string.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "lsh_writekey.c.x"

/* FIXME: Should support encryption of the private key. */

static struct sexp *dsa_private2public(struct sexp_iterator *i)
{
  struct sexp *p;
  struct sexp *q;
  struct sexp *g;
  struct sexp *y;
  struct sexp *x;
  
  p = SEXP_GET(i);
  
  if (!(p && sexp_check_type(p, "p", NULL)))
    return NULL;

  SEXP_NEXT(i); q = SEXP_GET(i);
  
  if (!(q && sexp_check_type(q, "q", NULL)))
    return NULL;

  SEXP_NEXT(i); g = SEXP_GET(i);
  
  if (!(g && sexp_check_type(g, "g", NULL)))
    return NULL;

  SEXP_NEXT(i); y = SEXP_GET(i);
  
  if (!(y && sexp_check_type(y, "y", NULL)))
    return NULL;

  SEXP_NEXT(i); x = SEXP_GET(i);
  
  if (!(x && sexp_check_type(x, "x", NULL)))
    return NULL;

  SEXP_NEXT(i);
  if (SEXP_GET(i))
    return NULL;

  return sexp_l(2, sexp_z("public-key"),
		sexp_l(5, sexp_z("dsa"), p, q, g, y, -1), -1);
}

/* CLASS:
   (class
     (name write_key)
     (super sexp_handler)
     (vars
       (status . "int *")
       (public_file . "char *")
       (private_file . "char *")))
*/

static int do_write_key(struct sexp_handler *h, struct sexp *private)
{
  CAST(write_key, closure, h);
  struct sexp_iterator *i;
  struct sexp *public;
  struct sexp *e;
  int public_fd;
  int private_fd;
  
  if (!sexp_check_type(private, "private-key", &i))
    {
      werror("lsh_writekey: Not a private key.");
      return LSH_FAIL | LSH_DIE;
    }

  e = SEXP_GET(i);
  if (! (e && sexp_check_type(e, "dsa", &i)))
    {
      werror("lsh_writekey: Unknown key type (only dsa is supported)\n");
      return LSH_FAIL | LSH_DIE;
    }

  public = dsa_private2public(i);
  if (!public)
    {
      werror("lsh_writekey: Invalid dsa key\n");
      return LSH_FAIL | LSH_DIE;
    }
  
  if ((public_fd = open(closure->public_file,
			O_CREAT | O_EXCL | O_WRONLY, 0644)) < 0)
    {
      werror("lsh_writekey: Failed to open %z (errno = %i): %z\n",
	     closure->public_file, errno, strerror(errno));
      return LSH_FAIL | LSH_DIE;
    }

  if ((private_fd = open(closure->private_file,
			 O_CREAT | O_EXCL | O_WRONLY, 0600)) < 0)
    {
      werror("lsh_writekey: Failed to open %z (errno = %i): %z\n",
	     closure->private_file, errno, strerror(errno));
      return LSH_FAIL | LSH_DIE;
    }

  if (LSH_FAILUREP(A_WRITE(make_blocking_write(public_fd, 0),
			   sexp_format(public, SEXP_TRANSPORT, 0))))
    {
      werror("lsh_writekey: Writing to %z failed (errno = %i): %z\n",
	     closure->public_file, errno, strerror(errno));
      return LSH_FAIL | LSH_DIE;
    }
  
  if (LSH_FAILUREP(A_WRITE(make_blocking_write(private_fd, 0),
			   sexp_format(private, SEXP_CANONICAL, 0))))
    {
      werror("lsh_writekey: Writing to %z failed (errno = %i): %z\n",
	     closure->private_file, errno, strerror(errno));
      return LSH_FAIL | LSH_DIE;
    }

  *closure->status = EXIT_SUCCESS;
  return LSH_OK | LSH_DIE;
}

#define BLOCK_SIZE 2000

static void usage(void)
{
  werror("Usage: lsh_writekey [filename]\n");
}

int main(int argc UNUSED, char **argv UNUSED)
{
  NEW(io_backend, backend);
  NEW(write_key, handler);

  int status = 1;
  char *public;
  char *private;
  
  switch (argc)
    {
    case 1:
      {
	char *home = getenv("HOME");
	char *buf;
	
	if (!home)
	  {
	    werror("lsh_keygen: $HOME not set.\n");
	    return 1;
	  }
	buf = alloca(strlen(home) + 20);
	sprintf(buf, "%s/.lsh", home);
	if (mkdir(buf, 0755) < 0)
	  {
	    if (errno != EEXIST)
	      {
		werror("lsh_writekey: Creating directory %z failed "
		       "(errno = %i): %z\n", buf, errno, strerror(errno));
		return EXIT_FAILURE;
	      }
	  }
	else
	  werror("lsh_writekey: Created directory %z\n", buf);
	
	sprintf(buf, "%s/.lsh/identity", home);
	private = buf;
	
	break;
      }
    case 2:
      if (argv[1][0] != '-')
	{
	  private = argv[1];
	  break;
	}
      /* Fall through */
    default:
      usage();
      return EXIT_FAILURE;
    }

  public = alloca(strlen(private) + 5);
  sprintf(public, "%s.pub", private);
  
  init_backend(backend);

  handler->super.handler = do_write_key;
  handler->status = &status;
  handler->public_file = public;
  handler->private_file = private;
  
  io_read(backend, STDIN_FILENO,
	  make_read_sexp(&handler->super, BLOCK_SIZE, SEXP_TRANSPORT, 0),
	  NULL);

  io_run(backend);

  return status;
}
