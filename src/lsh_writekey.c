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
#include "io_commands.h"
#include "sexp_commands.h"
#include "spki.h"
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

static struct read_sexp_command read_sexp
= STATIC_READ_SEXP(SEXP_TRANSPORT, 0);

#define READ_SEXP (&read_sexp.super.super)

static struct sexp_print_command write_canonical
= STATIC_PRINT_SEXP(SEXP_CANONICAL);
#define CANONICAL (&write_canonical.super.super.super)

static struct sexp_print_command write_transport
= STATIC_PRINT_SEXP(SEXP_TRANSPORT);
#define TRANSPORT (&write_transport.super.super.super)

#include "lsh_writekey.c.x"

/* GABA:
   (expr
     (name make_writekey)
     (globals
       (open IO_WRITE_FILE)
       (stdin IO_READ_STDIN)
       (read READ_SEXP) )
     (params
       (private object io_write_file_info)
       (public object io_write_file_info))
     (expr
       (lambda (backend)
         (let ((key (read (stdin backend))))
           (prog1 (transport (open backend public)
	                     (signer2public (spki_parse_private_key key)))
	          ; FIXME: Add encryption here
	          (canonical (open backend private) key))))))
*/

static void
do_lsh_writekey_handler(struct exception_handler *s UNUSED,
			const struct exception *e)
{
  werror("lsh_writekey: %z\n", e->msg);

  /* FIXME: It would be better to set the exit_success variable. */
  exit(EXIT_FAILURE);
}

static struct exception_handler exc_handler =
STATIC_EXCEPTION_HANDLER(do_lsh_writekey_handler, NULL);


#define BLOCK_SIZE 2000

static void usage(void)
{
  werror("Usage: lsh_writekey [filename]\n");
}

int main(int argc UNUSED, char **argv UNUSED)
{
  NEW(io_backend, backend);

  /* int status = 1; */
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
	    return EXIT_FAILURE;
	  }
	buf = alloca(strlen(home) + 20);
	sprintf(buf, "%s/.lsh", home);
	if (mkdir(buf, 0755) < 0)
	  {
	    if (errno != EEXIST)
	      {
		werror("lsh_writekey: Creating directory %z failed "
		       "(errno = %i): %z\n", buf, errno, STRERROR(errno));
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

  {
    CAST_SUBTYPE
      (command, work,
       make_writekey(make_io_write_file_info(private,
					     O_CREAT | O_EXCL | O_WRONLY,
					     0600,
					     BLOCK_SIZE),
		     make_io_write_file_info(public,
					     O_CREAT | O_EXCL | O_WRONLY,
					     0644,
					     BLOCK_SIZE)));
    
    COMMAND_CALL(work, backend, &discard_continuation, &exc_handler);
  }
  io_run(backend);

  return EXIT_SUCCESS;
}
