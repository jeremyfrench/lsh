/* lshd.c
 *
 * main server program.
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

#include <errno.h>
#include <locale.h>
#include <stdio.h>
#include <string.h>

#include "getopt.h"

#include "io.h"
#include "werror.h"
#include "server.h"

#define BLOCK_SIZE 32768

/* Global variable */
struct io_backend backend;

void usage() NORETURN;

void usage()
{
  exit(1);
}

int main(int argc, char **argv)
{
  char *host = NULL;  /* Interface to bind */
  char *port = "ssh";
  int option;

  struct sockaddr_in local;
    
  /* For filtering messages. Could perhaps also be used when converting
   * strings to and from UTF8. */
  setlocale(LC_CTYPE, "");
  
  while((option = getopt(argc, argv, "dp:qi:v")) != -1)
    switch(option)
      {
      case 'p':
	port = optarg;
	break;
      case 'q':
	quiet_flag = 1;
	break;
      case 'd':
	debug_flag = 1;
	break;
      case 'i':
	host = optarg;
	break;
      case 'v':
	verbose_flag = 1;
	break;
      default:
	usage();
      }

  if ( (argc - optind) != 0)
    usage();

  if (!get_inaddr(&local, host, port, "tcp"))
    {
      fprintf(stderr, "No such host or service");
      exit(1);
    }

  if (!io_listen(&backend, &local, 
	    make_server_callback(&backend,
				 "lsh - a free ssh",
				 BLOCK_SIZE)))
    {
      werror("lsh: Connection failed: %s\n", strerror(errno));
      return 1;
    }
  
  io_run(&backend);

  return 0;
}
