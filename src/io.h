/* io.h
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

#ifndef LSH_IO_H_INCLUDED
#define LSH_IO_H_INCLUDED

#include <time.h>
#include <netdb.h>
#include <netinet/in.h>

#include "abstract_io.h"
#include "write_buffer.h"

struct io_fd
{
  struct lsh_object header;
  
  struct io_fd *next;
  int fd;

  int please_close;
  
  /* Reading */
  struct read_handler *handler;
  int on_hold; /* For flow control */

  /* Writing */
  struct write_buffer *buffer;
  struct callback *close_callback;
};

/* A closed function with a file descriptor as argument */

struct fd_callback
{
  struct lsh_object header;
  
  int (*f)(struct fd_callback **closure, int fd);
};

#define FD_CALLBACK(c, fd) ((c)->f(&(c), (fd)))

struct listen_fd
{
  struct lsh_object header;
  
  struct listen_fd *next;
  int fd;
  struct fd_callback *callback;
};

struct connect_fd
{
  struct lsh_object header;
  
  struct connect_fd *next;
  int fd;
  struct fd_callback *callback;

};
  
struct callout
{
  struct lsh_object header;
  
  struct callout *next;
  struct callback *callout;
  time_t when;
  /* callback */
};

struct io_backend
{
  struct lsh_object header;
  
  unsigned nio;
  struct io_fd *io;
  unsigned nlisten;
  struct listen_fd *listen;
  unsigned nconnect;
  struct connect_fd *connect;
  struct callout *callouts;
};

void io_run(struct io_backend *b);

int get_inaddr(struct sockaddr_in	* addr,
	       const char		* host,
	       const char		* service,
	       const char		* protocol);

void io_set_nonblocking(int fd);

struct connect_fd *io_connect(struct io_backend *b,
			      struct sockaddr_in *remote,
			      struct sockaddr_in *local,
			      struct fd_callback *f);

struct listen_fd *io_listen(struct io_backend *b,
			    struct sockaddr_in *local,
			    struct fd_callback *callback);


struct abstract_write *io_read_write(struct io_backend *b,
				     int fd,
				     struct read_handler *read_callback,
				     UINT32 block_size,
				     struct callback *close_callback);

#endif /* LSH_IO_H_INCLUDED */
