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

#include "abstract_io.h"
#include "resource.h"
#include "write_buffer.h"

#include <time.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>

#define CLASS_DECLARE
#include "io.h.x"
#undef CLASS_DECLARE

/* A closed function with a file descriptor as argument */
/* CLASS:
   (class
     (name fd_callback)
     (vars
       (f indirect-method int "int fd")))
*/

#define FD_CALLBACK(c, fd) ((c)->f(&(c), (fd)))

/* Close callbacks are called with a reason as argument. */

/* End of file while reading.
 * Or when a closed write_buffer has been flushed successfully. */
/* FIXME: Should we use separate codes for these two events? */
#define CLOSE_EOF 1

/* EPIPE when writing */
#define CLOSE_BROKEN_PIPE 2

#define CLOSE_WRITE_FAILED 3

/* #define CLOSE_READ_FAILED 4 */

#define CLOSE_PROTOCOL_FAILURE 5

/* CLASS:
   (class
     (name close_callback)
     (vars
       (f method int "int reason")))
*/

#define CLOSE_CALLBACK(c, r) ((c)->f((c), (r)))

/* CLASS:
   (class
     (name lsh_fd)
     (super resource)
     (vars
       (next object lsh_fd)
       (fd simple int)

       ; User's close callback
       (close_reason simple int)
       (close_callback object close_callback)

       ; Called before poll
       (prepare method void)

       (want_read simple int)
       ; Called if poll indicates that data can be read. 
       (read method void)

       (want_write simple int)
       ; Called if poll indicates that data can be written.
       (write method void)

       ; (close_now simple int)
       (really_close method void)))
*/

#define PREPARE_FD(fd) ((fd)->prepare((fd)))
#define READ_FD(fd) ((fd)->read((fd)))
#define WRITE_FD(fd) ((fd)->write((fd)))
#define REALLY_CLOSE_FD(fd) ((fd)->really_close((fd)))

/* CLASS:
   (class
     (name io_fd)
     (super lsh_fd)
     (vars
       ; Reading 
       (handler object read_handler)
       ; Writing 
       (buffer object write_buffer)))
*/

/* CLASS:
   (class
     (name listen_fd)
     (super lsh_fd)
     (vars
       (callback object fd_callback)))
*/

#define connect_fd listen_fd

#if 0
struct callout
{
  struct lsh_object header;
  
  struct callout *next;
  struct callback *callout;
  time_t when;
};
#endif

/* CLASS:
   (class
     (name io_backend)
     (vars
       ; Linked list of fds. 
       (files object lsh_fd)
       ; Callouts
       ;; (callouts object callout)
       ))
*/

void init_backend(struct io_backend *b);

int io_iter(struct io_backend *b);
void io_run(struct io_backend *b);

int get_inaddr(struct sockaddr_in	* addr,
	       const char		* host,
	       const char		* service,
	       const char		* protocol);

void io_set_nonblocking(int fd);
void io_set_close_on_exec(int fd);
void io_init_fd(int fd);

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
				     struct close_callback *close_callback);

struct io_fd *io_read(struct io_backend *b,
		      int fd,
		      struct read_handler *read_callback,
		      struct close_callback *close_callback);

struct io_fd *io_write(struct io_backend *b,
		       int fd,
		       UINT32 block_size,
		       struct close_callback *close_callback);

/* Marks a file for close, without touching the close_Reason field. */
void kill_fd(struct lsh_fd *fd);

void close_fd(struct lsh_fd *fd, int reason);


#endif /* LSH_IO_H_INCLUDED */
