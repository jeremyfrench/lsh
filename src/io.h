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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef LSH_IO_H_INCLUDED
#define LSH_IO_H_INCLUDED

#include "abstract_io.h"
#include "resource.h"
#include "write_buffer.h"

#include <time.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* Forward declarations */

struct lsh_fd;

#define GABA_DECLARE
#include "io.h.x"
#undef GABA_DECLARE


/* A closed function with a file descriptor as argument */
/* GABA:
   (class
     (name fd_callback)
     (vars
       (f indirect-method void "int fd")))
*/

#define FD_CALLBACK(c, fd) ((c)->f(&(c), (fd)))

/* Close callbacks are called with a reason as argument. */

/* End of file while reading.
 * Or when a closed write_buffer has been flushed successfully.
 * Or when poll() returns POLLHUP. */
/* FIXME: Should we use separate codes for these two events? */
#define CLOSE_EOF 1

/* EPIPE when writing */
#define CLOSE_BROKEN_PIPE 2

#define CLOSE_WRITE_FAILED 3

/* #define CLOSE_READ_FAILED 4 */

#define CLOSE_PROTOCOL_FAILURE 5

/* GABA:
   (class
     (name close_callback)
     (vars
       (f method void "int reason")))
*/

#define CLOSE_CALLBACK(c, r) ((c)->f((c), (r)))

/* The fd read callback is a closure, in order to support different
 * reading styles (buffered and consuming). */

/* GABA:
   (class
     (name io_read_callback)
     (vars
       (read method void "struct lsh_fd *fd")))
*/

#define IO_READ_CALLBACK(c, fd) ((c)->read((c), (fd)))

/* GABA:
   (class
     (name lsh_fd)
     (super resource)
     (vars
       (next object lsh_fd)
       (fd simple int)

       ; Used for raising i/o- and eof-exceptions.
       ; Also passed on to readers of the consuming type,
       ; which seems kind of bogus.
       (e object exception_handler)
       
       ;; FIXME: Can the close handlers be replaced by exceptions?
       ; User's close callback
       (close_reason simple int)
       (close_callback object close_callback)

       ; Called before poll
       (prepare method void)
       
       (want_read simple int)
       ; Called if poll indicates that data can be read. 
       ;;(read method void)
			    
       (read object io_read_callback)

       (want_write simple int)
       ; Called if poll indicates that data can be written.
       (write method void)

       ; FIXME: really_close is an improper name. It is used to
       ; mark the fd's write_buffer as closed.
       (really_close method void))) */

#define PREPARE_FD(fd) ((fd)->prepare((fd)))
#define READ_FD(fd) IO_READ_CALLBACK((fd)->read, (fd))
#define WRITE_FD(fd) ((fd)->write((fd)))
#define REALLY_CLOSE_FD(fd) ((fd)->really_close((fd)))

/* GABA:
   (class
     (name io_fd)
     (super lsh_fd)
     (vars
       ; Reading 
       ;;(read_buffer object read_buffer)
       ;; (handler object read_handler)
       ; Writing 
       (write_buffer object write_buffer)))
*/

/* Used for read handlers like read_line and read_packet that
 * processes a little data at a time, possibly replacing the handler
 * and leaving some data for the new one. */

/* GABA:
   (class
     (name io_buffered_read)
     (super io_read_callback)
     (vars
       (buffer_size . UINT32)
       (handler object read_handler)))
*/

struct io_read_callback *
make_buffered_read(UINT32 buffer_size,
		   struct read_handler *handler);

/* Used for read handlers like read_data, that know how much data they
 * can consume. */

/* GABA:
   (class
     (name io_consuming_read)
     (super io_read_callback)
     (vars
       (query method UINT32)
       ; Returns the maximum number of octets that
       ; can be consumed immediately.
       (consumer object abstract_write)))
*/

#define READ_QUERY(r) ((r)->query((r)))

void init_consuming_read(struct io_consuming_read *self,
			 struct abstract_write *consumer);

/* Passed to the listen callback, and to other functions and commands
 * dealing with addresses. */
/* GABA:
   (class
     (name address_info)
     (vars
       ; An ipnumber, in decimal dot notation, ipv6 format, or
       ; a dns name.
       (ip string)
       ; The port number here is always in host byte order
       (port . UINT32))) */

/* GABA:
   (class
     (name fd_listen_callback)
     (vars
       (f method void int "struct address_info *")))
*/
#define FD_LISTEN_CALLBACK(c, fd, a) ((c)->f((c), (fd), (a)))

/* FIXME: Get rid of this class, and store the user callback inside
 * the io_read_callback. */

/* GABA:
   (class
     (name listen_fd)
     (super lsh_fd)
     (vars
       (callback object fd_listen_callback)))
*/

/* GABA:
   (class
     (name connect_fd)
     (super lsh_fd)
     (vars
       (callback object fd_callback)))
*/

/* GABA:
   (class
     (name callback)
     (vars
       (f method void)))
*/

#define CALLBACK(c) ((c)->f(c))

/* GABA:
   (class
     (name callout)
     (vars
       (next object callout)
       (action object callback)
       (when . time_t)))
*/

#if 0
struct callout
{
  struct lsh_object header;
  
  struct callout *next;
  struct callback *callout;
  time_t when;
};
#endif

/* GABA:
   (class
     (name io_backend)
     (vars
       ; Linked list of fds. 
       (files object lsh_fd)
       ; Callouts
       ;; (callouts object callout)
       ))
*/

/* I/O exceptions */
/* GABA:
   (class
     (name io_exception)
     (super exception)
     (vars
       ;; NULL if no fd was involved
       (fd object lsh_fd)
       ;; errno code, or zero if not available
       (error . int))))
*/

/* If msg is NULL, it is derived from errno */
struct exception *
make_io_exception(UINT32 type, struct lsh_fd *fd, int error, const char *msg);

/* Used in cases where the fd and errno are not available */
#define STATIC_IO_EXCEPTION(type, name) \
{ { STATIC_HEADER, (type), (name) }, NULL, 0}

extern struct exception finish_read_exception;

void init_backend(struct io_backend *b);

int io_iter(struct io_backend *b);
void io_run(struct io_backend *b);

int blocking_read(int fd, struct read_handler *r);

int get_inaddr(struct sockaddr_in	* addr,
	       const char		* host,
	       const char		* service,
	       const char		* protocol);

int get_portno(const char *s, const char *protocol);

int tcp_addr(struct sockaddr_in *sin,
	     UINT32 length,
	     UINT8 *addr,
	     UINT32 port);

struct address_info *make_address_info_c(const char *host,
					 const char *port);

struct address_info *make_address_info(struct lsh_string *host, 
				       UINT32 port);

struct address_info *sockaddr2info(size_t addr_len UNUSED,
				   struct sockaddr *addr);

int address_info2sockaddr_in(struct sockaddr_in *sin,
			     struct address_info *a);

/* Returns an exception, if anything went wrong */
const struct exception *
write_raw(int fd, UINT32 length, const UINT8 *data);
const struct exception *
write_raw_with_poll(int fd, UINT32 length, const UINT8 *data);

void io_set_nonblocking(int fd);
void io_set_close_on_exec(int fd);
void io_init_fd(int fd);

struct io_fd *make_io_fd(struct io_backend *b,
			 int fd,
			 struct exception_handler *e);

struct exception_handler *
make_exc_finish_read_handler(struct lsh_fd *fd,
			     struct exception_handler *parent,
			     const char *context);

struct connect_fd *
io_connect(struct io_backend *b,
	   struct sockaddr_in *remote,
	   struct sockaddr_in *local,
	   struct fd_callback *f,
	   struct exception_handler *e);

struct listen_fd *
io_listen(struct io_backend *b,
	  struct sockaddr_in *local,
	  struct fd_listen_callback *callback,
	  struct exception_handler *e);

struct io_fd *io_read_write(struct io_fd *fd,
			    struct io_read_callback *read,
			    UINT32 block_size,
			    struct close_callback *close_callback);

struct io_fd *io_read(struct io_fd *fd,
		      struct io_read_callback *read,
		      struct close_callback *close_callback);

struct io_fd *io_write(struct io_fd *fd,
		       UINT32 block_size,
		       struct close_callback *close_callback);

/* Marks a file for close, without touching the close_reason field. */
void kill_fd(struct lsh_fd *fd);

void close_fd(struct lsh_fd *fd, int reason);

/* Stop reading from the fd, and close it as soon as the buffer
 * is completely written. */
void close_fd_nicely(struct lsh_fd *fd, int reason);

struct io_fd *io_write_file(struct io_backend *backend,
			    const char *fname, int flags,
			    int mode,
			    UINT32 block_size,
			    struct close_callback *c,
			    struct exception_handler *e);

#endif /* LSH_IO_H_INCLUDED */
