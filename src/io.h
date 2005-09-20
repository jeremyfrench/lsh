/* io.h
 *
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998, 2001 Niels Möller
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

#include <time.h>
#include <netdb.h>
/* For sig_atomic_t */
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <oop.h>

#include "abstract_io.h"
#include "queue.h"
#include "resource.h"
#include "write_buffer.h"

extern oop_source *global_oop_source;

void
io_register_fd(int fd, const char *label);

void
io_close_fd(int fd);

/* Max number of simultaneous connection attempts */
#define CONNECT_ATTEMPTS_LIMIT 3

#define GABA_DECLARE
#include "io.h.x"
#undef GABA_DECLARE


/* GABA:
   (class
     (name lsh_callback)
     (vars
       (f method void)))
*/

#define LSH_CALLBACK(c) ((c)->f((c)))

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
       (port . uint32_t)))
*/

#if 0
/* Used for listening and connecting to local sockets.
 * Both strings have to be NUL-terminated. */

/* ;; GABA:
   (class
     (name local_info)
     (vars
       (directory string)
       (name string)))
*/

struct local_info *
make_local_info(struct lsh_string *directory,
		struct lsh_string *name);
#endif

/* Passed to the listen callback. Note that the fd here isn't
   registered anywhere, so it must be taken care of immedietely, or
   risk being leaked. */
/* GABA:
   (class
     (name listen_value)
     (vars
       (fd . int)
       (peer object address_info)))
*/

struct listen_value *
make_listen_value(int fd,
		  struct address_info *peer);


void
io_init(void);

void
io_run(void);

struct resource *
io_signal_handler(int signum,
		  struct lsh_callback *action);

struct resource *
io_callout(struct lsh_callback *action, unsigned seconds);

int blocking_read(int fd, struct read_handler *r);

int get_portno(const char *service, const char *protocol);

struct address_info *
make_address_info(struct lsh_string *host, 
		  uint32_t port);

struct address_info *
fd2info(struct lsh_fd *fd, int side);

struct address_info *
sockaddr2info(size_t addr_len,
	      struct sockaddr *addr);

struct sockaddr *
address_info2sockaddr(socklen_t *length,
		      struct address_info *a,
		      const int *preference,
		      int lookup);

unsigned
io_resolv_address(const char *host, const char *service,
		  unsigned default_port,
		  struct addr_queue *q);

/* Returns an 1 on success, 0 on error (and then see errno) */
int
write_raw(int fd, uint32_t length, const uint8_t *data);

const struct exception *
read_raw(int fd, uint32_t length, uint8_t *data);

struct lsh_string *
io_read_file_raw(int fd, uint32_t guess);

void io_set_nonblocking(int fd);
void io_set_blocking(int fd);
void io_set_close_on_exec(int fd);

#if 0
/* ;; GABA:
   (class
     (name connect_list_state)
     (super resource)
     (vars
       (q struct addr_queue)
       ;; Number of currently active fd:s
       (nfds . unsigned)
       (fds array (object lsh_fd) CONNECT_ATTEMPTS_LIMIT)))
*/

struct connect_list_state *
make_connect_list_state(void);

struct resource *
io_connect_list(struct connect_list_state *remote,
		struct command_continuation *c,
		struct exception_handler *e);

/* FIXME: Reorder arguments to put length first, for consistency? */
struct lsh_fd *
io_connect(struct sockaddr *remote,
	   socklen_t remote_length,
	   struct io_callback *c,
	   struct exception_handler *e);

struct io_callback *
make_connect_callback(struct command_continuation *c);

struct lsh_fd *
io_bind_sockaddr(struct sockaddr *local,
		 socklen_t length,
		 struct exception_handler *e);

struct lsh_fd *
io_listen(struct lsh_fd *fd,
	  struct io_callback *callback);

struct resource *
io_listen_list(struct addr_queue *addresses,
	       struct io_callback *callback,
	       struct exception_handler *e);

struct lsh_fd *
io_bind_local(struct local_info *info,
	      struct exception_handler *e);

struct lsh_fd *
io_connect_local(struct local_info *info,
		 struct command_continuation *c,
		 struct exception_handler *e);

struct io_callback *
make_listen_callback(struct command *c,
		     struct exception_handler *e);

#endif

int
lsh_make_pipe(int *fds);

int
lsh_popen(const char *program, const char **argv, int in,
	  pid_t *child);

struct lsh_string *
lsh_popen_read(const char *program, const char **argv, int in,
	       unsigned guess);


/* Temporarily changing the current directory. */

int
lsh_pushd_fd(int dir);

int
lsh_pushd(const char *directory,
	  int *fd,
	  int create, int secret);
void
lsh_popd(int old_cd, const char *directory);


/* Socket workaround */
#ifndef SHUTDOWN_WORKS_WITH_UNIX_SOCKETS

#define SHUTDOWN_UNIX(fd, how) 0

#endif /* !SHUTDOWN_WORKS_WITH_UNIX_SOCKETS */

#ifndef SHUTDOWN_UNIX
#define SHUTDOWN_UNIX(fd, how) (shutdown((fd), (how)))
#endif

#ifndef SHUT_RD
#define SHUT_RD 0
#endif

#ifndef SHUT_WR
#define SHUT_WR 1
#endif

#ifndef SHUT_RD_WR
#define SHUT_RD_WR 2
#endif

#ifndef SHUT_RD_UNIX
#define SHUT_RD_UNIX SHUT_RD
#endif

#ifndef SHUT_WR_UNIX
#define SHUT_WR_UNIX SHUT_WR
#endif

#ifndef SHUT_RD_WR_UNIX
#define SHUT_RD_WR_UNIX SHUT_RD_WR
#endif

#endif /* LSH_IO_H_INCLUDED */
