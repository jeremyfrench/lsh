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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02111-1301  USA
 */

#ifndef LSH_IO_H_INCLUDED
#define LSH_IO_H_INCLUDED

#include <time.h>
#include <netdb.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <oop.h>

#include "queue.h"
#include "resource.h"

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


/* FIXME: Get rid of this class. Used by escape_callback (client.h),
   reaper_callback, transport_timeout, and a few others, and for
   io_callout. For the latter, add a method to the lsh_callout class
   with the corresponding action. */
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

/* Used for listening and connecting to local sockets.
 * Both strings have to be NUL-terminated. */

/* GABA:
   (class
     (name local_info)
     (vars
       (directory const string)
       (name const string)))
*/

struct local_info *
make_local_info(const struct lsh_string *directory,
		const struct lsh_string *name);


void
io_init(void);

void
io_run(void);

struct resource *
io_signal_handler(int signum,
		  struct lsh_callback *action);

struct resource *
io_callout(struct lsh_callback *action, unsigned seconds);

unsigned
get_portno(const char *service, const char *protocol);

int
io_getaddrinfo(const struct address_info *addr,
	       int flags,
	       struct addrinfo **res);

struct address_info *
make_address_info(struct lsh_string *host, 
		  uint32_t port);

struct address_info *
sockaddr2info(size_t addr_len,
              const struct sockaddr *addr);

/* Returns an 1 on success, 0 on error (and then see errno) */
int
write_raw(int fd, uint32_t length, const uint8_t *data);

struct lsh_string *
io_read_file_raw(int fd, uint32_t guess);

int
io_readable_p(int fd);

void io_set_nonblocking(int fd);
void io_set_blocking(int fd);
void io_set_close_on_exec(int fd);


/* GABA:
   (class
     (name io_fd_resource)
     (super resource)
     (vars
       (fd . int)))
*/
   
/* GABA:
   (class
     (name io_connect_state)
     (super io_fd_resource)
     (vars
       (done method void "int fd")
       ; The argument is a socket failure value.
       (error method void "int err")))
*/

void
init_io_connect_state(struct io_connect_state *self,
		      void (*done)(struct io_connect_state *self, int fd),
		      void (*error)(struct io_connect_state *self, int err));

int
io_connect(struct io_connect_state *self,
	   socklen_t addr_length,
	   struct sockaddr *addr);


int
io_bind_sockaddr(struct sockaddr *addr, socklen_t addr_length);

/* GABA:
   (class
     (name io_listen_port)
     (super io_fd_resource)
     (vars
       (accept method void "int fd"
                            "socklen_t addr_len"
			    "const struct sockaddr *addr")))
*/

void
init_io_listen_port(struct io_listen_port *self,  int fd,
		    void (*accept)(struct io_listen_port *self,
				   int fd,
				   socklen_t addr_len,
				   const struct sockaddr *addr));
					
int
io_listen(struct io_listen_port *self);

int
io_bind_local(const struct local_info *info);

int
io_connect_local(const struct local_info *info);

int
lsh_make_pipe(int *fds);

struct lsh_string *
lsh_popen_read(const char *program, const char **argv, int in,
	       unsigned guess);

int
lsh_popen_write(const char *program, const char **argv, int out,
		uint32_t length, const uint8_t *data);

/* Temporarily changing the current directory. */

int
lsh_pushd_fd(int dir);

int
lsh_pushd(const char *directory,
	  int *fd,
	  int create, int secret);
void
lsh_popd(int old_cd, const char *directory);


/* FIXME: Is this needed anymore? */
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

#endif /* LSH_IO_H_INCLUDED */
