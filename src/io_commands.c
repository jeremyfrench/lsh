/* io_commands.c
 *
 */

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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <errno.h>

/* For STDIN_FILENO */
#include <unistd.h>

#include "io_commands.h"

#include "command.h"
#include "lsh_string.h"
#include "werror.h"
#include "xalloc.h"

#include "io_commands.c.x"

/* (listen_tcp_command address callback)

   Returns a resource. The callback gets a listen-value as argument.
*/

/* GABA:
   (class
     (name io_port)
     (super resource)
     (vars
       (fd . int)
       (callback object command)))
*/

static void
kill_io_port(struct resource *s)
{
  CAST(io_port, self, s);
  if (self->super.alive)
    {
      self->super.alive = 0;
      io_close_fd(self->fd);
      self->fd = -1;
    }
};

static struct io_port *
make_io_port(int fd, struct command *callback)
{
  NEW(io_port, self);
  init_resource(&self->super, kill_io_port);

  io_register_fd(fd, "listen port");

  self->fd = fd;
  self->callback = callback;

  return self;
}

static void *
oop_io_port_accept(oop_source *source UNUSED,
		   int fd, oop_event event, void *state)
{
  CAST(io_port, self, (struct lsh_object *) state);

#if WITH_IPV6
  struct sockaddr_storage peer;
#else
  struct sockaddr_in peer;
#endif

  socklen_t peer_length = sizeof(peer);
  int s;
  
  assert(event == OOP_READ);
  assert(self->fd == fd);

  s = accept(self->fd, (struct sockaddr *) &peer, &peer_length);
  if (s < 0)
    {
      werror("accept failed, fd = %i: %e\n", self->fd, errno);
    }
  else
    COMMAND_CALL(self->callback,
		 make_listen_value(s, sockaddr2info(peer_length,
						    (struct sockaddr *)&peer)),
		 &discard_continuation, &ignore_exception_handler);

  return OOP_CONTINUE;  
}

/* (listen_tcp callback port) */
DEFINE_COMMAND2(listen_tcp_command)
     (struct lsh_object *a1,
      struct lsh_object *a2,
      struct command_continuation *c,
      struct exception_handler *e)
{
  CAST_SUBTYPE(command, callback, a1);
  CAST(address_info, a, a2);
  struct sockaddr *addr;
  socklen_t addr_length;
  struct io_port *port;
  int yes = 1;
  int fd;

  addr = io_make_sockaddr(&addr_length, lsh_get_cstring(a->ip), a->port);
  if (!addr)
    {
      EXCEPTION_RAISE(e, make_exception(EXC_RESOLVE, 0, "invalid address"));
      return;
    }

  fd = socket(addr->sa_family, SOCK_STREAM, 0);

  if (fd < 0)
    {
      EXCEPTION_RAISE(e, make_exception(EXC_IO_ERROR, errno, "socket failed"));
      lsh_space_free(addr);
      return;
    }

  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char*)&yes, sizeof(yes)) < 0)
    werror("setsockopt failed: %e\n", errno);

  if (bind(fd, addr, addr_length) < 0)
    {
      EXCEPTION_RAISE(e, make_exception(EXC_IO_ERROR, errno, "bind failed"));
      lsh_space_free(addr);
      close(fd);
      return;
    }

  lsh_space_free(addr);

  if (listen(fd, 256) < 0)
    {
      EXCEPTION_RAISE(e, make_exception(EXC_IO_ERROR, errno, "listen failed"));
      close(fd);
      return;
    }    

  port = make_io_port(fd, callback);
  global_oop_source->on_fd(global_oop_source, fd, OOP_READ,
			   oop_io_port_accept, port);

  COMMAND_RETURN(c, port);
}


#if 0
#if WITH_TCPWRAPPERS
#include <tcpd.h> 

/* This seems to be necessary on some systems */
#include <syslog.h>

int allow_severity = LOG_INFO;
int deny_severity = LOG_INFO;

#endif /* WITH_TCPWRAPPERS */

/* Takes a listen_value as argument, logs the peer address, and
 * returns the fd object. */

DEFINE_COMMAND(io_log_peer_command)
     (struct command *s UNUSED,
      struct lsh_object *a,
      struct command_continuation *c,
      struct exception_handler *e UNUSED)
{
  CAST(listen_value, lv, a);

  verbose("Accepting connection from %S, port %i\n",
	  lv->peer->ip, lv->peer->port);

  COMMAND_RETURN(c, lv);
}






/* ;;GABA:
   (class
     (name tcp_wrapper)
     (super command)
     (vars
       (name string)
       (msg string)))
*/


/* TCP wrapper function, replaces io_log_peer if used */

static void
do_tcp_wrapper(struct command *s UNUSED,
	       struct lsh_object *a,
	       struct command_continuation *c,
	       struct exception_handler *e UNUSED)
{
  CAST(listen_value, lv, a);

#if WITH_TCPWRAPPERS  

  CAST(tcp_wrapper, self, s);

  struct request_info res;

  request_init(&res,
	       RQ_DAEMON, lsh_get_cstring(self->name), /* Service name */
	       RQ_FILE, lv->fd->fd,   /* connection fd */
	       0);                /* No more arguments */
  
  fromhost(&res); /* Lookup information before */
  
  if (!hosts_access(&res)) /* Connection OK? */
    { 
      /* FIXME: Should we say anything to the other side? */

      verbose("Denying access for %z@%z (%z)\n",
	      eval_user(&res),
	      eval_hostname(res.client),
	      eval_hostaddr(res.client)
	      );


      
      io_write(lv->fd, 1024, NULL);
      A_WRITE(&lv->fd->write_buffer->super, 
	      lsh_string_dup(self->msg));

      close_fd_nicely(lv->fd);

      return;
    }

#endif /* WITH_TCPWRAPPERS */
  
  verbose("Accepting connection from %S, port %i\n",
	  lv->peer->ip, lv->peer->port);
  
  COMMAND_RETURN(c, lv);
}



struct command *
make_tcp_wrapper(struct lsh_string *name, struct lsh_string *msg )
{
  NEW(tcp_wrapper, self);
  self->super.call = do_tcp_wrapper;
  self->name = name;
  self->msg = msg;

  return &self->super;
}

/* ***
 *
 * (lambda (backend connection port)
     (listen backend connection port
             (lambda (peer)
                (start-io peer (request-forwarded-tcpip connection peer)))))
 */
#endif
