/* client_x11.c
 *
 * Client side of X11 forwaarding.
 *
 * $id:$ */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 2001 Niels Möller
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

#include "channel-h"

#include "client_x11.c.x"

#include <unistd.h>
#include <fcntl.h>

#define X11_WINDOW_SIZE 10000

/* GABA
   (class
     (name client_x11_auth_info)
     (vars
       ; Fake MIT-COOKIE-1
       (fake string)

       ; Real authentication info
       (auth_name string)
       (auth_data string)))
*/

/* GABA:
   (class
     (name channel_open_x11)
     (super channel_open)
     (vars
       (address_length . socklen_t)
       (address space "struct sockaddr")

       (authinfo object client_x11_auth_info)))
*/

/* GABA:
   (class
     (name client_x11_channel)
     (super channel_forward)
     (vars
       (authinfo object client_x11_auth_info)
       (state . unsigned)
       (buffer string)))
*/

/* Format is host:display.screen, where display and screen are numbers */
static struct sockaddr *
parse_display(const char *display, socklen_t *sl)
{
  struct lsh_string *host;
  unsigned display;
  
  /* Get host name */
  if (display[0] == ':')
    {
      /* Local transport */
      host = NULL;
      display++;
    }
  else
    {
      const char *separator = strchr(display, ':');
      size_t length;

      if (!separator)
	return 0;

      host = ssh_format("%ls", length, display);
      
      display = separator + 1;
    }
  
  /* Get display number */
  {
    char *end;
    display = strtol(display, &end, 0);

    if ( (end == display)
	 || ( (end[0] != '\0') && (end[0] != '.')) )
      {
	lsh_string_free(host);
	return 0;
      }
  }

  /* Ignore screen number */
  /* FIXME: We don't use the screen_number. It should be used for
   * DefaultRootWindow on the other side. */

  if (host)
    {
      /* NOTE: We don't support with IPv6 displays. I have no idea how
       * that would work with xauth. Actually, xauth ought to use DNS
       * names rather than IP addresses. */
      struct address_info *a = make_address_info(host, display);
      struct sockaddr *sa;
      socklen_t length;
      const int prefs[] = { AF_INET, 0 };
      
      sa = address_info2sockaddr(&length, a, prefs, 1);

      KILL(a);

      if (!sa)
	return NULL;

      assert(sa->sin_family == AF_INET);
      *sl = sizeof(*sa);
      
      return sa;
    }
  else
    {
      /* Local transport */
      struct lsh_string *name = ssh_format("/tmp/.X11-unix/X%di", display);
      struct sockaddr_un *sa;

      *sl = offsetof(struct sockaddr_un, sun_path) + name->length;
      sa = = lsh_space_alloc(*sl);
      sa->sun_family = AF_UNIX;
      memcpy(sa->sun_path, name->data, name->length);

      lsh_string_free(name);
      return sa;
    }
}

/* GABA:
   (class
     (name channel_open_x11_callback)
     (super io_callback)
     (vars
       (ctx object channel_open_x11)
       (c object command_continuation)))
*/

static void
do_channel_open_x11_callback(struct io_callback *s, struct lsh_fd *fd)
{
  CAST(channel_open_callback, self, s);

  struct channel_forward *channel = make_client_channel_x11(fd, X11_WINDOW_SIZE);
  channel_forward_start_io(channel_forward);
  channel->super.do_receive = do_channel_x11_receive
  COMMAND_RETURN(self->c, channel);
}
				     
struct io_callback *
make_channel_open_x11_callback(struct channel_open_x11 *ctx,
			       struct command_continuation *c)
{
  NEW(channel_open_x11_callback, self);
  self->super.f = do_channel_open_x11_callback;
  self->ctx = ctx;
  self->c = c;

  return &self->super;
}

/* Exception handler that promotes connect errors to CHANNEL_OPEN
 * exceptions */

static void
do_exc_x11_connect_handler(struct exception_handler *s,
			   const struct exception *e)
{
  switch(e->type)
    {
    case EXC_IO_CONNECT:
      EXCEPTION_RAISE(s->parent,
		      make_channel_open_exception(SSH_OPEN_CONNECT_FAILED,
						  e->msg));
      break;
    default:
      EXCEPTION_RAISE(s->parent, e);
    }
}

static struct exception_handler *
make_exc_x11_connect_handler(struct exception_handler *parent,
			     const char *context)
{
  return make_exception_handler(do_exc_x11_connect_handler, parent, context);
}

static void
do_channel_open_x11(struct channel_open *s,
		    struct ssh_connection *connection,
		    struct channel_open_info *info UNUSED,
		    struct simple_buffer *args,
		    struct command_continuation *c,
		    struct exception_handler *e)
{
  CAST(channel_open_x11, self, s);

  UINT32 originator_length;
  const UINT8 *originator;
  UINT32 originator_port;

  if (parse_string(args, &originator_length, &originator)
      && parse_uint32(args, &originator_port) 
      && parse_eod(args))
    {
      verbose("x11 connection attempt, originator: %s:%d\n",
	      originator_length, originator, originator_port);

      werror("WARNING: X11 cookie check not yet implemented.\n");

      io_connect(self->backend, self->address, self->address_length,
		 make_channel_open_x11_callback(self),
		 make_exc_x11_connect_handler(e, HANDLER_CONTEXT));
    }
  else
    {
      werror("do_channel_open_x11: Invalid message!\n");
      PROTOCOL_ERROR(connection->e, "Invalid CHANNEL_OPEN x11 message.");
    }
}


struct channel_open *
make_forward_x11(const char *display, struct lsh_string *fake)
{
  NEW(channel_open_x11, self);

  self->super.handler = do_forward_x11;
  self->fake = fake;
  
  self->address = parse_display(display, &self->address_length);

  if (!self->address)
    {
      KILL(self);
      return NULL;
    }
  
  if (!xauth_lookup(self->address, &self->auth_name,
		   &self->auth_data))
    werror("Couldn't lookup X authority information.\n");
}
