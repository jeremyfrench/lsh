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

#include "client.h"

#include "channel_forward.h"
#include "format.h"
#include "ssh.h"
#include "werror.h"
#include "xalloc.h"

#include "client_x11.c.x"

#include <assert.h>
#include <string.h>

#include <unistd.h>
#include <fcntl.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>

/* First port number for X, according to RFC 1013 */
#define X11_BASE_PORT 6000

#define X11_WINDOW_SIZE 10000

#define X11_COOKIE_LENGTH 16

/* GABA:
   (class
     (name client_x11_auth_info)
     (vars
       ; Fake MIT-COOKIE-1
       (fake string)

       ; Real authentication info
       (name string)
       (auth string)))
*/

/* FIXME: Perhaps merge auth_info directly into this struct */
/* GABA:
   (class
     (name client_x11_display)
     (vars
       (address_length . socklen_t)
       (address space "struct sockaddr")

       ; Default screen
       (screen . UINT16)
       (auth_info object client_x11_auth_info)))
*/
     
/* GABA:
   (class
     (name channel_open_x11)
     (super channel_open)
     (vars
       (backend object io_backend)))
*/

/* GABA:
   (class
     (name client_x11_channel)
     (super channel_forward)
     (vars
       (auth_info object client_x11_auth_info)
       (state . int)
       (i . UINT32)
       (buffer string)))
*/

/* This function is responsible for checking the fake cookie, and
 * replacing it with the real one.
 *
 * It intercepts the first packet sent by the client, which has the
 * following format:
 *
 * Type                        Possible or typical values
 *
 * uint8_t  byte-order         'B' (big endian) or 'L' (little endian)
 * uint16_t major-version      Usually 11
 * uint16_t minor-version      Usually 5 or 6.
 * uint8_t  name_length        18
 * uint8_t [name_length] name  "MIT-MAGIC-COOKIE-1"
 * uint8_t  auth_length
 * uint8_t [auth_length] auth  Authentication data
 *
 * As the lengths are maximum 255 octets, the max length of the
 * setup packet is  517 bytes.
 */

/* FIXME: Observed data:
 *
 *  $10 = {0x42, 0x0, 0x0, 0xb, 0x0, 0x0, 0x0, 0x12, 0x0, 0x10, 0x0, 0xa4, 0x4d, 
 *  0x49, 0x54, 0x2d, 0x4d, 0x41, 0x47, 0x49, 0x43, 0x2d, 0x43, 0x4f, 0x4f, 
 *  0x4b, 0x49, 0x45, 0x2d, 0x31, 0xff, 0xf7, 0x8b, 0x1e, 0x2c, 0xa0, 0x98, 
 *  0x11, 0x27, 0x82, 0xa9, 0x0, 0x2d, 0xc4, 0x68, 0x7f, 0x66, 0x2b}
 *
 * I.e. no minor version, and name length at index 7.
 */

#define MIT_COOKIE_NAME "MIT-MAGIC-COOKIE-1"
#define MIT_COOKIE_NAME_LENGTH 18
#define MIT_COOKIE_LENGTH 16

#define X11_SETUP_MAX_LENGTH 517

enum { CLIENT_X11_START,
       CLIENT_X11_GOT_NAME_LENGTH,
       CLIENT_X11_GOT_AUTH_LENGTH,
       CLIENT_X11_OK,
       CLIENT_X11_DENIED
};

static void
do_client_channel_x11_receive(struct ssh_channel *s,
                              int type, struct lsh_string *data)
{
  CAST(client_x11_channel, self, s);

  switch (type)
    {
    case CHANNEL_DATA:
      {
        /* Copy data to buffer */
        UINT32 left = self->buffer->length - self->i;

	/* The small initial window size should ensure that we don't get
	 * more data. */
	assert(data->length <= left);

        memcpy(self->buffer->data + self->i, data->data,
               data->length);
        self->i += data->length;
	lsh_string_free(data);
	
        switch (self->state)
          {
          case CLIENT_X11_START:
            /* We need byte-order, major, minor and name_length,
             * which is 6 octets */
               
            if (self->i < 6)
              break;

            /* Fall through */
            self->state = CLIENT_X11_GOT_NAME_LENGTH;
            
          case CLIENT_X11_GOT_NAME_LENGTH:
            /* We want the above data, the name, and the auth_length */
	    /* FIXME: Is 7U needed? */
            if (self->i < (7U + self->buffer->data[5]))
              break;

            /* Fall through */
            self->state = CLIENT_X11_GOT_AUTH_LENGTH;

          case CLIENT_X11_GOT_AUTH_LENGTH:
            {
              UINT32 name_length = self->buffer->data[5];
              UINT32 auth_length = self->buffer->data[6 + name_length];
              UINT32 length = 7 + name_length + auth_length;
              
              /* We also want the auth data */
              if (self->i < length)
                break;

	      verbose("Received cookie: `%ps':`%xs'\n",
		      name_length, self->buffer->data + 6,
		      auth_length, self->buffer->data + 7 + name_length);
	      
              /* Ok, now we have the connection setup message. Check if it's ok. */
              if ( (name_length == MIT_COOKIE_NAME_LENGTH)
                   && !memcpy(self->buffer->data + 6, MIT_COOKIE_NAME, MIT_COOKIE_NAME_LENGTH)
                   && lsh_string_eq_l(self->auth_info->fake,
                                      auth_length,
                                      self->buffer->data + 7 + name_length))
                {
                  struct lsh_string *msg;
                  
                  /* Cookies match! */
                  verbose("client_x11: Allowing X11 connection; cookies match.\n");

                  /* Construct the real setup message. */
                  msg = ssh_format("%ls%c%ls%c%ls%ls",
                                   5, self->buffer->data,
                                   self->auth_info->name->length,
                                   self->auth_info->name->length,
                                   self->auth_info->name->data,
                                   self->auth_info->auth->length,
                                   self->auth_info->auth->length,
                                   self->auth_info->auth->data,
                                   self->i - length,
                                   self->buffer + self->i);

		  lsh_string_free(self->buffer);
		  self->buffer = NULL;

		  /* Bump window size */
		  channel_start_receive(&self->super.super, X11_WINDOW_SIZE - msg->length);

		  /* Send real x11 connection setup message. */
		  A_WRITE(&self->super.socket->write_buffer->super, msg);

		  self->state = CLIENT_X11_OK;
                }
              else
                {
                  werror("client_x11: X11 connection denied; bad cookie.\n");
		  channel_close(&self->super.super);
		  self->state = CLIENT_X11_DENIED;
		}
	      break;
	    }
	  case CLIENT_X11_OK:
	    A_WRITE(&self->super.socket->write_buffer->super, data);
	    break;
	  case CLIENT_X11_DENIED:
	    /* Any data on the channel should be stopped before we get
	     * here; the CHANNEL_SENT_CLOSE should be set. */
	    fatal("Internal error!\n");
	  }
	break;
      }
    case CHANNEL_STDERR_DATA:
      werror("Ignoring unexpected stderr data.\n");
      lsh_string_free(data);
      break;
    default:
      fatal("Internal error. do_client_channel_x11_receive");
    }
}

static struct client_x11_channel *
make_client_x11_channel(struct lsh_fd *fd,
			struct client_x11_auth_info *auth_info)
{
  NEW(client_x11_channel, self);

  /* Use a limited window size for the setup */
  init_channel_forward(&self->super, fd, X11_SETUP_MAX_LENGTH);
  self->auth_info = auth_info;
  self->state = 0;
  self->buffer = lsh_string_alloc(X11_SETUP_MAX_LENGTH);

  return self;
}

/* GABA:
   (class
     (name channel_open_x11_continuation)
     (super command_continuation)
     (vars
       (auth_info object client_x11_auth_info)
       (up object command_continuation)))
*/

static void
do_channel_open_x11_continuation(struct command_continuation *s,
				 struct lsh_object *a)
{
  CAST(channel_open_x11_continuation, self, s);
  CAST(lsh_fd, fd, a);
  
  struct client_x11_channel *channel = make_client_x11_channel(fd, self->auth_info);
  channel_forward_start_io(&channel->super);
  channel->super.super.receive = do_client_channel_x11_receive;

  COMMAND_RETURN(self->up, channel);
}
				     
static struct command_continuation *
make_channel_open_x11_continuation(struct client_x11_auth_info *auth_info,
				   struct command_continuation *up)
{
  NEW(channel_open_x11_continuation, self);
  self->super.c = do_channel_open_x11_continuation;
  self->auth_info = auth_info;
  self->up = up;

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
      struct client_x11_display *display = connection->table->x11_display;
      
      verbose("x11 connection attempt, originator: %s:%i\n",
	      originator_length, originator, originator_port);

      
      if (display)
	{
	  struct lsh_fd *fd
	    = io_connect(self->backend,
			 display->address,
			 display->address_length,
			 make_channel_open_x11_continuation(display->auth_info,
							    c),
			 make_exc_x11_connect_handler(e, HANDLER_CONTEXT));

	  if (fd)
	    REMEMBER_RESOURCE(connection->resources, &fd->super);
	  else
	    EXCEPTION_RAISE(e, 
		      make_channel_open_exception(SSH_OPEN_CONNECT_FAILED,
						  STRERROR(errno)));
	  
 	  /* FIXME: To handle single-connection feature,
	   * remove the display here. */
	}
      else
	EXCEPTION_RAISE(e, make_channel_open_exception
			(SSH_OPEN_CONNECT_FAILED,
			 "No X11 forwarding has been requested."));
    }
  else
    {
      werror("do_channel_open_x11: Invalid message!\n");
      PROTOCOL_ERROR(connection->e, "Invalid CHANNEL_OPEN x11 message.");
    }
}

struct channel_open *
make_channel_open_x11(struct io_backend *backend)
{
  NEW(channel_open_x11, self);

  self->super.handler = do_channel_open_x11;
  self->backend = backend;

  return &self->super;
}


/* Format is host:display.screen, where display and screen are numbers */
static struct sockaddr *
parse_display(const char *display, socklen_t *sl, UINT16 *screen)
{
  struct lsh_string *host;
  unsigned display_num;
  
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
	return NULL;

      length = separator - display;
      host = ssh_format("%ls", length, display);
      
      display = separator + 1;
    }
  
  /* Get display number */
  {
    char *end;
    display_num = strtol(display, &end, 0);

    if (end == display)
      {
	lsh_string_free(host);
	return NULL;
      }
    if (!*end)
      /* Default screen number */
      *screen = 0;
    else if (*end != '.')
      {
	lsh_string_free(host);
	return NULL;
      }
    display = end + 1;
    *screen = strtol(display, &end, 0);

    if (*end)
      {
	lsh_string_free(host);
	return NULL;
      }
  }

  if (host)
    {
      /* NOTE: We don't support with IPv6 displays. I have no idea how
       * that would work with xauth. Actually, xauth ought to use DNS
       * names rather than IP addresses. */
      struct address_info *a = make_address_info(host, X11_BASE_PORT + display_num);
      struct sockaddr *sa;
      socklen_t length;
      const int prefs[] = { AF_INET, 0 };
      
      sa = address_info2sockaddr(&length, a, prefs, 1);

      KILL(a);

      if (!sa)
	return NULL;

      assert(sa->sa_family == AF_INET);
      *sl = sizeof(*sa);
      
      return sa;
    }
  else
    {
      /* Local transport */
      struct lsh_string *name = ssh_format("/tmp/.X11-unix/X%di", display_num);
      struct sockaddr_un *sa;

      verbose("Using local X11 transport `%pS'\n", name);
      
      *sl = offsetof(struct sockaddr_un, sun_path) + name->length;
      sa = lsh_space_alloc(*sl);
      sa->sun_family = AF_UNIX;
      memcpy(sa->sun_path, name->data, name->length);

      lsh_string_free(name);
      return (struct sockaddr *) sa;
    }
}


static struct client_x11_auth_info *
get_client_x11_auth_info(struct lsh_string *fake,
			 struct sockaddr *address)
{
  NEW(client_x11_auth_info, self);
  self->fake = fake;

  if
#if 0
    (!xauth_lookup(address, &self->name,
		    &self->auth))
#else
    (1)
#endif
    {
      /* Fallback: Don't use xauth, and hope that the X server uses
       * xhost to let us in anyway. */
      werror("Can't find any xauth information for X11 display.\n");

      self->name = ssh_format("");
      self->auth = ssh_format("");
    }
  return self;
}

struct client_x11_display *
make_client_x11_display(const char *display, struct lsh_string *fake)
{
  NEW(client_x11_display, self);
  
  self->address = parse_display(display, &self->address_length, &self->screen);

  if (!self->address)
    {
      werror("Can't parse X11 display: `%s'\n", display);
      lsh_string_free(fake);
      KILL(self);
      return NULL;
    }

  self->auth_info = get_client_x11_auth_info(fake, self->address);

  assert(self->auth_info);

  return self;
}

/* GABA:
   (class
     (name client_x11_display_resource)
     (super resource)
     (vars
       (connection object ssh_connection)
       (display object client_x11_display)))
*/

static void
do_kill_x11_display(struct resource *s)
{
  CAST(client_x11_display_resource, self, s);

  if (self->super.alive)
    {
      self->super.alive = 0;

      if (self->connection->table->x11_display == self->display)
	self->connection->table->x11_display = NULL;
      else
	werror("do_kill_x11_display: Display has been replaced.\n");
    }
}

static struct resource *
make_client_x11_display_resource(struct ssh_connection *connection,
				 struct client_x11_display *display)
{
  NEW(client_x11_display_resource, self);
  init_resource(&self->super, do_kill_x11_display);

  self->connection = connection;
  self->display = display;

  return &self->super;
}

/* GABA:
   (class
     (name request_x11_continuation)
     (super command_continuation)
     (vars
       (connection object ssh_connection)
       (display object client_x11_display)
       (up object command_continuation)))
*/

static void
do_request_x11_continuation(struct command_continuation *s,
			    struct lsh_object *a)
{
  CAST(request_x11_continuation, self, s);
  CAST_SUBTYPE(ssh_channel, channel, a);

  verbose("X11 request succeeded\n");

  if (self->connection->table->x11_display)
    werror("client_x11.c: Replacing old x11 forwarding.\n");

  self->connection->table->x11_display = self->display;

  REMEMBER_RESOURCE(channel->resources,
		    make_client_x11_display_resource(self->connection,
						     self->display));

  COMMAND_RETURN(self->up, a);
}

static struct command_continuation *
make_request_x11_continuation(struct ssh_connection *connection,
			      struct client_x11_display *display,
			      struct command_continuation *up)
{
  NEW(request_x11_continuation, self);
  self->super.c = do_request_x11_continuation;

  self->connection = connection;
  self->display = display;
  self->up = up;

  return &self->super;
}

/* GABA:
   (class
     (name request_x11_forward_command)
     (super channel_request_command)
     (vars
       (connection object ssh_connection)
       (display object client_x11_display)))
*/

static struct lsh_string *
do_format_request_x11_forward(struct channel_request_command *s,
			      struct ssh_channel *channel,
			      struct command_continuation **c)
{
  CAST(request_x11_forward_command, self, s);

  verbose("Requesting X11 forwarding.\n");
  
  *c = make_request_x11_continuation(channel->connection,
				     self->display, *c);

  /* NOTE: The cookie is hex encoded, appearantly so that it can be
   * passed directly to the xauth command line. That's really ugly,
   * but it's how the other ssh implementations do it. */
  
  return format_channel_request(ATOM_X11_REQ, channel, 1, "%c%s%xS%i",
				0, /* Single connection not supported */
				MIT_COOKIE_NAME_LENGTH, MIT_COOKIE_NAME,
				self->display->auth_info->fake,
				self->display->screen);
}

/* Consumes fake */
struct command *
make_forward_x11(const char *display_string,
		 struct randomness *random)
{
  struct lsh_string *fake = lsh_string_alloc(X11_COOKIE_LENGTH);
  struct client_x11_display *display;

  RANDOM(random, fake->length, fake->data);

  verbose("X11 fake cookie: `%xS'\n", fake);
  
  /* This deallocates fake if it fails. */
  display = make_client_x11_display(display_string, fake);

  if (display)
    {
      NEW(request_x11_forward_command, self);
      self->super.super.call = do_channel_request_command;
      self->super.format_request = do_format_request_x11_forward;

      self->display = display;
      return &self->super.super;
    }
  else
    return NULL;
}
