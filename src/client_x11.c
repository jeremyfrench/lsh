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

#include "channel.h"

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
       (name string)
       (auth string)))
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
     (name client_channel_x11)
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
  CAST(client_channel_x11, self, s);

  switch (type)
    {
    case CHANNEL_DATA:
      {
        /* Copy data to buffer */
        UINT32 left = self->buffer->size - self->i;
        UINT32 consumed = MIN(left, data->length);

        memcpy(self->buffer->data + self->i, data->data,
               consumed);
        self->i += consumed;

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
            if (self->i < (7 + self->buffer->data[5]))
              break;

            /* Fall through */
            self->state = CLIENT_X11_GOT_AUTH_LENGTH;

          case CLIENT_X11_GOT_AUTH_LENGTH:
            {
              UINT32 name_length = self->buffer->data[5];
              UINT32 auth_length = self->buffer->data[6 + name_length];
              UINT32 in_length = 7 + name_length + auth_length;
              
              /* We also want the auth data */
              if (self->i < in_length)
                break;

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
                  msg = ssh_format("%ls%c%ls%c%ls%ls%ls",
                                   5, self->buffer->data,
                                   self->auth_info->name->length,
                                   self->auth_info->name->length,
                                   self->auth_name->name->data,
                                   self->auth_info->auth->length,
                                   self->auth_info->auth->length,
                                   self->auth_info->auth->data,
                                   self->i - length,
                                   self->buffer + self->i,
                                   data->length - consumed,
                                   data->data + consumed);
                  
                  out_length = (7
                                + self->auth_info->name->length
                                + self->auth_info->auth->length);

                  if (out_length > in_length)
                    werror("client_x11: Replacing the fake cookie made\n"
                           "            the X11 setup packet larger.\n"
                           "            Flow control will be slightly broken.\n");
                  else if (out_length < in_length)
                    /* Compensate by saying that we consumed 

                }
              else
                {
                  warning("client_x11: X11 connection
      A_WRITE(&closure->socket->write_buffer->super, data);
      break;
    case CHANNEL_STDERR_DATA:
      werror("Ignoring unexpected stderr data.\n");
      lsh_string_free(data);
      break;
    default:
      fatal("Internal error. do_client_channel_x11_receive");
    }
}

struct client_x11_channel *
make_client_x11_channel(struct client_x11_auth_info *auth_info,
                        struct lsh_fd *fd,
                        UINT32 window)
{
  NEW(client_x11_channel, self);

  init_channel_forward(&self->super, fd, window);
  self->auth_info = auth_info;
  self->state = 0;
  self->buffer = lsh_string_alloc(X11_SETUP_MAX_LENGTH);
}

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
make_channel_open_x11(const char *display, struct lsh_string *fake)
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

struct command *
make_forward_x11(const char *display, struct lsh_string *fake)
{
  /* FIXME: Request X11 forwarding, and install a channel open-handler
     if that succeeds. */
  return NULL;
}
