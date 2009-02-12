/* client_x11.c
 *
 * Client side of X11 forwaarding.
 *
 */

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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <string.h>

#include <fcntl.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/un.h>

#include <netinet/in.h>

#include <X11/X.h>
#if HAVE_X11_XAUTH_H
#include <X11/Xauth.h>
#endif

#include "nettle/macros.h"

#include "client.h"

#include "channel_forward.h"
#include "format.h"
#include "gateway.h"
#include "lsh_string.h"
#include "ssh.h"
#include "werror.h"
#include "xalloc.h"

#include "client_x11.c.x"

/* First port number for X, according to RFC 1013 */
#define X11_BASE_PORT 6000

#define X11_WINDOW_SIZE 10000

#define X11_COOKIE_LENGTH 16

/* GABA:
   (class
     (name client_x11_display)
     (super client_x11_handler)
     (vars
       (address_length . socklen_t)
       (address space "struct sockaddr")

       ; Default screen
       (screen . uint16_t)

       ; Fake MIT-COOKIE-1
       (fake string)

       ; Real authentication info
       (auth_name string)
       (auth_data string)))
*/

/* GABA:
   (class
     (name client_x11_channel)
     (super channel_forward)
     (vars
       (display object client_x11_display)
       (state . int)
       (little_endian . int)
       (name_length . unsigned)
       (auth_length . unsigned)
       (i . uint32_t)
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
 *                             According to Jean-Pierre, some servers
 *                             use 'b' and 'l' instead.
 * uint8_t  pad                0
 * uint16_t major-version      Usually 11
 * uint16_t minor-version      Usually 0.
 * uint16_t name_length        18
 * uint16_t auth_length        16
 * uint16_t pad                What's this?
 * uint8_t [name_length] name  "MIT-MAGIC-COOKIE-1"
 * uint8_t [auth_length] auth  Authentication data
 *
 * The last fields; name and auth, are padded to a multiple of four octets.
 *
 * The typical setup packet, with a 16-octet cookie, is 48 octets.
 */

/* Observed data:
 *
 *  $10 = {0x42, 0x0, 0x0, 0xb, 0x0, 0x0, 0x0, 0x12, 0x0, 0x10, 0x0, 0xa4, 0x4d, 
 *  0x49, 0x54, 0x2d, 0x4d, 0x41, 0x47, 0x49, 0x43, 0x2d, 0x43, 0x4f, 0x4f, 
 *  0x4b, 0x49, 0x45, 0x2d, 0x31, 0xff, 0xf7, 0x8b, 0x1e, 0x2c, 0xa0, 0x98, 
 *  0x11, 0x27, 0x82, 0xa9, 0x0, 0x2d, 0xc4, 0x68, 0x7f, 0x66, 0x2b}
 *
 */

/* From Pike's X.pmod:
 *
 *     // Always uses network byteorder (big endian) 
 *     string msg = sprintf("B\0%2c%2c%2c%2c\0\0%s%s",
 * 			    11, 0,
 * 			    strlen(auth_data->name), strlen(auth_data->data),
 * 			    ._Xlib.pad(auth_data->name), ._Xlib.pad(auth_data->data));
 */

#define MIT_COOKIE_NAME "MIT-MAGIC-COOKIE-1"
#define MIT_COOKIE_NAME_LENGTH 18
#define MIT_COOKIE_LENGTH 16

#define X11_SETUP_VERSION_LENGTH 6
#define X11_SETUP_HEADER_LENGTH 12

/* The size of a connection setup message with a 16 octet
 * MIT-MAGIC-COOKIE-1. Using such a low value leaks the information
 * that we expect a 16-octet cookie, but I don't think that's a real
 * problem. */
#define X11_SETUP_MAX_LENGTH 48

enum { CLIENT_X11_START,
       CLIENT_X11_GOT_LENGTHS,
       CLIENT_X11_CANT_HAPPEN,
};

/* And the other, little-endian, byteorder */
#define LE_READ_UINT16(p)			\
(  (((uint32_t) (p)[1]) << 8)			\
 |  ((uint32_t) (p)[0]))

#define LE_WRITE_UINT16(p, i)			\
do {						\
  (p)[1] = ((i) >> 8) & 0xff;			\
  (p)[0] = (i) & 0xff;				\
} while(0)

static void
do_client_channel_x11_receive(struct ssh_channel *s,
                              int type,
			      uint32_t length, const uint8_t *data)
{
  CAST(client_x11_channel, self, s);

  if (type != CHANNEL_DATA)
    werror("Ignoring unexpected stderr data on X11 channel.\n");

  else
    {
      /* Copy data to buffer */
      const uint8_t *buffer;
	
      /* The small initial window size should ensure that all the
	 data fits. */
      lsh_string_write(self->buffer, self->i, length, data);
      self->i += length;

      buffer = lsh_string_data(self->buffer);
	
      switch (self->state)
	{
	default:
	  fatal("Internal error. do_client_channel_x11_receive");
	  break;
	case CLIENT_X11_START:
	  /* We need byte-order, major, minor and name_length,
	   * which is 6 octets */
               
	  if (self->i < X11_SETUP_HEADER_LENGTH)
	    break;

	  self->state = CLIENT_X11_GOT_LENGTHS;
	  switch (buffer[0])
	    {
	    case 'B': /* Big endian */
	    case 'b':
	      self->little_endian = 0;
	      self->name_length = READ_UINT16(buffer + 6);
	      self->auth_length = READ_UINT16(buffer + 8);
	      break;
	    case 'L': /* Little endian */
	    case 'l':
	      self->little_endian = 1;
	      self->name_length = LE_READ_UINT16(buffer + 6);
	      self->auth_length = LE_READ_UINT16(buffer + 8);
	      break;
	    default:
	      werror("client_x11.c: Bad endian indicator.\n");
	      goto fail;
	    }
	  if ( (self->name_length > 20)
	       || (self->auth_length > 16) )
	    {
	      werror("client_x11.c: Too long auth name or cookie\n");
	      goto fail;
	    }
            
	  /* Fall through */
            
	case CLIENT_X11_GOT_LENGTHS:
	  {
	    const unsigned pad_length[4] = { 0, 3, 2, 1 };

#define PAD(l) (pad_length[ (l) % 4])
              
	    uint32_t auth_offset = X11_SETUP_HEADER_LENGTH
	      + self->name_length + PAD(self->name_length);

	    uint32_t length = auth_offset
	      + self->auth_length + PAD(self->auth_length); 
                
	    if (self->i < length)
	      break;

	    debug("Received cookie of type `%ps': %xs\n",
		  self->name_length, buffer + X11_SETUP_HEADER_LENGTH,
		  self->auth_length, buffer + auth_offset);

	    /* Ok, now we have the connection setup message. Check if it's ok. */
	    if ( (self->name_length == MIT_COOKIE_NAME_LENGTH)
		 && !memcmp(buffer + X11_SETUP_HEADER_LENGTH,
			    MIT_COOKIE_NAME, MIT_COOKIE_NAME_LENGTH)
		 && lsh_string_eq_l(self->display->fake,
				    self->auth_length,
				    buffer + auth_offset))
	      {
		struct lsh_string *msg;
		uint8_t lengths[4];
		static const uint8_t pad[3] = { 0, 0, 0 };
		uint32_t nlength = lsh_string_length(self->display->auth_name);
		uint32_t alength = lsh_string_length(self->display->auth_data);
		  
		/* Cookies match! */
		verbose("client_x11: Allowing X11 connection; cookies match.\n");
                  
		if (self->little_endian)
		  {
		    LE_WRITE_UINT16(lengths, nlength);
		    LE_WRITE_UINT16(lengths + 2, alength);
		  }
		else
		  {
		    WRITE_UINT16(lengths, nlength);
		    WRITE_UINT16(lengths + 2, alength);
		  }

		/* Construct the real setup message. (Perhaps it would
		 * be easier to build the message by hand than using
		 * ssh_format?) */
		msg = ssh_format("%ls%ls%c%c%lS%ls%lS%ls",
				 X11_SETUP_VERSION_LENGTH, buffer,
				 4, lengths,
				 0, 0,
				 self->display->auth_name,
				 PAD(nlength), pad,
				 self->display->auth_data,
				 self->i - length,
				 buffer + self->i);

		lsh_string_free(self->buffer);
		self->buffer = NULL;

		/* Bump window size */
		channel_start_receive(&self->super.super,
				      X11_WINDOW_SIZE - lsh_string_length(msg));

		/* Replaces receive method, so that we are not called again. */
		channel_forward_start_io(&self->super);

		debug("client_x11.c: Sending real X11 setup message: %xS\n",
		      msg);
                  
		/* Send real x11 connection setup message. */
		channel_forward_write(&self->super, STRING_LD(msg));
		lsh_string_free(msg);
		  
		self->state = CLIENT_X11_CANT_HAPPEN;
	      }
	    else
	      {
		werror("client_x11: X11 connection denied; bad cookie.\n");
	      fail:
		channel_close(&self->super.super);
		self->state = CLIENT_X11_CANT_HAPPEN;
	      }
	    break;
#undef PAD
	  }
	}
    }
}

static struct client_x11_channel *
make_client_x11_channel(int fd,
			struct client_x11_display *display)
{
  NEW(client_x11_channel, self);

  /* Use a limited window size for the setup */
  init_channel_forward(&self->super, fd, X11_WINDOW_SIZE, NULL);

  self->super.super.rec_window_size = X11_SETUP_MAX_LENGTH;
  self->super.super.receive = do_client_channel_x11_receive;

  self->display = display;
  self->state = 0;
  self->buffer = lsh_string_alloc(X11_SETUP_MAX_LENGTH);

  return self;
}

/* GABA:
   (class
     (name x11_connect_state)
     (super io_connect_state)
     (vars
       (display object client_x11_display)
       (info const object channel_open_info)))
*/

static void
x11_connect_done(struct io_connect_state *s, int fd)
{
  CAST(x11_connect_state, self, s);

  struct client_x11_channel *channel
    = make_client_x11_channel(fd, self->display);
  
  channel_open_confirm(self->info, &channel->super.super);
}

/* Identical to tcpforward_connect_error. Unify? */
static void
x11_connect_error(struct io_connect_state *s, int error)
{
  CAST(x11_connect_state, self, s);
  
  werror("Connection failed, socket error %i\n", error);
  channel_open_deny(self->info,
		    SSH_OPEN_CONNECT_FAILED, "Connection failed");
}

static struct resource *
x11_connect(struct client_x11_display *display,
	    const struct channel_open_info *info)
{
  NEW(x11_connect_state, self);

  init_io_connect_state(&self->super,
			x11_connect_done,
			x11_connect_error);

  self->display = display;
  self->info = info;
  
  if (!io_connect(&self->super, display->address_length, display->address))
    {
      werror("Connecting to X11 server failed: %e.\n", errno);
      return NULL;
    }
  return &self->super.super.super;
}

DEFINE_CHANNEL_OPEN(channel_open_x11)
	(struct channel_open *s UNUSED,
	 const struct channel_open_info *info,
	 struct simple_buffer *args)
{
  CAST(client_connection, connection, info->connection);
  CAST_SUBTYPE(client_x11_handler, handler,
       resource_list_top(connection->x11_displays));

  if (handler)
    {
      if (handler->single_connection)
	KILL_RESOURCE(&handler->super);

      handler->open(handler, info, args);
    }
  else
    channel_open_deny(info,
		      SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
		      "Unexpected x11 request");
}


/* Setting up the forwarding. */
void
client_add_x11_handler(struct client_connection *connection,
		       struct client_x11_handler *handler)
{
  remember_resource(connection->x11_displays, &handler->super);
}

static int
xauth_lookup(struct sockaddr *sa,
             unsigned number_length,
             const char *number,
             struct lsh_string **name,
             struct lsh_string **data)
{
#if HAVE_LIBXAU

  int res = 0;
  unsigned family;

  const char *address;
  unsigned address_length;
  
#define HOST_MAX 200
  char host[HOST_MAX];
  
  const char *filename = XauFileName();
  Xauth *xa;

  if (!filename)
    return 0;

  switch(sa->sa_family)
    {
    case AF_UNIX:
      if (gethostname(host, sizeof(host) - 1) < 0)
	return 0;
      address = host;
      address_length = strlen(host);
      family = FamilyLocal;
      break;

    case AF_INET:
      {
	struct sockaddr_in *s = (struct sockaddr_in *) sa;
	
	address = (char *) &s->sin_addr;
	address_length = 4;
	family = FamilyInternet;
	break;
      }

#if WITH_IPV6
    case AF_INET6:
      {
	struct sockaddr_in6 *s = (struct sockaddr_in6 *) sa;
	
	address = (char *) &s->sin6_addr;
	address_length = 16;
	family = FamilyInternet6;
	break;
      }
#endif
    default:
      return 0;
    }

  /* 5 retries, 1 second each */
  if (XauLockAuth(filename, 5, 1, 0) != LOCK_SUCCESS)
    return 0;

  /* NOTE: The man page doesn't list the last two arguments,
     name_length and name. From the source, it seems that a zero
     name_length means match any name. */
  xa = XauGetAuthByAddr(family, address_length, address,
			number_length, number, 0, "");
  if (xa)
    {
      debug("xauth: family: %i\n", xa->family);
      debug("       address: %ps\n", xa->address_length, xa->address);
      debug("       display: %s\n", xa->number_length, xa->number);
      debug("       name: %s\n", xa->name_length, xa->name);
      debug("       data length: %i\n", xa->data_length);

      *name = ssh_format("%ls", xa->name_length, xa->name);
      *data = ssh_format("%ls", xa->data_length, xa->data);

      XauDisposeAuth(xa);
      res = 1;
    }
  else
    res = 0;

  XauUnlockAuth(filename);
  return res;
#else /* !HAVE_LIBXAU */
  return 0;
#endif /* !HAVE_LIBXAU */
}

/* Format is host:display.screen, where display and screen are numbers */
static int
parse_display(struct client_x11_display *self, const char *display)
{
  struct lsh_string *host;

  const char *num;
  unsigned num_length;
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
	return 0;

      length = separator - display;

      if (!strncmp("unix", display, length)) /* Special name unix? */
	host = NULL; /* Local transport */
      else
 	host = ssh_format("%ls", length, display);

      display = separator + 1;
    }
  
  /* Get display number */
  {
    char *end;
    num = display;
    
    display_num = strtol(display, &end, 0);

    num_length = end - num;

    if (!num_length)
      {
	lsh_string_free(host);
	return 0;
      }
    
    if (!*end)
      /* Default screen number */
      self->screen = 0;
    else if (*end != '.')
      {
	lsh_string_free(host);
	return 0;
      }
    else
      {
        display = end + 1;
        self->screen = strtol(display, &end, 0);

        if (*end)
          {
            lsh_string_free(host);
            return 0;
          }
      }
  }
  
  if (host)
    {
      /* FIXME: Some duplication with io_lookup_address. */
      struct addrinfo hints;
      struct addrinfo *list;
      int err;
      char service[10];

      /* FIXME: uses IPv4 only. */
      memset(&hints, 0, sizeof(hints));
      hints.ai_family = AF_INET;
      hints.ai_socktype = SOCK_STREAM;

      snprintf(service, sizeof(service), "%d", X11_BASE_PORT + display_num);
      
      err = getaddrinfo(lsh_get_cstring(host), service, &hints, &list);
      lsh_string_free(host);

      if (err)
	{
	  werror("parse_display: getaddrinfo failed: %z\n",
		 gai_strerror(err));
	  return 0;
	}
      self->address_length = list->ai_addrlen;
      
      self->address = lsh_space_alloc(self->address_length);
      memcpy(self->address, list->ai_addr, self->address_length);

      freeaddrinfo(list);      
    }
  else
    {
      /* Local transport */
      struct lsh_string *name = ssh_format("/tmp/.X11-unix/X%di", display_num);
      uint32_t nlength = lsh_string_length(name);
      struct sockaddr_un *sa;

      verbose("Using local X11 transport `%pS'\n", name);
      
      self->address_length = offsetof(struct sockaddr_un, sun_path) + nlength;
      sa = lsh_space_alloc(self->address_length);
      sa->sun_family = AF_UNIX;
      memcpy(sa->sun_path, lsh_string_data(name), nlength);

      lsh_string_free(name);
      self->address = (struct sockaddr *) sa;
    }

  if (!xauth_lookup(self->address,
                    num_length, num,
                    &self->auth_name,
                    &self->auth_data))
    {
      /* Fallback: Don't use xauth, and hope that the X server uses
       * xhost to let us in anyway. */
      werror("Can't find any xauth information for X11 display.\n");

      self->auth_name = ssh_format("");
      self->auth_data = ssh_format("");
    }
  
  return 1;
}

static void
do_client_x11_display_open(struct client_x11_handler *s,
			   const struct channel_open_info *info,
			   struct simple_buffer *args)
{
  CAST(client_x11_display, self, s);

  uint32_t originator_length;
  const uint8_t *originator;
  uint32_t originator_port;

  if (parse_string(args, &originator_length, &originator)
      && parse_uint32(args, &originator_port) 
      && parse_eod(args))
    {
      struct resource *r;

      verbose("x11 connection attempt, originator: %s:%i\n",
	      originator_length, originator, originator_port);

      r = x11_connect(self, info);
      if (r)
	remember_resource(info->connection->resources, r);
    }
  else
    {
      werror("do_client_x11_display_open: Invalid message!\n");
	  
      SSH_CONNECTION_ERROR(info->connection, "Invalid CHANNEL_OPEN x11 message.");
    }
}

static struct client_x11_display *
make_client_x11_display(const char *display, int single_connection)
{
  NEW(client_x11_display, self);
  init_resource(&self->super.super, NULL);

  self->super.single_connection = single_connection;
  self->super.open = do_client_x11_display_open;
  self->fake = NULL;

  if (!parse_display(self, display))
    {
      werror("Can't parse X11 display: `%z'\n", display);
      KILL(self);
      return NULL;
    }
  
  return self;
}

/* GABA:
   (class
     (name client_x11_fake_handler)
     (super client_random_handler)
     (vars
       (session object client_session)
       (display object client_x11_display)))
*/

static void
do_client_x11_handle_random_reply(struct client_random_handler *s,
				  uint32_t length,
				  const uint8_t *data)
{
  CAST(client_x11_fake_handler, self, s);

  assert(!self->display->fake);

  debug("do_client_x11_handle_random_reply: Fake cookie is %xs\n",
	length, data);

  if (length != X11_COOKIE_LENGTH)
    {
      werror("Unexpected length %i in RANDOM_REPLY for fake X11 cookie.\n",
	     length);
      channel_close(&self->session->super);
    }
  else
    {
      self->display->fake = ssh_format("%ls", length, data);

      /* NOTE: The cookie is hex encoded, presumably so that it can be
	 passed directly to the xauth command line. That's ugly, but
	 it's what the specification says. */
      
      if (!channel_send_request(&self->session->super, ATOM_LD(ATOM_X11_REQ), 1,
				"%c%s%xS%i",
				0, /* FIXME: Single connection not supported */
				MIT_COOKIE_NAME_LENGTH, MIT_COOKIE_NAME,
				self->display->fake,
				self->display->screen))
	werror("Session channel was closed in the middle of x11 forwarding setup.");
    }
}

/* GABA:
   (class
     (name client_x11_action)
     (super client_session_action)
     (vars
       (display object client_x11_display)))
*/

static void
do_action_x11_start(struct client_session_action *s,
		    struct client_session *session)
{
  CAST(client_x11_action, self, s);
  CAST(client_connection, connection, session->super.connection);

  NEW(client_x11_fake_handler, handler);
  handler->super.gateway = NULL;
  handler->super.reply = do_client_x11_handle_random_reply;

  handler->session = session;
  handler->display = self->display;

  client_random_request(connection,
			X11_COOKIE_LENGTH, &handler->super);  
}
       
static void
do_action_x11_success(struct client_session_action *s,
		      struct client_session *session)
{
  CAST(client_x11_action, self, s);
  CAST(client_connection, connection, session->super.connection);

  verbose("X11 request succeeded\n");

  client_add_x11_handler(connection, &self->display->super);
  session->x11 = &self->display->super.super;
}

static int
do_action_x11_failure(struct client_session_action *s UNUSED,
		      struct client_session *session UNUSED)
{
  verbose("x11 request failed\n");

  return 1;
}

struct client_session_action *
make_x11_action(const char *display_string, int single_connection)
{
  struct client_x11_display *display
    = make_client_x11_display(display_string, single_connection);

  if (display)
    {
      NEW(client_x11_action, self);
      self->super.serial = 0;
      self->super.start = do_action_x11_start;
      self->super.success = do_action_x11_success;
      self->super.failure = do_action_x11_failure;

      self->display = display;

      return &self->super;
    }
  else
    return NULL;
}
