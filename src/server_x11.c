/* server_x11.c
 *
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 2002 Niels Möller
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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <string.h>

#include <fcntl.h>
#include <unistd.h>

#if HAVE_X11_XAUTH_H
#include <X11/Xauth.h>
#endif

#undef HAVE_LIBXAU

#include <sys/types.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#include "server_x11.h"

#include "channel_forward.h"
#include "environ.h"
#include "format.h"
#include "io.h"
#include "lsh_string.h"
#include "lsh_process.h"
#include "reaper.h"
#include "resource.h"
#include "ssh.h"
#include "werror.h"
#include "xalloc.h"


#define GABA_DEFINE
#include "server_x11.h.x"
#undef GABA_DEFINE

#if WITH_X11_FORWARD

#ifndef SUN_LEN
# define SUN_LEN(x) \
  (offsetof(struct sockaddr_un, sun_path) + strlen((x)->sun_path))
#endif

#define X11_WINDOW_SIZE 10000

#define X11_MIN_COOKIE_LENGTH 10
#define X11_SOCKET_DIR "/tmp/.X11-unix"

/* The interval of display numbers that we use. */
#define X11_MIN_DISPLAY 10
#define X11_MAX_DISPLAY 1000

static void
do_kill_x11_listen_port(struct resource *s)
{
  CAST(x11_listen_port, self, s);
  int old_cd;

  if (self->super.super.super.alive)
    {
      self->super.super.super.alive = 0;
      io_close_fd(self->super.super.fd);

      assert(self->dir >= 0);

      /* Temporarily change to the right directory. */
      old_cd = lsh_pushd_fd(self->dir);

      close(self->dir);
      self->dir = -1;

      if (old_cd < 0)
	return;

      if (unlink(lsh_get_cstring(self->name)) < 0)
	werror("Failed to delete x11 socket %S: %e.\n",
	       self->name, errno);

      lsh_popd(old_cd, X11_SOCKET_DIR);

      if (unlink(lsh_get_cstring(self->xauthority)) < 0)
	werror("Failed to delete xauthority file %S: %e.\n",
	       self->xauthority, errno);
	
    }
}

static void
do_x11_listen_port_accept(struct io_listen_port *s,
				 int fd,
				 socklen_t addr_length UNUSED,
				 const struct sockaddr *addr UNUSED)
{
  CAST(x11_listen_port, self, s);
  struct ssh_channel *channel;

  trace("x11_listen_port_accept\n");

  io_register_fd(fd, "forwarded X11 socket");
  if (self->single)
    KILL_RESOURCE(&self->super.super.super);

  channel = &make_channel_forward(fd, X11_WINDOW_SIZE)->super;

  /* NOTE: The request ought to include some reference to the
   * corresponding x11 request, but no such id is specified in the
   * protocol spec. */
  /* NOTE: The name "unix-domain" was suggested by Tatu in
   * <200011290813.KAA17106@torni.hel.fi.ssh.com> */
  if (!channel_open_new_type(self->connection, channel,
			     ATOM_LD(ATOM_X11),
			     "%z%i", "unix-domain", 0))
    {
      werror("Allocating a local channel number for forwarded X11 failed.");
      KILL_RESOURCE(&channel->super);
    }
}

static struct x11_listen_port *
make_x11_listen_port(int dir, const struct lsh_string *name,
		     int display_number, int fd,
		     struct ssh_connection *connection,
		     int single)
{
  NEW(x11_listen_port, self);
  init_io_listen_port(&self->super, fd, do_x11_listen_port_accept);
  self->super.super.super.kill = do_kill_x11_listen_port;

  self->display = NULL;
  self->xauthority = NULL;

  self->dir = dir;
  self->name = name;
  self->display_number = display_number;

  self->connection = connection;
  self->single = single;

  return self;
}

/* FIXME: Figure out if and how we should use /tmp/.X11-lock. */

/* Creates a socket in tmp. Some duplication with io_bind_local in
   io.c, but sufficiently different that it doesn't seem practical to
   unify them. */
/* This code is quite paranoid in order to avoid symlink attacks when
 * creating the socket. Similar paranoia in xlib would be desirable,
 * but not realistic. However, most of this is not needed if the
 * sticky bit is set properly on the /tmp and /tmp/.X11-unix
 * directories. */
static struct x11_listen_port *
open_x11_socket(struct ssh_connection *connection,
		int single)
{
  int old_cd;
  int dir;
  mode_t old_umask;
  
  int number;
  int s;
  struct lsh_string *name = NULL;

  if (mkdir(X11_SOCKET_DIR, 01777) < 0 && errno != EEXIST)
    werror("Failed to create `%z': %e.\n", X11_SOCKET_DIR, errno);

  /* We have to change the umask, as that's the only way to control
   * the permissions that bind uses. */

  old_umask = umask(0077);
  
  old_cd = lsh_pushd(X11_SOCKET_DIR, &dir, 0, 0);
  if (old_cd < 0)
    {
      werror("Failed to cd to `%z': %e.\n", X11_SOCKET_DIR, errno);

      umask(old_umask);
      return NULL;
    }
  
  for (number = X11_MIN_DISPLAY; number <= X11_MAX_DISPLAY; number++)
    {
      /* The default size of sockaddr_un should always be enough to format
       * the filename "X<display num>". */
      struct sockaddr_un sa;
  
      sa.sun_family = AF_UNIX;
      sa.sun_path[sizeof(sa.sun_path) - 1] = '\0';
      snprintf(sa.sun_path, sizeof(sa.sun_path), "X%d", number);

      trace("Trying to bind X11 display %i\n", number);
      s = io_bind_sockaddr((struct sockaddr *) &sa, SUN_LEN(&sa));

      if (s >= 0)
	{
	  /* Store name */
	  name = make_string(sa.sun_path);
	  break;
	}
      else if (errno != EADDRINUSE)
	/* FIXME: On Solaris, gid root is required to create sockets
	   in /tmp/.X11-unix. Attempt to bind tcp/ip port on localhost
	   instead? */
	break;
    }

  umask(old_umask);
  
  lsh_popd(old_cd, X11_SOCKET_DIR);

  if (!name)
    {
      /* Couldn't find any display */
      close(dir);
      
      return NULL;
    }

  return make_x11_listen_port(dir, name, number, s, connection, single);
}

static int
create_xauth(struct x11_listen_port *port, const char *hostname,
	     uint32_t protocol_length, const uint8_t *protocol,
	     uint32_t cookie_length, const uint8_t *cookie)
{
  size_t hostname_length;
  char number[10];
  size_t number_length;
  const char *file;
  int fd;
  int res;
  
  snprintf(number, sizeof(number), "%d", port->display_number);
  number_length = strlen(number);
  hostname_length = strlen(hostname);
  file = lsh_get_cstring(port->xauthority);
  {
#if HAVE_LIBXAU
  Xauth xa;
  FILE *f;

  /* Casts needed since the Xauth pointers are non-const. */
  xa.family = FamilyLocal;
  xa.address_length = hostname_length;
  xa.address = (char *) hostname;
  xa.number_length = number_length;
  xa.number = number;
  xa.name_length = protocol_length;
  xa.name = (char *) protocol;
  xa.data_length = cookie_length;
  xa.data = (char *) cookie;

  /* Is locking overkill? */
  if (XauLockAuth(file, 1, 1, 0) != LOCK_SUCCESS)
    return 0;

  /* Use O_EXCL rather than O_TRUNC, since we create the file directly
     under /tmp, and may be subject to symlink attacks. */
  fd = open(file, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0)
    {
      werror("Opening xauth file %z failed: %e.\n", file, errno);
    fail:
      XauUnlockAuth(file);
      return 0;
    }
	    
  f = fdopen(fd, "wb");
  if (!f)
    {
      werror("fdopen of xauth file %z failed.\n", file);
      close(fd);
      goto fail;
    }
  res = XauWriteAuth(f, &xa);

  if (fclose(f) != 0)
    res = 0;

  XauUnlockAuth(file);
  return res;
#else /* !HAVE_LIBXAU */
  /* The xauth file is a sequence of entries of the following format:
   *
   * uint16_t                family
   * uint16_t                address_length
   * uint8_t[address_length] address
   * uint16_t                display_length
   * uint8_t[display_length] display  (a number, formatted as ascii digits)
   * uint16_t                name_length
   * uint8_t[name_length]    name  (e.g "MIT-MAGIC-COOKIE-1")
   * uint16_t                data_length
   * uint8_t[data_length]    data
   *
   * All uint16_t are in network byte order.
   */
  struct lsh_string *xa;

  fd = open(file, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0)
    {
      werror("Opening xauth file %z failed: %e.\n", file, errno);
      return 0;
    }

#define XAUTH_STRING(l, p) ((l) >> 8), (l) & 0xff, l, p

  xa = ssh_format("%c%c%c%c%ls%c%c%ls%c%c%ls%c%c%ls",
		  1, 0, /* FamilyLocal = 256 */
		  XAUTH_STRING(hostname_length, hostname),
		  XAUTH_STRING(number_length, number),
		  XAUTH_STRING(protocol_length, protocol),
		  XAUTH_STRING(cookie_length, cookie));
  res = write_raw(fd, STRING_LD(xa));
  lsh_string_free(xa);
  close(fd);

  return res;
#endif /* !HAVE_LIBXAU */
  }
}

struct x11_listen_port *
server_x11_setup(struct ssh_channel *channel,
		 int single,
		 uint32_t protocol_length, const uint8_t *protocol,
		 uint32_t cookie_length, const uint8_t *cookie,
		 uint32_t screen)
{
  struct x11_listen_port *port;
  const char *tmp;
#define HOST_MAX 200
  char host[HOST_MAX];

  if (cookie_length < X11_MIN_COOKIE_LENGTH)
    {
      werror("server_x11_setup: Cookie too small.\n");
      return NULL;
    }

  if (gethostname(host, sizeof(host) - 1) < 0)
    return 0;
  
  /* Get a free socket under /tmp/.X11-unix/ */
  port = open_x11_socket(channel->connection, single);
  if (!port)
    return NULL;

  /* FIXME: Does it make sense to check for TMPDIR? I don't think
     there's any way to get set it in this environment. */
  tmp = getenv(ENV_TMPDIR);
  if (!tmp)
    tmp = "/tmp";

  port->xauthority = ssh_format("%lz/.lshd.%di.Xauthority", tmp, port->display_number);

  if (!create_xauth(port, host, protocol_length, protocol,
		    cookie_length, cookie))
    {
      KILL_RESOURCE(&port->super.super.super);
      return NULL;
    }
  else if (!io_listen(&port->super))
    {
      KILL_RESOURCE(&port->super.super.super);
      return NULL;
    }
  else
    {
      port->display = ssh_format("unix:%di.%di",
				 port->display_number, screen);
      return port;
    }
}

#endif /* WITH_X11_FORWARD */
