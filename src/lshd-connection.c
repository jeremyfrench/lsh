/* lshd-connection.c
 *
 * Main program for the ssh-connection service.
 *
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005 Niels Möller
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

#include <stdio.h>

#include <oop.h>

#include "nettle/macros.h"

#include "channel.h"
#include "format.h"
#include "io.h"
#include "lsh_string.h"
#include "resource.h"
#include "reaper.h"
#include "server_session.h"
#include "service.h"
#include "ssh.h"
#include "version.h"
#include "werror.h"
#include "xalloc.h"

#include "lshd-connection.c.x"

/* GABA:
   (class
     (name connection)
     (super channel_table)
     (vars
       (reader object service_read_state)))
*/

static void
kill_connection(struct resource *s)
{
  CAST(connection, self, s);
  if (self->super.super.alive)
    {
      trace("kill_connection\n");

      self->super.super.alive = 0;      
  
      kill_channels(&self->super);
      io_close_fd(STDIN_FILENO);
    }
}

/* Modifies the iv in place */
static int
blocking_writev(int fd, struct iovec *iv, size_t n)
{
  while (n > 0)
    {
      int res = writev(fd, iv, n);
      uint32_t done;
      
      if (res < 0)
	{
	  if (errno == EINTR)
	    continue;
	  else
	    return 0;
	}

      for (done = res; n > 0 && done >= iv[0].iov_len ;)
	{
	  done -= iv[0].iov_len;
	  iv++; n--;
	}
      if (done > 0)
	{
	  iv[0].iov_base = (char *) iv[0].iov_base + done;
	  iv[0].iov_len -= done;
	}
    }
  return 1;
}

/* NOTE: Uses blocking mode. Doesn't set any sequence number. */
static void
write_packet(struct connection *self, struct lsh_string *packet)
{
  uint32_t length;
  const uint8_t *data;
  uint8_t header[8];
  struct iovec iv[2];
  
  length = lsh_string_length(packet);
  data = lsh_string_data(packet);

  assert(length > 0);
  trace("Writing packet of type %T (%i)\n", data[0], data[0]);
  debug("packet contents: %xs\n", length, data);

  WRITE_UINT32(header, 0);
  WRITE_UINT32(header + 4, length);
  
  iv[0].iov_base = header;
  iv[0].iov_len = sizeof(header);
  iv[1].iov_base = (char *) data;
  iv[1].iov_len = length;

  if (!blocking_writev(STDOUT_FILENO, iv, 2))
    {
      werror("write_packet: Write failed: %e\n", errno);
      KILL_RESOURCE(&self->super.super);
    }

  lsh_string_free(packet);
}
		  
static void
disconnect(struct connection *self, const char *msg)
{
  werror("disconnecting: %z.\n", msg);

  write_packet(self, format_disconnect(SSH_DISCONNECT_BY_APPLICATION,
				       msg, ""));
  KILL_RESOURCE(&self->super.super);
}

static void
service_start_read(struct connection *self);

/* NOTE: fd is in blocking mode, so we want precisely one call to read. */
static void *
oop_read_service(oop_source *source UNUSED, int fd, oop_event event, void *state)
{
  CAST(connection, self, (struct lsh_object *) state);

  assert(event == OOP_READ);

  for (;;)
    {
      enum service_read_status status;

      uint32_t seqno;
      uint32_t length;      
      const uint8_t *packet;
      const char *error_msg;
      uint8_t msg;
      
      status = service_read_packet(self->reader, fd,
				   &error_msg,
				   &seqno, &length, &packet);
      fd = -1;

      switch (status)
	{
	case SERVICE_READ_IO_ERROR:
	  werror("Read failed: %e\n", errno);
	  exit(EXIT_FAILURE);
	  break;
	case SERVICE_READ_PROTOCOL_ERROR:
	  werror("Invalid data from transport layer: %z\n", error_msg);
	  exit(EXIT_FAILURE);
	  break;
	case SERVICE_READ_EOF:
	  werror("Transport layer closed\n", error_msg);
	  return OOP_HALT;
	  break;
	case SERVICE_READ_PUSH:
	case SERVICE_READ_PENDING:
	  return OOP_CONTINUE;

	case SERVICE_READ_COMPLETE:
	  if (!length)
	    disconnect(self, "lshd-connection received an empty packet");

	  msg = packet[0];

	  if (msg < SSH_FIRST_USERAUTH_GENERIC)
	    /* FIXME: We might want to handle SSH_MSG_UNIMPLEMENTED. */
	    disconnect(self, "lshd-connection received a transport layer packet");

	  if (msg < SSH_FIRST_CONNECTION_GENERIC)
	    {
	      /* Ignore */
	    }
	  else if (!channel_packet_handler(&self->super, length, packet))
	    write_packet(self, format_unimplemented(seqno));
	}
    }
}

static void
service_start_read(struct connection *self)
{
  global_oop_source->on_fd(global_oop_source,
			   STDIN_FILENO, OOP_READ,
			   oop_read_service, self);  
}


static void
do_write_packet(struct channel_table *s, struct lsh_string *packet)
{
  CAST(connection, self, s);
  write_packet(self, packet);
}

static struct connection *
make_connection(void)
{
  NEW(connection, self);
  init_channel_table(&self->super, kill_connection, do_write_packet);

  io_register_fd(STDIN_FILENO, "transport read fd");

  self->reader = make_service_read_state();
  service_start_read(self);

  /* FIXME: Never enables X11 or pty */
  ALIST_SET(self->super.channel_types, ATOM_SESSION,
	    &make_open_session(
	      make_alist(1,
			 ATOM_SHELL, &shell_request_handler,
			 /* ATOM_PTY_REQ, &pty_request_handler, */
			 /* ATOM_X11_REQ, &x11_request_handler, */ -1))->super);

  return self;
}

/* Option parsing */

const char *argp_program_version
= "lshd-connection (lsh-" VERSION "), secsh protocol version " SERVER_PROTOCOL_VERSION;

const char *argp_program_bug_address = BUG_ADDRESS;

static const struct argp_child
main_argp_children[] =
{
  { &werror_argp, 0, "", 0 },
  { NULL, 0, NULL, 0}
};

static const struct argp
main_argp =
{ NULL, NULL,
  NULL,
  "Handles the ssh-connection service.\v"
  "Intended to be invoked by lshd and lshd-userauth.",
  main_argp_children,
  NULL, NULL
};


int
main(int argc, char **argv)
{
  struct connection *connection;
#if 0
  fprintf(stderr, "argc = %d\n", argc);
  {
    int i;
    for (i = 0; i < argc; i++)
      fprintf(stderr, "argv[%d] = %s\n", i, argv[i]);
  }
#endif
  argp_parse(&main_argp, argc, argv, 0, NULL, NULL);

  io_init();
  reaper_init();

  werror("Started connection service\n");
  
  connection = make_connection();
  gc_global(&connection->super.super);

  io_run();

  verbose("Exiting.\n");
  return EXIT_SUCCESS;
}
