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

#include <limits.h>
#include <stdio.h>

#include <unistd.h>

#include <sys/uio.h>

#include <oop.h>

#include "nettle/macros.h"

#include "channel.h"
#include "environ.h"
#include "format.h"
#include "io.h"
#include "lsh_string.h"
#include "resource.h"
#include "reaper.h"
#include "server.h"
#include "server_session.h"
#include "service.h"
#include "ssh.h"
#include "tcpforward.h"
#include "version.h"
#include "xalloc.h"

#include "lshd-connection.c.x"

enum tcpforward_type {  
  TCPFORWARD_LOCAL = 1,
  TCPFORWARD_REMOTE = 2
};

/* GABA:
   (class
     (name lshd_connection_config)
     (super server_config)
     (vars
       (helper_fd . int)
       (subsystem_config object service_config)
       ; For all these, -1 means use the default
       ; enum tcpforward_type flags ored together.
       (allow_tcpforward . int)
       (allow_session . int)
       (allow_shell . int)
       (allow_exec . int)
       (allow_pty . int)
       (allow_x11 . int)))
*/

/* GABA:
   (class
     (name lshd_connection)
     (super ssh_connection)
     (vars
       (config object lshd_connection_config)
       (reader object service_read_state)))
*/

static void
kill_lshd_connection(struct resource *s)
{
  CAST(lshd_connection, self, s);
  if (self->super.super.alive)
    {
      trace("kill_lshd_connection\n");

      self->super.super.alive = 0;      
  
      KILL_RESOURCE(&self->super.resources->super);
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

/* NOTE: Uses blocking mode. Doesn't set any sequence number. The
   reason we may get away with blocking mode, is that it's primarily
   the client's responsibility to consume data and avoid dead locks.
   FIXME: But that may not be enough if we're forwarding channels with
   reversed client/server responsibilities. */
static void
write_packet(struct lshd_connection *self, struct lsh_string *packet)
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
      werror("write_packet: Write failed: %e.\n", errno);
      KILL_RESOURCE(&self->super.super);
    }

  lsh_string_free(packet);
}
		  
static void
disconnect(struct lshd_connection *self, uint32_t reason, const char *msg)
{
  werror("disconnecting: %z.\n", msg);

  write_packet(self, format_disconnect(reason, msg, ""));
  KILL_RESOURCE(&self->super.super);
}

static void
service_start_read(struct lshd_connection *self);

/* NOTE: fd is in blocking mode, so we want precisely one call to read. */
static void *
oop_read_service(oop_source *source UNUSED, int fd, oop_event event, void *state)
{
  CAST(lshd_connection, self, (struct lsh_object *) state);

  assert(event == OOP_READ);

  for (;;)
    {
      enum ssh_read_status status;

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
	case SSH_READ_IO_ERROR:
	  werror("Read failed: %e.\n", errno);
	  exit(EXIT_FAILURE);
	  break;
	case SSH_READ_PROTOCOL_ERROR:
	  werror("Invalid data from transport layer: %z\n", error_msg);
	  exit(EXIT_FAILURE);
	  break;
	case SSH_READ_EOF:
	  verbose("Transport layer closed.\n");
	  return OOP_HALT;

	case SSH_READ_PUSH:
	case SSH_READ_PENDING:
	  return OOP_CONTINUE;

	case SSH_READ_COMPLETE:
	  if (!length)
	    disconnect(self, SSH_DISCONNECT_BY_APPLICATION,
		       "lshd-connection received an empty packet");

	  msg = packet[0];

	  if (msg < SSH_FIRST_USERAUTH_GENERIC)
	    /* FIXME: We might want to handle SSH_MSG_UNIMPLEMENTED. */
	    disconnect(self, SSH_DISCONNECT_BY_APPLICATION,
		       "lshd-connection received a transport layer packet");

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
service_start_read(struct lshd_connection *self)
{
  global_oop_source->on_fd(global_oop_source,
			   STDIN_FILENO, OOP_READ,
			   oop_read_service, self);  
}


static void
do_write_packet(struct ssh_connection *s, struct lsh_string *packet)
{
  CAST(lshd_connection, self, s);
  write_packet(self, packet);
}

static void
do_disconnect(struct ssh_connection *s, uint32_t reason, const char *msg)
{
  CAST(lshd_connection, self, s);
  disconnect(self, reason, msg);  
}

static struct lshd_connection *
make_lshd_connection(struct lshd_connection_config *config)
{
  NEW(lshd_connection, self);
  init_ssh_connection(&self->super, kill_lshd_connection, do_write_packet, do_disconnect);
  
  io_register_fd(STDIN_FILENO, "transport read fd");

  self->config = config;
  self->reader = make_service_read_state();
  service_start_read(self);

  if (config->allow_session)
    {
      struct alist *requests = make_alist(0, -1);

      if (config->allow_shell)
	ALIST_SET(requests, ATOM_SHELL, &shell_request_handler.super);
      if (config->allow_exec)
	ALIST_SET(requests, ATOM_EXEC, &exec_request_handler.super);

      if (config->allow_pty)
	{
#if WITH_PTY_SUPPORT
	  ALIST_SET(requests, ATOM_PTY_REQ, &pty_request_handler.super);
	  ALIST_SET(requests, ATOM_WINDOW_CHANGE,
		    &window_change_request_handler.super);
#else /* !WITH_PTY_SUPPORT */
	  werror("PTY support disabled at compile time.\n");
#endif /* !WITH_PTY_SUPPORT */
	}
      if (config->allow_x11)
	{
#if WITH_X11_FORWARD
	  ALIST_SET (requests, ATOM_X11_REQ, &x11_request_handler.super);
#else /* !WITH_X11_FORWARD */
	  werror("X11 support disabled at compile time.\n");
#endif /* !WITH_X11_FORWARD */
	}
      if (!object_queue_is_empty(&config->subsystem_config->services))
	ALIST_SET(requests, ATOM_SUBSYSTEM,
		  &make_subsystem_handler(config->subsystem_config)->super);

      ALIST_SET(self->super.channel_types, ATOM_SESSION,
		&make_open_session(requests,
				   config->helper_fd)->super);
    }

  if (config->allow_tcpforward & TCPFORWARD_LOCAL)
    ALIST_SET(self->super.channel_types, ATOM_DIRECT_TCPIP,
	      &channel_open_direct_tcpip.super);

  if (config->allow_tcpforward & TCPFORWARD_REMOTE)
    {
      ALIST_SET(self->super.global_requests, ATOM_TCPIP_FORWARD,
		&tcpip_forward_handler.super);
      ALIST_SET(self->super.global_requests, ATOM_CANCEL_TCPIP_FORWARD,
		&tcpip_cancel_forward_handler.super);
    }

  return self;
}

/* Option parsing */

static const struct config_parser
lshd_connection_config_parser;

static struct lshd_connection_config *
make_lshd_connection_config(void)
{
  NEW(lshd_connection_config, self);
  init_server_config(&self->super, &lshd_connection_config_parser,
		     FILE_LSHD_CONNECTION_CONF,
		     ENV_LSHD_CONNECTION_CONF);

  self->subsystem_config = make_service_config ();
  self->helper_fd = -1;

  self->allow_tcpforward = -1;
  self->allow_session = -1;
  self->allow_shell = -1;
  self->allow_exec = -1;
  self->allow_pty = -1;
  self->allow_x11 = -1;

  return self;
}

enum {
  OPT_HELPER_FD = 0x201,
  OPT_SESSION,
  OPT_NO_SESSION,
  OPT_SHELL,
  OPT_NO_SHELL,
  OPT_EXEC,
  OPT_NO_EXEC,
  OPT_PTY,
  OPT_NO_PTY,
  OPT_X11_FORWARD,
  OPT_NO_X11_FORWARD,
  OPT_SUBSYSTEM,
  OPT_ADD_SUBSYSTEM,
  OPT_TCPFORWARD,
  OPT_NO_TCPFORWARD,
};

static const struct argp_option
main_options[] =
{
  /* Name, key, arg-name, flags, doc, group */
  { "allow-tcpip-forward", OPT_TCPFORWARD, "TYPE", OPTION_ARG_OPTIONAL,
    "The optional type can be \"local\" or \"remote\".", 0 },
  { "deny-tcpip-forward", OPT_NO_TCPFORWARD, NULL, 0,
    "Disable all TCP/IP forwarding.", 0 },
  { "helper-fd", OPT_HELPER_FD, "FD", 0,
    "Use this file descriptor to talk to the helper process "
    "managing ptys and utmp records.", 0 },
  { NULL, 0, NULL, 0, "Session configuration:", 0},
  { "allow-session", OPT_SESSION, NULL, 0, "Allow sessions channels.", 0},
  { "deny-session", OPT_NO_SESSION, NULL, 0, "Deny all session channels.", 0},
  { "allow-shell", OPT_SHELL, NULL, 0, "Allow shell sessions.", 0},
  { "deny-shell", OPT_NO_SHELL, NULL, 0, "Deny shell sessions.", 0},
  { "allow-exec", OPT_EXEC, NULL, 0, "Allow exec sessions.", 0},
  { "deny-exec", OPT_NO_EXEC, NULL, 0, "Deny exec sessions.", 0},
  { "subsystem", OPT_SUBSYSTEM, "NAME { COMMAND LINE }", 0,
    "Enable named subsystem.", 0 },
  { "add-subsystem", OPT_ADD_SUBSYSTEM, "NAME { COMMAND LINE }", 0,
    "Enable named subsystem. Unlike --subsystem does not override "
    "other services listed in the config file.", 0 },
  { NULL, 0, NULL, 0, NULL, 0 }
};

const char *argp_program_version
= "lshd-connection (" PACKAGE_STRING ")";

const char *argp_program_bug_address = BUG_ADDRESS;

static const struct argp_child
main_argp_children[] =
{
  { &server_argp, 0, "", 0 },
  { NULL, 0, NULL, 0}
};

#define CASE_FLAG(opt, flag)			\
  case OPT_##opt:				\
    self->flag = 1;				\
    break;					\
  case OPT_NO_##opt:				\
    self->flag = 0;				\
    break

static error_t
main_argp_parser(int key, char *arg, struct argp_state *state)
{
  CAST(lshd_connection_config, self, state->input);

  switch(key)
    {
    default:
      return ARGP_ERR_UNKNOWN;
    case ARGP_KEY_INIT:
      state->child_inputs[0] = &self->super;
      break;
    case ARGP_KEY_END:
      /* Defaults should have been setup at the end of the config
	 file parsing. */
      assert(self->allow_tcpforward >= 0);
      assert(self->allow_session >= 0);
      assert(self->allow_shell >= 0);
      assert(self->allow_exec >= 0);
      assert(self->allow_pty >= 0);
      assert(self->allow_x11 >= 0);

      if (!self->allow_tcpforward && !self->allow_session)
	argp_error(state, "All channel types disabled.");
      if (self->allow_session
	  && !self->allow_shell && !self->allow_exec
	  && object_queue_is_empty(&self->subsystem_config->services))
	argp_error(state, "Session channel enabled, but all requests "
		   "to start a process are disabled.");

      break;
    case OPT_HELPER_FD:
      {
	long x;
	char *end;
	int socket_error;
	socklen_t len = sizeof(socket_error);
	
	if (self->helper_fd != -1)
	  argp_error(state, "There can be at most one --helper-fd option.");

	x = strtol(arg, &end, 10);
	if (x < 0 || x > INT_MAX)
	  argp_error(state, "Invalid argument to --helper-fd.");

	if (getsockopt(x, SOL_SOCKET, SO_ERROR,
		       (char *) &socket_error, &len) < 0)
	  argp_failure(state, EXIT_FAILURE, errno,
		       "The fd %s passed to --helper-fd is invalid", arg);

	self->helper_fd = x;
	io_set_close_on_exec(self->helper_fd);
      }
      break;
    case OPT_TCPFORWARD:
      if (optarg)
	{
	  if (!strcmp(optarg, "local"))
	    self->allow_tcpforward = TCPFORWARD_LOCAL;
	  else if (!strcmp(optarg, "remote"))
	    self->allow_tcpforward = TCPFORWARD_REMOTE;
	  else
	    argp_error(state, "Invalid argument to --allow-tcpforward.");
	}
      else
	self->allow_tcpforward = TCPFORWARD_LOCAL | TCPFORWARD_REMOTE;
      
      break;
    case OPT_NO_TCPFORWARD:
      self->allow_tcpforward = 0;
      break;

    CASE_FLAG(SESSION, allow_session);
    CASE_FLAG(SHELL, allow_shell);
    CASE_FLAG(EXEC, allow_exec);
    CASE_FLAG(PTY, allow_pty);
    CASE_FLAG(X11_FORWARD, allow_x11);

    case OPT_SUBSYSTEM:
      self->subsystem_config->override_config_file = 1;
      /* Fall through */
    case OPT_ADD_SUBSYSTEM:
      service_config_argp(self->subsystem_config,
			  state, "subsystem", arg);      
      break;      
    }
  return 0;
}
	
static const struct argp
main_argp =
  { main_options, main_argp_parser,
  NULL,
  "Handles the ssh-connection service.\v"
  "Intended to be invoked by lshd and lshd-userauth.",
  main_argp_children,
  NULL, NULL
};

static const struct config_option
lshd_connection_config_options[] = {
  { OPT_SUBSYSTEM, "subsystem", CONFIG_TYPE_LIST, "Enable subsystem.", NULL },
  { OPT_SESSION, "allow-session", CONFIG_TYPE_BOOL,
    "Support for session channels.", "yes" },
  { OPT_SHELL, "allow-shell", CONFIG_TYPE_BOOL,
    "Support for shell requests.", "yes" },
  { OPT_EXEC, "allow-exec", CONFIG_TYPE_BOOL,
    "Support for exec requests.", "yes" },
  { OPT_PTY, "allow-pty", CONFIG_TYPE_BOOL,
    "Support for pty requests.", "yes" },
  { OPT_X11_FORWARD, "allow-x11", CONFIG_TYPE_BOOL,
    "Support X11 forwarding.", "yes" },
  { OPT_TCPFORWARD, "allow-tcpforward", CONFIG_TYPE_STRING,
    "Support for tcpforward, \"yes\", \"no\", \"local\", or \"remote\".", "yes" },

  { 0, NULL, 0, NULL, NULL }
};

static int
lshd_connection_config_handler(int key, uint32_t value, const uint8_t *data UNUSED,
			       struct config_parser_state *state)
{
  CAST_SUBTYPE(lshd_connection_config, self, state->input);
  switch (key)
    {
    case CONFIG_PARSE_KEY_INIT:
      state->child_inputs[0] = &self->super.super;
      break;
    case CONFIG_PARSE_KEY_END:
      /* Set up defaults, for values specified neither in the
	 configuration file nor on the command line. */
      if (self->allow_tcpforward < 0)
	self->allow_tcpforward = 0;
      if (self->allow_session < 0)
	self->allow_session = 0;
      if (self->allow_shell < 0)
	self->allow_shell = 0;
      if (self->allow_exec < 0)
	self->allow_exec = 0;
      if (self->allow_pty < 0)
	self->allow_pty = 0;
      if (self->allow_x11 < 0)
	self->allow_x11 = 0;

      break;

    case OPT_SUBSYSTEM:
      if (!service_config_option(self->subsystem_config,
				 "subsystem", value, data))
	return EINVAL;
      break;

    case OPT_TCPFORWARD:
      {
	int flags;
	switch (value)
	  {
	  default:
	  fail:
	    werror("Invalid argument for allow-tcpforward option.\n");
	    return EINVAL;
	  case 2:
	    if (memcmp(data, "no", value))
	      goto fail;
	    flags = 0;
	    break;
	  case 3:
	    if (memcmp(data, "yes", value))
	      goto fail;
	    flags = TCPFORWARD_LOCAL | TCPFORWARD_REMOTE;
	    break;
	  case 5:
	    if (memcmp(data, "local", value))
	      goto fail;
	    flags = TCPFORWARD_LOCAL;
	    break;
	  case 6:
	    if (memcmp(data, "remote", value))
	      goto fail;
	    flags = TCPFORWARD_REMOTE;
	    break;
	  }
		
	if (self->allow_tcpforward < 0)
	  self->allow_tcpforward = flags;

	break;
      }

    case OPT_SESSION:
      if (self->allow_session < 0)
	self->allow_session = value;
      break;
    case OPT_SHELL:
      if (self->allow_shell < 0)
	self->allow_shell = value;
      break;
    case OPT_EXEC:
      if (self->allow_exec < 0)
	self->allow_exec = value;
      break;
    case OPT_PTY:
      if (self->allow_pty < 0)
	self->allow_pty = value;
      break;
    case OPT_X11_FORWARD:
      if (self->allow_x11 < 0)
	self->allow_x11 = value;
      break;
    }
  return 0;
}

static const struct config_parser *
lshd_connection_config_children[] = {
  &werror_config_parser,
  NULL
};

static const struct config_parser
lshd_connection_config_parser = {
  lshd_connection_config_options,
  lshd_connection_config_handler,
  lshd_connection_config_children
};

int
main(int argc, char **argv)
{
  struct lshd_connection *connection;
  struct lshd_connection_config *config
    = make_lshd_connection_config();

  argp_parse(&main_argp, argc, argv, 0, NULL, config);

  io_init();
  reaper_init();

  trace("Started connection service\n");
  if (config->helper_fd != -1)
    verbose("helper fd: %i.\n", config->helper_fd);

  connection = make_lshd_connection(config);
  gc_global(&connection->super.super);

  io_run();

  verbose("Exiting.\n");
  return EXIT_SUCCESS;
}
