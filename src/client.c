/* client.c
 *
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998, 1999, 2000, 2008 Niels Möller
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
#include <signal.h>

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>

#include "client.h"

#include "channel.h"
#include "environ.h"
#include "format.h"
#include "gateway.h"
#include "interact.h"
#include "io.h"
#include "lsh_string.h"
#include "parse.h"
#include "service.h"
#include "ssh.h"
#include "tcpforward.h"
#include "translate_signal.h"
#include "xalloc.h"
#include "io.h"

#include "lsh_argp.h"

#define GABA_DEFINE
#include "client.h.x"
#undef GABA_DEFINE

#include "client.c.x"

#define CONNECTION_WRITE_BUFFER_SIZE (100*SSH_MAX_PACKET)
#define CONNECTION_WRITE_BUFFER_STOP_THRESHOLD \
  (CONNECTION_WRITE_BUFFER_SIZE - 10*SSH_MAX_PACKET)
#define CONNECTION_WRITE_BUFFER_START_THRESHOLD \
  (10 * SSH_MAX_PACKET)

static void
handle_random_reply(struct client_connection *self,
		    uint32_t length, const uint8_t *packet);

/* FIXME: Duplicates code in lshd-connection and gateway.c, in
   particular oop_read_service. */

static void
kill_client_connection(struct resource *s)
{
  CAST(client_connection, self, s);
  if (self->super.super.alive)
    {
      trace("kill_client_connection\n");

      self->super.super.alive = 0;      

      KILL_RESOURCE_LIST(self->super.resources);
      
      io_close_fd(self->transport);
      self->transport = -1;
    }
}

static void
service_start_write(struct client_connection *self);

static void
service_stop_write(struct client_connection *self);

static void
stop_gateway(struct resource *r)
{
  CAST(gateway_connection, gateway, r);
  gateway_stop_read(gateway);  
}

static void
start_gateway(struct resource *r)
{
  CAST(gateway_connection, gateway, r);
  gateway_start_read(gateway);  
}

static void *
oop_write_service(oop_source *source UNUSED, int fd, oop_event event, void *state)
{
  CAST(client_connection, self, (struct lsh_object *) state);
  uint32_t done;

  assert(event == OOP_WRITE);
  assert(fd == self->transport);
    
  done = ssh_write_flush(self->writer, self->transport, 0);
  if (done > 0)
    {
      if (!self->writer->length)
	service_stop_write(self);

      if (self->write_blocked &&
	  self->writer->length <= CONNECTION_WRITE_BUFFER_START_THRESHOLD)
	{
	  trace("oop_write_service: restarting channels.\n");
	  ssh_connection_start_channels(&self->super);
	  resource_list_foreach(self->gateway_connections, start_gateway);
	}
    }
  else if (errno != EWOULDBLOCK)
    {
      werror("oop_write_service: Write failed: %e.\n", errno);
      exit(EXIT_FAILURE);
    }
  return OOP_CONTINUE;
}

static void
service_start_write(struct client_connection *self)
{
  if (!self->write_active)
    {
      trace("service_start_write: register callback.\n");
      self->write_active = 1;
      global_oop_source->on_fd(global_oop_source, self->transport, OOP_WRITE,
			       oop_write_service, self);
    }
  if (!self->write_blocked
      && self->writer->length >= CONNECTION_WRITE_BUFFER_STOP_THRESHOLD)
    {
      trace("service_start_write: stopping channels.\n");
      self->write_blocked = 1;
      ssh_connection_stop_channels(&self->super);
      resource_list_foreach(self->gateway_connections, stop_gateway);
    }
}

static void
service_stop_write(struct client_connection *self)
{
  if (self->write_active)
    {
      trace("service_stop_write: cancel callback.\n");
      self->write_active = 0;
      global_oop_source->cancel_fd(global_oop_source, self->transport, OOP_WRITE);
    }
}

static void
write_packet(struct client_connection *connection,
	     struct lsh_string *packet)
{
  uint32_t done;
  int msg;
  
  assert(lsh_string_length(packet) > 0);
  msg = lsh_string_data(packet)[0];
  trace("Writing packet of type %T (%i)\n", msg, msg);
  debug("packet contents: %xS\n", packet);

  /* Sequence number not supported */
  packet = ssh_format("%i%fS", 0, packet);
  
  done = ssh_write_data(connection->writer,
			connection->transport, 0, 
			STRING_LD(packet));
  lsh_string_free(packet);

  if (done > 0 || errno == EWOULDBLOCK)
    {
      if (connection->writer->length)
	service_start_write(connection);
      else
	service_stop_write(connection);
    }
  else
    {
      werror("write_packet: Write failed: %e.\n", errno);
      exit(EXIT_FAILURE);
    }
}

static void
disconnect(struct client_connection *connection,
	   uint32_t reason, const char *msg)
{
  werror("disconnecting: %z.\n", msg);

  if (reason)
    write_packet(connection,
		 format_disconnect(reason, msg, ""));

  /* FIXME: If the disconnect message could not be written
     immediately, it will be lost. */
  KILL_RESOURCE(&connection->super.super);
}

static void
service_start_read(struct client_connection *self);

static void *
oop_read_service(oop_source *source UNUSED, int fd, oop_event event, void *state)
{
  CAST(client_connection, self, (struct lsh_object *) state);

  assert(event == OOP_READ);
  assert(fd == self->transport);

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
	  werror("Transport layer closed\n", error_msg);
	  return OOP_HALT;
	  break;
	case SSH_READ_PUSH:
	case SSH_READ_PENDING:
	  return OOP_CONTINUE;

	case SSH_READ_COMPLETE:
	  if (!length)
	    disconnect(self, SSH_DISCONNECT_BY_APPLICATION,
		       "lsh received an empty packet from the transport layer");

	  msg = packet[0];

	  if (msg < SSH_FIRST_CONNECTION_GENERIC)
	    {
	      /* FIXME: We might want to handle SSH_MSG_UNIMPLEMENTED. */
	      disconnect(self, SSH_DISCONNECT_BY_APPLICATION,
			 "lsh received a transport or userauth layer packet");
	      debug("%xs\n", length, packet);
	    }
	  else if (msg == SSH_LSH_RANDOM_REPLY)
	    handle_random_reply(self, length, packet);
	  else if (!channel_packet_handler(&self->super, length, packet))
	    write_packet(self, format_unimplemented(seqno));	    
	}
    }
}

static void
service_start_read(struct client_connection *self)
{
  global_oop_source->on_fd(global_oop_source,
			   self->transport, OOP_READ,
			   oop_read_service, self);  
}

static void
do_write_packet(struct ssh_connection *s, struct lsh_string *packet)
{
  CAST(client_connection, self, s);

  write_packet(self, packet);
}

static void
do_disconnect(struct ssh_connection *s, uint32_t reason, const char *msg)
{
  CAST(client_connection, self, s);
  disconnect(self, reason, msg);  
}

struct client_connection *
make_client_connection(int fd)
{
  NEW(client_connection, self);
  init_ssh_connection(&self->super, kill_client_connection,
		      do_write_packet, do_disconnect);

  io_register_fd(fd, "lsh transport connection");

  self->transport = fd;
  self->reader = make_service_read_state();
  service_start_read(self);

  self->writer = make_ssh_write_state(CONNECTION_WRITE_BUFFER_SIZE);
  self->write_active = self->write_blocked = 0;

  object_queue_init(&self->pending_random);
  
  self->x11_displays = make_resource_list();
  remember_resource(self->super.resources,
		    &self->x11_displays->super);

  self->gateway_connections = make_resource_list();
  remember_resource(self->super.resources,
		    &self->gateway_connections->super);

  return self;
}

/* Handling of SSH_LSH_RANDOM_REQUEST and SSH_LSH_RANDOM_REPLY */

static void
handle_random_reply(struct client_connection *self,
			   uint32_t length, const uint8_t *packet)
{
  if (object_queue_is_empty(&self->pending_random))
    {
      werror("handle_random_reply: Unexpected message. Ignoring.\n");
    }
  else
    {
      CAST_SUBTYPE(client_random_handler, handler,
		   object_queue_remove_head(&self->pending_random));
      if (handler->gateway)
	gateway_write_packet(handler->gateway,
			     ssh_format("%ls", length, packet));
      else
	{
	  struct simple_buffer buffer;

	  uint32_t random_length;
	  const uint8_t *random_data;

	  simple_buffer_init(&buffer, length - 1, packet + 1);

	  if (parse_string(&buffer, &random_length, &random_data)
	      && parse_eod(&buffer))
	    handler->reply(handler, random_length, random_data);
	  else
	    disconnect(self, 0, "Invalid SSH_LSH_RANDOM_REPLY message.");
	}
    }
}

void
client_random_request(struct client_connection *connection,
		      uint32_t length,
		      struct client_random_handler *handler)
{
  write_packet(connection,
	       ssh_format("%c%i",
			  SSH_LSH_RANDOM_REQUEST,
			  length));
  object_queue_add_tail(&connection->pending_random, &handler->super);
}

void
client_gateway_random_request(struct client_connection *connection,
			      uint32_t length, const uint8_t *packet,
			      struct gateway_connection *gateway)
{
  NEW(client_random_handler, handler);
  
  write_packet(connection,
	       ssh_format("%ls", length, packet));
  handler->gateway = gateway;
  handler->reply = NULL;
  
  object_queue_add_tail(&connection->pending_random, &handler->super);
}

#if 0
/* ;; GABA:
   (class
     (name detach_callback)
     (super lsh_callback)
     (vars 
       (channel_flag . int)
       (fd_flag . int)
       (exit_status . "int *")))
*/

/* ;; GABA:
   (class
     (name detach_resource)
     (super resource)
     (vars
       (c object detach_callback)))
*/

static void 
do_detach_res_kill(struct resource *r)
{
  CAST(detach_resource,self,r);

  trace("client.c:do_detach_res\n");
  self->c->channel_flag = 1;

  if (self->c->channel_flag && self->c->fd_flag)
    /* If the fd_flag is set, the callback should be changed */
    io_callout(&self->c->super, 0);
}

static struct resource*
make_detach_resource(struct lsh_callback *c)
{
   NEW(detach_resource, self);
   CAST(detach_callback, cb, c);

   trace("client.c:make_detach_resource\n");
   init_resource(&self->super, do_detach_res_kill);

   self->c = cb;

   return &self->super;
}


static void 
do_detach_cb(struct lsh_callback *c)
{
  CAST(detach_callback,self,c);

  trace("client.c: do_detach_cb\n");
  
  if (!self->fd_flag) /* First time around? */
    {
      self->fd_flag = 1; /* Note */
      
      if (self->channel_flag && self->fd_flag)
	/* If the fd is closed already, ask to be called from the main loop */ 
	io_callout(c, 0);
    }
  else
    {
      int pid = fork();

      /* Ignore any errors, what can we do? */
      
      switch(pid)
	{
	case -1: /* Fork failed, this we can handle by doing nothing */
	  werror("Fork failed, not detaching.\n");
	  break;
	  
	case 0:
	  /* Detach */	  
	  close(STDIN_FILENO); 
	  close(STDOUT_FILENO); 
	  close(STDERR_FILENO); 
	  
	  /* Make sure they aren't used by any file lsh opens */
	  
	  open("/dev/null", O_RDONLY);
	  open("/dev/null", O_RDONLY);
	  open("/dev/null", O_RDONLY);
	  break;
	  
	default:
	  exit(*self->exit_status);
	}
    }
}

static struct lsh_callback* 
make_detach_callback(int *exit_status)
{
   NEW(detach_callback, self);

   self->super.f = do_detach_cb;
   self->exit_status = exit_status;
   self->fd_flag = 0;
   self->channel_flag = 0;

   return &self->super;
}
#endif

/* GABA:
   (class
     (name session_open_action)
     (super client_connection_action)
     (vars
       ; This command can only be executed once,
       ; so we can allocate the session object in advance.
       (channel object ssh_channel)))
*/

static void
do_open_session_action(struct client_connection_action *s,
		       struct ssh_connection *connection)
{
  CAST(session_open_action, self, s);
  
  if (!channel_open_new_type(connection, self->channel,
			     ATOM_LD(ATOM_SESSION), ""))
    {
      werror("Allocating a local channel number for session failed.\n");
      KILL_RESOURCE(&self->channel->super);
    }
}

struct client_connection_action *
make_open_session_action(struct ssh_channel *channel)
{
  if (channel)
    {
      NEW(session_open_action, self);
      self->super.action = do_open_session_action;
      self->channel = channel;

      return &self->super;
    }
  else
    return NULL;
}


/* Block size for stdout and stderr buffers */
#define BLOCK_SIZE 32768

/* Window size for the session channel
 *
 * NOTE: Large windows seem to trig a bug in sshd2. */
#define WINDOW_SIZE 10000


/* NOTE: Some of the original quoting is lost here. */
struct lsh_string *
client_rebuild_command_line(unsigned argc, char **argv)
{
  unsigned length;
  unsigned i;
  unsigned pos;
  struct lsh_string *r;
  unsigned *alengths = alloca(sizeof(unsigned) * argc);
  
  assert (argc);
  length = argc - 1; /* Number of separating spaces. */

  for (i = 0; i<argc; i++)
    {
      alengths[i] = strlen(argv[i]);
      length += alengths[i];
    }

  r = lsh_string_alloc(length);
  lsh_string_write(r, 0, alengths[0], argv[0]);
  pos = alengths[0];
  for (i = 1; i<argc; i++)
    {
      lsh_string_putc(r, pos++, ' ');
      lsh_string_write(r, pos, alengths[i], argv[i]);
      pos += alengths[i];
    }

  assert(pos == length);

  return r;
}

/* A callback that exits the process immediately. */
DEFINE_ESCAPE(exit_callback, "Exit.")
{
  exit(EXIT_SUCCESS);
}

/* A callback that suspends the process. */
DEFINE_ESCAPE(suspend_callback, "Suspend.")
{
  if (kill(getpid(), SIGTSTP) < 0)
    werror("do_suspend: kill failed: %e.\n", errno);
}

DEFINE_ESCAPE(quiet_callback, "Toggle warning messages.")
{
  toggle_quiet();
}

DEFINE_ESCAPE(verbose_callback, "Toggle verbose messages.")
{
  toggle_verbose();
}

DEFINE_ESCAPE(trace_callback, "Toggle trace messages.")
{
  toggle_trace();
}

DEFINE_ESCAPE(debug_callback, "Toggle trace messages.")
{
  toggle_trace();
}

struct escape_info *
make_client_escape(uint8_t escape_char)
{
  struct escape_info *escape = make_escape_info(escape_char);

  /* Bind ^Z to suspend. */
  escape->dispatch[26] = &suspend_callback;
  escape->dispatch['.'] = &exit_callback;

  /* Toggle the verbosity flags */
  escape->dispatch['q'] = &quiet_callback;      
  escape->dispatch['v'] = &verbose_callback;
  escape->dispatch['t'] = &trace_callback;
  escape->dispatch['d'] = &debug_callback;

  return escape;
}

/* Treat environment variables as sources for options */

/* FIXME: Can we obsolete this hack once we have reasonable
   configuration files? */
void
env_parse(const struct argp *argp,
	  const char *value,
	  unsigned flags, 
	  void *input)
{
  if (value)
    {
      char **sim_argv;
      char *entry;

      /* Make a copy we can modify */
      entry = strdup(value);

      if (entry)
	{
	  /* Extra space doesn't hurt */
	  sim_argv = malloc(sizeof(char*) * (strlen(entry)+2));

	  if (sim_argv)
	    {
	      int sim_argc = 1;
	      char *token = strtok(entry, " \n\t");
		  
	      sim_argv[0] = "";

	      while (token) /* For all tokens in variable */
		{
		  sim_argv[sim_argc++] = token;
		  token = strtok( NULL, " \n\t");
		}

	      sim_argv[sim_argc] = NULL;
	
	      argp_parse(argp, sim_argc, sim_argv, flags | ARGP_NO_ERRS | ARGP_NO_EXIT, NULL, input);
	    }
	}
    }
}
