/* lshg.c
 *
 * $Id$
 *
 * Connect to a gateway. */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 2000 Niels Möller
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

#include "charset.h"
#include "connection.h"
#include "debug.h"
#include "format.h"
#include "gateway.h"
#include "gateway_commands.h"
#include "interact.h"
#include "io_commands.h"
#include "ssh.h"
#include "version.h"
#include "werror.h"
#include "xalloc.h"

#include <assert.h>
#include <locale.h>

#include "lsh_argp.h"

/* Forward declarations */
struct command_simple options2info;
#define OPTIONS2INFO (&options2info.super.super)

struct command_simple options2actions;
#define OPTIONS2ACTIONS (&options2actions.super.super)

#include "lshg.c.x"

/* GABA:
   (class
     (name lshg_options)
     (vars
       ;; (not . int)
       ;; (port . "char *")
       (tty object interact)
       (remote object address_info)
       ; Command to connect to the gateway
       (gateway object local_info)
       
       (local_user . "char *")
       (user . "char *")

       (actions struct object_queue)))
*/

static struct lshg_options *
make_options(void) 
{
  NEW(lshg_options, self);

  self->remote = NULL;
  self->local_user = self->user = getenv("LOGNAME");
  object_queue_init(&self->actions);

  return self;
}

DEFINE_COMMAND_SIMPLE(options2info, a)
{
  CAST(lshg_options, self, a);
  return &make_gateway_address(self->local_user, self->user,
			       self->remote)->super;
}

DEFINE_COMMAND_SIMPLE(options2actions, a)
{
  CAST(lshg_options, self, a);
  return &queue_to_list(&self->actions)->super.super;
}

/* GABA:
   (expr
     (name make_lshg_connect)
     (params
       (backend object io_backend))
     (expr
       (lambda (options)
         ((progn (options2actions options))
	  (gateway_init
	    (connect_local backend (options2info options)))))))
*/

/* GABA:
   (class
     (name lshg_simple_action)
     (super command)
     (vars
       (msg . "const char *")))
*/

static void
do_lshg_send_debug(struct command *s,
		   struct lsh_object *x,
		   struct command_continuation *c UNUSED,
		   struct exception_handler *e UNUSED)
{
  CAST(lshg_simple_action, self, s);
  CAST(ssh_connection, connection, x);

  send_debug_message(connection->write, self->msg, 1);
}

static struct command *
make_lshg_send_debug(const char *msg)
{
  NEW(lshg_simple_action, self);
  self->msg = msg;
  self->super.call = do_lshg_send_debug;

  return &self->super;
}

static void
do_lshg_send_ignore(struct command *s,
		    struct lsh_object *x,
		    struct command_continuation *c UNUSED,
		    struct exception_handler *e UNUSED)
{
  CAST(lshg_simple_action, self, s);
  CAST(ssh_connection, connection, x);

  C_WRITE(connection, ssh_format("%c%z", SSH_MSG_IGNORE, self->msg));
}

static struct command *
make_lshg_send_ignore(const char *msg)
{
  NEW(lshg_simple_action, self);
  self->msg = msg;
  self->super.call = do_lshg_send_ignore;

  return &self->super;
}


/* Option parsing */

const char *argp_program_version
= "lshg-" VERSION ", secsh protocol version " CLIENT_PROTOCOL_VERSION;

const char *argp_program_bug_address = BUG_ADDRESS;

#define ARG_NOT 0x400

static const struct argp_option
main_options[] =
{
  /* Name, key, arg-name, flags, doc, group */
  { "port", 'p', "Port", 0, "Connect to this port.", 0 },
  { "user", 'l', "User name", 0, "Login as this user.", 0 },
  { NULL, 0, NULL, 0, "Actions:", 0 },
  { "execute", 'E', "command", 0, "Execute a command on the remote machine", 0 },  
  { "shell", 'S', "command", 0, "Spawn a remote shell", 0 },
  { "send-debug", 'D', "Message", 0, "Send a debug message "
    "to the remote machine.", 0 },
  { "send-ignore", 'I', "Message", 0, "Send an ignore message "
    "to the remote machine.", 0 },
  { NULL, 0, NULL, 0, NULL, 0 }
};

static const struct argp_child
main_argp_children[] =
{
  { &werror_argp, 0, "", 0 },
  { NULL, 0, NULL, 0}
};

static struct command *
lshg_add_action(struct lshg_options *self,
		struct command *action)
{
  if (action)
    object_queue_add_tail(&self->actions, &action->super);

  return action;
}

static error_t
main_argp_parser(int key, char *arg, struct argp_state *state)
{
  CAST(lshg_options, self, state->input);
  
  switch(key)
    {
    default:
      return ARGP_ERR_UNKNOWN;
    case ARGP_KEY_INIT:
      state->child_inputs[0] = NULL;
      break;
    case ARGP_KEY_NO_ARGS:
      argp_usage(state);
      break;
    case ARGP_KEY_ARG:
      if (!state->arg_num)
	{
	  self->remote = make_address_info_c(arg, "ssh", 22);
	  assert(self->remote);
	  break;
	}
      else
	/* Let the next case parse it.  */
	return ARGP_ERR_UNKNOWN;
#if 0
    case ARGP_KEY_ARGS:
      /* Handle command line. */
      break;
#endif
    case ARGP_KEY_END:
      if (!self->local_user)
	{
	  argp_error(state, "You have to set LOGNAME in the environment.");
	  break;
	}
      assert(self->user);
      self->gateway = make_gateway_address(self->local_user, self->user,
					   self->remote);

      if (object_queue_is_empty(&self->actions))
	{
	  argp_error(state, "No actions given.");
	    break;
	}
      
      break;
#if 0
    case 'E':
      lshg_add_action(self, lsh_command_session(self, ssh_format("%lz", arg)));
      break;

    case 'S':
      lshg_add_action(self, lsh_shell_session(self));
      break;
#endif
    case 'D':
      lshg_add_action(self, make_lshg_send_debug(arg));
      break;

    case 'I':
      lshg_add_action(self, make_lshg_send_ignore(arg));
      break;
#if 0
    case 'n':
      self->not = !self->not;
      break;
#endif      
    }
  return 0;
}

static const struct argp
main_argp =
{ main_options, main_argp_parser, 
  "host\nhost command",
  "Connects to a remote machine, using a gateway\v"
  "Connects to the remote machine, using a local gateway, previously setup"
  "by running lsh -G.",
  main_argp_children,
  NULL, NULL
};

static void
do_exc_lshg_handler(struct exception_handler *s UNUSED,
		    const struct exception *e)
{
  werror(e->msg);
  exit(EXIT_FAILURE);
}

static struct exception_handler *
make_lshg_exception_handler(struct exception_handler *parent,
			    const char *context)
{
  return make_exception_handler(do_exc_lshg_handler, parent, context);
}

int
main(int argc, char **argv)
{
  struct lshg_options *options;
  struct io_backend *backend = make_io_backend();
  
  /* For filtering messages. Could perhaps also be used when converting
   * strings to and from UTF8. */
  setlocale(LC_CTYPE, "");

  /* FIXME: Choose character set depending on the locale */
  set_local_charset(CHARSET_LATIN1);

  options = make_options();

  argp_parse(&main_argp, argc, argv, ARGP_IN_ORDER, NULL, options);

  {
    CAST_SUBTYPE(command, lshg_connect,
		 make_lshg_connect(backend));

    COMMAND_CALL(lshg_connect, options, &discard_continuation,
		 make_lshg_exception_handler(&default_exception_handler,
					     HANDLER_CONTEXT));
  }

  io_run(backend);
  
  return EXIT_SUCCESS;
}
