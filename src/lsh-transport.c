/* lsh-transport.c
 *
 * Client program responsible for the transport protocol and
 * user authnetication.
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998, 1999, 2000, 2005, Niels Möller
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

/* GABA:
   (class
     (name transport_options)
     (vars
       (random object randomness)
       (tty object interact)

       (sloppy . int)
       (capture . "const char *")
       (capture_file object abstract_write)
       (known_hosts . "const char *")
       
       (home . "const char *")
       (port . "const char *")
       (target . "const char *")

       (local_user . "char *")
       (user . "char *")
       (identity . "char *")))
*/

struct transport_options *
make_transport_options(void)
{
  NEW(transport_options, self);

  self->home = getenv(HOME);
  if (!self->home)
    {
      werror("No home directory. Please set HOME in the environment.");
      return NULL;
    }
  
  self->random = make_user_random(self->home);
  if (!self->random)
    {
      werror("No randomness generator available.\n");
      return NULL;
    }
  
  self->tty = make_unix_interact();

  self->sloppy = 0;
  self->capture = 0;
  self->capture_file = NULL;
  self->known_hosts = NULL;

  self->port = "22";
  self->target = NULL;

  USER_NAME_FROM_ENV(self->user);
  self->local_user = self->user;
  self->identity = NULL;

  return self;
}

static int
lsh_connect(struct transport_options *)
{
  struct addrinfo hints;
  struct addrinfo *list;
  struct addrinfo *p;
  int err;
  int s = -1;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = PF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  err = getaddrinfo(options->target, options->port, &hints, &list);
  if (err)
    {
      werror("Could not resolv address `%z', port %z: %z\n",
	     options->target, options->port, gai_strerror(err));
      return 0;
    }

  for (p = list; p; p = p->ai_next)
    {
      s = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
      if (s < 0)
	continue;

      if (connect(s, p->ai_addr, p->ai_addrlen) == 0)
	break;

      if (p->ai_next)
	werror("Connection failed, trying next address.\n");
      else
	werror("Connection failed.\n");
      close(s);
      s = -1;
    }
  
  freeaddrinfo(list);

  /* We keep the socket in blocking mode */
  struct transport_connection *connection;
  connection = make_
}

/* Option parsing */

const char *argp_program_version
= "lsh-transport (lsh-" VERSION "), secsh protocol version " SERVER_PROTOCOL_VERSION;

const char *argp_program_bug_address = BUG_ADDRESS;

#define ARG_NOT 0x400

/* Transport options */
#define OPT_SLOPPY 0x202
#define OPT_STRICT 0x203
#define OPT_CAPTURE 0x204
#define OPT_HOST_DB 0x205

/* Userauth options */
#define OPT_USERAUTH 0x210
#define OPT_PUBLICKEY 0x211

/* FIXME: Enable/disable password, kbdinteract, etc */

/* Service options */
#define OPT_SERVICE 0x220

static const struct argp_option
main_options[] =
{
  /* Name, key, arg-name, flags, doc, group */
  /* Connection */
  { "port", 'p', "Port", 0, "Connect to this port.", 0 },

  /* Host authentication */
  { "host-db", OPT_HOST_DB, "Filename", 0, "By default, ~/.lsh/host-acls", 0},
  { "sloppy-host-authentication", OPT_SLOPPY, NULL, 0,
    "Allow untrusted hostkeys.", 0 },
  { "strict-host-authentication", OPT_STRICT, NULL, 0,
    "Never, never, ever trust an unknown hostkey. (default)", 0 },
  { "capture-to", OPT_CAPTURE, "File", 0,
    "When a new hostkey is received, append an ACL expressing trust in the key. "
    "In sloppy mode, the default is ~/.lsh/captured_keys.", 0 },
  
  /* User authentication */
  { "identity", 'i',  "Identity key", 0, "Use this key to authenticate.", 0 },
  { "service" , OPT_SERVICE, "Name", 0, "Service to request. Default is `ssh-connection'.", 0},
  
  { NULL, 0, NULL, 0, NULL, 0 }
};

static error_t
main_argp_parser(int key, char *arg, struct argp_state *state)
{
  CAST(lsh_options, self, state->input);
  
  switch(key)
    {
    default:
      return ARGP_ERR_UNKNOWN;
    case ARGP_KEY_INIT:
      state->child_inputs[0] = NULL;
      break;
      
    case ARGP_KEY_END:
      /* FIXME: Open capture file if appropriate */
      break;
      
    case 'p':
      options->port = arg;
      break;

    case OPT_HOST_DB:
      self->known_hosts = arg;
      break;
      
    case OPT_SLOPPY:
      self->sloppy = 1;
      break;

    case OPT_STRICT:
      self->sloppy = 0;
      break;

    case OPT_CAPTURE:
      self->capture = arg;
      break;

    case 'i':
      self->identity = arg;
      break;

    case OPT_SERVICE:
      self->service = arg;
      break;
    }
  return 0;
}

static const struct argp_child
main_argp_children[] =
{
  { &werror_argp, 0, "", 0 },
  { NULL, 0, NULL, 0}
};

static const struct argp
main_argp =
{ main_options, main_argp_parser,
  "host",
  "Creates a secure shell connection to a remote host\v"
  "Uses secure shell transport and userauth protocols to "
  "talk to the remote host. On success, reads cleartext"
  "ssh messages on stdin writes cleartext messages to stdout.",
  main_argp_children,
  NULL, NULL
};

int
main(int argc, char **argv)
{
  struct transport_options *options;

  options = make_transport_options();
  if (!options)
    return EXIT_FAILURE;
  
  argp_parse(&main_argp, argc, argv, 0, NULL, NULL);

  global_oop_source = io_init();

  if (!lsh_connect(options))
    return EXIT_FAILURE;

  io_run();
  io_final();

  return EXIT_SUCCESS;
}
