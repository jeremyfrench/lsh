/* lshd-userauth.c
 *
 * Main program for the ssh-userauth service.
 *
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 2005 Niels Möller
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
#include <stdarg.h>
#include <string.h>

#include <unistd.h>
#include <pwd.h>
#include <grp.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "nettle/base16.h"
#include "nettle/macros.h"

#include "charset.h"
#include "crypto.h"
#include "environ.h"
#include "list.h"
#include "lsh_string.h"
#include "format.h"
#include "io.h"
#include "parse.h"
#include "ssh.h"
#include "version.h"
#include "werror.h"
#include "xalloc.h"

#include "lsh_argp.h"

#define HEADER_SIZE 8

static struct lsh_string *
format_userauth_failure(struct int_list *methods,
			int partial)
{
  return ssh_format("%c%A%c", SSH_MSG_USERAUTH_FAILURE, methods, partial);
}

static struct lsh_string *
format_userauth_success(void)
{
  return ssh_format("%c", SSH_MSG_USERAUTH_SUCCESS);
}

static struct lsh_string *
format_userauth_pk_ok(int algorithm,
		      uint32_t key_length, const uint8_t *key)
{
  return ssh_format("%c%a%s", SSH_MSG_USERAUTH_PK_OK, 
		    algorithm, key_length, key);
}

/* We use blocking i/o through out. */
static struct lsh_string *
read_packet(void)
{
  uint8_t header[HEADER_SIZE];
  uint32_t seqno;
  uint32_t length;
  struct lsh_string *packet;
  uint32_t done;

  for (done = 0; done < HEADER_SIZE; )
    {
      int res;
      do
	res = read(STDIN_FILENO, header + done, HEADER_SIZE - done);
      while (res < 0 && errno == EINTR);
      if (res <= 0)
	{
	  if (res == 0)
	    die("read_packet: End of file after %i header octets.\n",
		done);
	  else
	    die("read_packet: read failed after %i header octets: %e\n",
		   done, errno);
	}
      done += res;
    }
  
  seqno = READ_UINT32(header);
  length = READ_UINT32(header + 4);

  if (length > SSH_MAX_PACKET)
    die("lshd-userauth: Too large packet.\n");

  packet = lsh_string_alloc(length);

  for (done = 0; done < length; )
    {
      int res;
      do
	res = lsh_string_read(packet, done, STDIN_FILENO, length - done);
      while (res < 0 && errno == EINTR);
      if (res <= 0)
	{
	  if (res == 0)
	    die("read_packet: End of file after %i data octets.\n",
		done);
	  else
	    die("read_packet: read failed after %i data octets: %e\n",
		done, errno);
	}
      done += res;
    }
  return packet;
}

static void
write_packet(struct lsh_string *packet)
{
  packet = ssh_format("%i%fS", lsh_string_sequence_number(packet), packet);

  if (!write_raw(STDOUT_FILENO, STRING_LD(packet)))
    die("write_packet: write failed: %e\n", errno);

  lsh_string_free(packet);
}

static void
protocol_error(const char *msg) NORETURN;

static void
protocol_error(const char *msg)
{
  write_packet(format_disconnect(SSH_DISCONNECT_PROTOCOL_ERROR,
				 msg, ""));
  die("Protocol error: %z.\n", msg);
}

static void
service_error(const char *msg) NORETURN;

static void
service_error(const char *msg)
{
  write_packet(format_disconnect(SSH_DISCONNECT_SERVICE_NOT_AVAILABLE,
				 msg, ""));
  die("Service not available: %z.\n", msg);
  exit(EXIT_FAILURE);  
}

/* Some or all of these pointers are returned by getpwnam, and hence
   destroyed after the next lookup. Can we trust the libc to never
   call getpwnam and friends behind our back? */
   
struct lshd_user
{
  /* Name, in local charset */
  struct lsh_string *name;
  uid_t uid;
  gid_t gid;
  const char *crypted;
  const char *home;
  const char *shell;
};

static void
lshd_user_init(struct lshd_user *self)
{
  self->name = NULL;
}  

static void
lshd_user_clear(struct lshd_user *self)
{
  lsh_string_free(self->name);
  self->name = NULL;
}

static int
lookup_user(struct lshd_user *user, uint32_t name_length,
	    const uint8_t *name_utf8)
{
  struct passwd *passwd;
  const char *cname;
  uid_t me;

  if (memchr(name_utf8, 0, name_length))
    return 0;

  lshd_user_clear(user);
  user->name = low_utf8_to_local(name_length, name_utf8, utf8_paranoid);

  cname = lsh_get_cstring(user->name);
  
  /* NUL:s should be filtered out during the utf8 conversion. */
  assert(cname);

  passwd = getpwnam(cname);
  if (!passwd)
    return 0;

  user->crypted = passwd->pw_passwd;
  if (!user->crypted || !*user->crypted)
    /* Ignore accounts with empty passwords. */
    return 0;

  user->uid = passwd->pw_uid;
  user->gid = passwd->pw_gid;
  user->shell = passwd->pw_shell;
  user->home = passwd->pw_dir;

  me = getuid();
  if (me)
    {
      const char *home;
      
      /* Not root. We can't login anybody but ourselves. */
      if (user->uid != me)
	return 0;

      /* Override $HOME */
      home = getenv(ENV_HOME);
      if (home)
	user->home = home;

      /* FIXME: Do the same with $SHELL? */
    }
  else
    {
      /* No root login */
      if (!user->uid)
	return 0;

      /* FIXME: Handle the shadow database */
    }

  /* A passwd field of more than one character, which starts with a star,
     indicates a disabled account. */
  if (user->crypted[0] == '*' && user->crypted[1])
    return 0;

  /* FIXME: Is it really appropriate to have a default for the login
     shell? */
  if (!user->shell)
    user->shell = "/bin/sh";
  if (!user->home)
    user->home = "/";

  return 1;
}

#define AUTHORIZATION_DIR "authorized_keys_sha1"

static struct verifier *
get_verifier(struct lshd_user *user, int algorithm,
	     uint32_t key_length, const uint8_t *key)
{
  struct verifier *v;
  struct lsh_string *file;
  const char *s;
  struct stat sbuf;
  
  switch(algorithm)
    {
    case ATOM_SSH_DSS:
      v = make_ssh_dss_verifier(key_length, key);
      break;
    case ATOM_SSH_RSA:
      v = make_ssh_rsa_verifier(key_length, key);
      break;
    default:
      werror("Unknown publickey algorithm %a\n", algorithm);
      return NULL;
    }
  if (!v)
    return NULL;

  /* FIXME: We should have proper spki support */
  file = ssh_format("%lz/.lsh/" AUTHORIZATION_DIR "/%lxfS",
		    user->home,
		    hash_string(&crypto_sha1_algorithm,
				PUBLIC_SPKI_KEY(v, 0),
				1));
  s = lsh_get_cstring(file);
  assert(s);

  /* FIXME: Use seteuid around the stat call. */
  if (stat(s, &sbuf) < 0)
    v = NULL;
  
  lsh_string_free(file);
  return v;
}

/* Returns 1 on success, 0 on failure, and -1 if we have sent an
   USERAUTH_PK_OK reply. */
static int
handle_publickey(struct simple_buffer *buffer,
		 struct lshd_user *user,
		 const struct lsh_string *session_id)
{
  int check_key;
  int algorithm;
  uint32_t key_length;
  const uint8_t *key;
  uint32_t signature_start;
  uint32_t signature_length;
  const uint8_t *signature;
  struct lsh_string *signed_data;
  int res;
  
  struct verifier *v;

  if (! (parse_boolean(buffer, &check_key)
	 && parse_atom(buffer, &algorithm)
	 && parse_string(buffer, &key_length, &key)))
    protocol_error("Invalid USERAUTH_REQUEST \"publickey\"");

  signature_start = buffer->pos;

  if (check_key)
    {
      if (!parse_string(buffer, &signature_length, &signature))
	protocol_error("Invalid USERAUTH_REQUEST \"publickey\"");
    }
  
  if (!parse_eod(buffer))
    protocol_error("Invalid USERAUTH_REQUEST \"publickey\"");

  v = get_verifier(user, algorithm, key_length, key);
  if (!v)
    return 0;

  if (!check_key)
    {
      write_packet(format_userauth_pk_ok(algorithm, key_length, key));
      return -1;
    }

  /* The signature is on the session id, followed by the userauth
     request up to the actual signature. To avoid collisions, the
     length field for the session id is included. */
  signed_data = ssh_format("%S%ls", session_id, 
			   signature_start, buffer->data);

  res = VERIFY(v, algorithm,
	       lsh_string_length(signed_data), lsh_string_data(signed_data),
	       signature_length, signature);
  lsh_string_free(signed_data);
  KILL(v);  

  return res;
}

#define MAX_ATTEMPTS 10

static int
handle_userauth(struct lshd_user *user, const struct lsh_string *session_id)
{
  struct int_list *methods
    = make_int_list(1, ATOM_PUBLICKEY, -1);
  unsigned attempt;
  
  for (attempt = 0; attempt < MAX_ATTEMPTS; attempt++)
    {
      struct lsh_string *packet;
      struct simple_buffer buffer;
      unsigned msg_number;
      uint32_t user_length;
      const uint8_t *user_utf8;
      
      int service;
      int method;
      
      packet = read_packet();
      
      werror("handle_userauth: Received packet.\n");
      simple_buffer_init(&buffer, STRING_LD(packet));

      if (!parse_uint8(&buffer, &msg_number))
	protocol_error("Received empty packet.\n");

      /* All supported methods use a single USERAUTH_REQUEST */
      if (msg_number != SSH_MSG_USERAUTH_REQUEST)
	{
	  write_packet(format_unimplemented(
			 lsh_string_sequence_number(packet)));
	  lsh_string_free(packet);
	  continue;
	}

      if (! (parse_string(&buffer, &user_length, &user_utf8)
	     && parse_atom(&buffer, &service)
	     && parse_atom(&buffer, &method)))
	protocol_error("Invalid USERAUTH_REQUEST message");
      
      if (service != ATOM_SSH_CONNECTION)
	{
	fail:
	  write_packet(format_userauth_failure(methods, 0));
	  lsh_string_free(packet);
	  lshd_user_clear(user);
	  continue;
	}

      if (method != ATOM_PUBLICKEY)
	goto fail;
      
      if (!lookup_user(user, user_length, user_utf8))
	goto fail;

      switch (handle_publickey(&buffer, user, session_id))
	{
	default:
	  fatal("Internal error!\n");
	case 0:
	  goto fail;
	case -1:
	  lsh_string_free(packet);
	  break;
	case 1:
	  write_packet(format_userauth_success());
	  lsh_string_free(packet);
	  return 1;
	}
    }
  return 0;  
}

static const char *
format_env_pair(const char *name, const char *value)
{
  return lsh_get_cstring(ssh_format("%lz=%lz", name, value));
}

/* Change persona, set up new environment, change directory, and exec
   the service process. */
static void
start_service(struct lshd_user *user, char **argv)
{
  /* We need place for SHELL, HOME, USER, LOGNAME, TZ, PATH and a
     terminating NULL */
  
#define ENV_MAX 6

  const char *env[ENV_MAX + 1];
  const char *tz = getenv(ENV_TZ);
  const char *cname = lsh_get_cstring(user->name);
  assert(cname);
  
  env[0] = format_env_pair(ENV_SHELL, user->shell);
  env[1] = format_env_pair(ENV_HOME, user->home);
  env[2] = format_env_pair(ENV_USER, cname);
  env[3] = format_env_pair(ENV_LOGNAME, cname);
  env[4] = ENV_PATH "=/bin:/usr/bin";
  env[5] = tz ? format_env_pair(ENV_TZ, tz) : NULL;
  env[6] = NULL;

  /* To allow for a relative path, even when we cd to $HOME. */
  argv[0] = canonicalize_file_name(argv[0]);
  if (!argv[0])
    {
      werror("start_service: canonicalize_file_name failed: %e\n", errno);
      service_error("Failed to start service process");
    }

  if (user->uid != getuid())
    {
      if (initgroups(cname, user->gid) < 0)
	{
	  werror("start_service: initgroups failed: %e\n", errno);
	  service_error("Failed to start service process");
	}
      if (setgid(user->gid) < 0)
	{
	  werror("start_service: setgid failed: %e\n", errno);
	  service_error("Failed to start service process");
	}

      /* FIXME: On obscure systems, notably UNICOS, it's not enough to
	 change our uid, we must also explicitly lower our
	 privileges. */

      if (setuid(user->uid) < 0)
	{
	  werror("start_service: setuid failed: %e", errno);
	  service_error("Failed to start service process");
	}
    }
  assert(user->uid == getuid());

  if (!user->home)
    goto cd_root;

  if (chdir(user->home) < 0)
    {
      werror("chdir to home directory `%z' failed %e\n", user->home, errno);

    cd_root:
      if (chdir("/") < 0)
	{
	  werror("chdir to `/' failed %e\n", errno);
	  _exit(EXIT_FAILURE);
	}
    }
    
  /* FIXME: We should use the user's login shell.

       $SHELL -c 'argv[0] "$@"' argv[0] argv[1] ...
       
     should work. Or perhaps even

       $SHELL -c '"$0" "$@"' argv[0] argv[1] ...

     Can we require that the login-shell is posix-style?
  */
  execve(argv[0], (char **) argv, (char **) env);

  werror("start_service: exec failed: %e", errno);
}

static struct lsh_string *
decode_hex(const char *hex)
{
  struct base16_decode_ctx ctx;
  struct lsh_string *s;
  unsigned length = strlen(hex);
  unsigned i;
  
  s = lsh_string_alloc(BASE16_DECODE_LENGTH(length));
  
  base16_decode_init(&ctx);
  for (i = 0; *hex; hex++)
    {
      uint8_t octet;
      switch(base16_decode_single(&ctx, &octet, *hex))
	{
	case -1:
	  lsh_string_free(s);
	  return NULL;
	case 0:
	  break;
	case 1:
	  lsh_string_putc(s, i++, octet);
	}
    }
  if (!base16_decode_final(&ctx))
    {
      lsh_string_free(s);
      return NULL;
    }
  lsh_string_trunc(s, i);
  return s;      
}

/* Option parsing */

#define OPT_SESSION_ID 0x200
const char *argp_program_version
= "lshd-userauth (lsh-" VERSION "), secsh protocol version " SERVER_PROTOCOL_VERSION;

const char *argp_program_bug_address = BUG_ADDRESS;

static const struct argp_child
main_argp_children[] =
{
  { &werror_argp, 0, "", 0 },
  { NULL, 0, NULL, 0}
};

static const struct argp_option
main_options[] =
{
  /* Name, key, arg-name, flags, doc, group */
  { "session-id", OPT_SESSION_ID, "Session id", 0,
    "Session id from the transport layer.", 0 },
  { NULL, 0, NULL, 0, NULL, 0 }
};

struct lshd_userauth_options
{
  struct lsh_string *session_id;
};  

static error_t
main_argp_parser(int key, char *arg, struct argp_state *state)
{
  struct lshd_userauth_options *options
    = (struct lshd_userauth_options *) state->input;

  switch(key)
    {
    default:
      return ARGP_ERR_UNKNOWN;
    case ARGP_KEY_INIT:
      options->session_id = NULL;
      state->child_inputs[0] = NULL;
      break;

    case ARGP_KEY_END:
      if (!options->session_id)
	argp_error(state, "Mandatory option --session-id is missing.");
      break;

    case OPT_SESSION_ID:
      options->session_id = decode_hex(arg);
      if (!options->session_id)
	argp_error(state, "Invalid argument for --session-id.");
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

int
main(int argc, char **argv)
{
  struct lshd_user user;
  struct lshd_userauth_options options;

  argp_parse(&main_argp, argc, argv, 0, NULL, &options);
  
  werror("Started userauth service.\n");

  lshd_user_init(&user);

  if (!handle_userauth(&user, options.session_id))
    {
      write_packet(format_disconnect(SSH_DISCONNECT_SERVICE_NOT_AVAILABLE,
				     "Access denied", ""));
      exit(EXIT_FAILURE);      
    }

  {
    char *args[] = { NULL, "-v", "--trace", NULL };
    GET_FILE_ENV(args[0], LSHD_CONNECTION);
    start_service(&user, args);
    
    service_error("Failed to start service process");
  }
}
