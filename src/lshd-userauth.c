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

#include <pwd.h>
#include <sys/types.h>

#include "nettle/macros.h"

#include "charset.h"
#include "environ.h"
#include "list.h"
#include "lsh_string.h"
#include "format.h"
#include "parse.h"
#include "ssh.h"
#include "werror.h"

#define HEADER_SIZE 8

static void
die(const char *format, ...) NORETURN;

/* FIXME: Should this be moved to werror.c? */
static void
die(const char *format, ...)
{
  va_list args;

  va_start(args, format);  
  werror_vformat(format, args);
  va_end(args);

  exit(EXIT_FAILURE);
}

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
  uint32_t done;
  const uint8_t *data;
  uint32_t length;
  
  packet = ssh_format("%i%fS", lsh_string_sequence_number(packet), packet);

  length = lsh_string_length(packet);
  data = lsh_string_data(packet);

  for (done = 0; done < length; )
    {
      int res;
      do
	res = write(STDOUT_FILENO, data + done, length - done);
      while (res < 0 && errno == EINTR);

      assert (res != 0);
      if (res < 0)
	die("write_packet: write failed: %e\n", errno);

      done += res;      
    }
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

static struct verifier *
get_verifier(struct lshd_user *user, int algorithm,
	     uint32_t key_length, const uint8_t *key)
{
  return NULL;
}

/* Returns 1 on success, 0 on failure, and -1 if we have sent an
   USERAUTH_PK_OK reply. */
static int
handle_publickey(struct simple_buffer *buffer, struct lshd_user *user)
{
  int check_key;
  int algorithm;
  uint32_t key_length;
  const uint8_t *key;
  uint32_t signature_start;
  uint32_t signature_length;
  const uint8_t *signature;
  struct verifier *v;
  
  if (! (parse_boolean(buffer, &check_key)
	 && parse_atom(buffer, &algorithm)
	 && parse_string(buffer, &key_length, &key)))
    protocol_error("Invalid USERAUTH_REQUEST \"publickey\"");
  
  if (check_key)
    {
      signature_start = buffer->pos;
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
  
  /* FIXME: Verify signature. */
  return 0;	
}

#define MAX_ATTEMPTS 10

static int
handle_userauth(struct lshd_user *user)
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

      switch(handle_publickey(&buffer, user))
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

int
main(int argc, char **argv)
{
  struct lshd_user user;
  
  werror("Started userauth service.\n");
  lshd_user_init(&user);

  if (!handle_userauth(&user))
    {
      write_packet(format_disconnect(SSH_DISCONNECT_SERVICE_NOT_AVAILABLE,
				     "Access denied", ""));
      exit(EXIT_FAILURE);      
    }

  /* FIXME: Change persona, set up new environment, and exec
     lshd-connection. */
  
  return EXIT_FAILURE;  
}
