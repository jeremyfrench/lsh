/* server_publickey.c
 *
 * Publickey authentication method
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1999 Balázs Scheidler
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

#include "server_userauth.h"
#include "userauth.h"
#include "xalloc.h"
#include "connection.h"
#include "parse.h"
#include "werror.h"
#include "format.h"
#include "charset.h"
#include "ssh.h"
#include "lookup_verifier.h"
#include "publickey_crypto.h"

#include "server_publickey.c.x"

/* GABA:
   (class
     (name userauth_publickey)
     (super userauth)
     (vars
       (verifiers object alist)))
*/

static struct lsh_string *format_userauth_pk_ok(int algorithm, struct lsh_string *keyblob)
{
  return ssh_format("%c%a%S", SSH_MSG_USERAUTH_PK_OK, 
		    algorithm, keyblob);
}

static void
do_authenticate(struct userauth *s,
		struct ssh_connection *connection,
		struct lsh_string *username,
		struct simple_buffer *args,
		struct command_continuation *c,
		struct exception_handler *e)
{
  CAST(userauth_publickey, self, s);
  
  struct lsh_string *keyblob = NULL;
  struct lookup_verifier *lookup;
  struct verifier *v;
  UINT8 *signature_blob;
  UINT32 signature_length;
  UINT32 signature_start = 0;
  UINT32 algorithm;
  int check_key;

  username = utf8_to_local(username, 1, 1);
  if (!username)
    {
      PROTOCOL_ERROR(e, "Invalid utf8 in username.");
      return;
    }

  if (parse_boolean(args, &check_key) &&
      parse_atom(args, &algorithm) &&
      (keyblob = parse_string_copy(args)) &&
      (check_key
       ? ((signature_start = args->pos)
	  , (parse_string(args, &signature_length, &signature_blob))
	  && parse_eod(args))
       : parse_eod(args))) 
    {

      lookup = ALIST_GET(self->verifiers, algorithm);

      if (!lookup) 
	{
	  static const struct exception unsupported_publickey_algorithm
	    = STATIC_EXCEPTION(EXC_USERAUTH,
			       "Unsupported public key algorithm.");
	  
	  lsh_string_free(keyblob); 
	  lsh_string_free(username);
	  verbose("Unknown publickey algorithm\n");
	  EXCEPTION_RAISE(e, &unsupported_publickey_algorithm);
	  return;
	}
      v = LOOKUP_VERIFIER(lookup, algorithm, username, keyblob);

#if DATAFELLOWS_WORKAROUNDS
      if ( v && (algorithm == ATOM_SSH_DSS)
	   && (connection->peer_flags & PEER_SSH_DSS_KLUDGE))
	v = make_dsa_verifier_kludge(v);
#endif

      if (!check_key)
	{
	  lsh_string_free(username);
	  if (v)
	    {
	      struct lsh_string *reply = format_userauth_pk_ok(algorithm, keyblob);
	      lsh_string_free(keyblob);
	      KILL(v);
	      EXCEPTION_RAISE(e, make_userauth_special_exception(reply, NULL));
	      return;
	    }
	  else
	    {
	      static const struct exception unauthorized_key
		= STATIC_EXCEPTION(EXC_USERAUTH,
				   "Unauthorized public key.");
	      
	      lsh_string_free(keyblob);
	      EXCEPTION_RAISE(e, &unauthorized_key);
	      return;
	    }
	}
      else 
	{
	  struct lsh_string *signed_data;

#if DATAFELLOWS_WORKAROUNDS
	  if (connection->peer_flags & PEER_USERAUTH_REQUEST_KLUDGE)
	    {
	      signed_data = ssh_format("%lS%c%S%a%a%c%a%S", 
				       connection->session_id,
				       SSH_MSG_USERAUTH_REQUEST,
				       username, 
				       ATOM_SSH_USERAUTH,
				       ATOM_PUBLICKEY,
				       1,
				       algorithm,
				       keyblob);
	    }
	  else
#endif
	    /* The signature is on the session id, followed by the
	     * userauth request up to the actual signature. To avoid collisions,
	     * the length field for the session id is included. */
	    signed_data = ssh_format("%S%ls", connection->session_id, 
				     signature_start, args->data);

	  lsh_string_free(keyblob); 
	  if (VERIFY(v, signed_data->length, signed_data->data, signature_length, signature_blob))
	    {
	      werror("user %S has authenticated\n", username);
	      /* FIXME: We should have done this lookup already */
	      COMMAND_RETURN(c, lookup_user(username, 0));
	    }
	  else
	    {
              static const struct exception bad_sign
                = STATIC_EXCEPTION(EXC_USERAUTH, "Bad signature in userauth request");
	      
              EXCEPTION_RAISE(e, &bad_sign);
	    }
	  lsh_string_free(username);
	  lsh_string_free(signed_data);
	  return;
	}
    }
  else 
    {
      werror("Badly formatted publickey authentication request\n");
      PROTOCOL_ERROR(e, "Invalid publickey authentication request");
    }
}

struct userauth *make_userauth_publickey(struct alist *verifiers)
{
  NEW(userauth_publickey, self);

  self->super.authenticate = do_authenticate;
  self->verifiers = verifiers;
  return &self->super;
}
