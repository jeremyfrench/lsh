/* spki_commands.c
 *
 * SPKI interface
 *
 * $Id$ */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1999 Niels Möller
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

#include "spki_commands.h"

#include "atoms.h"
#include "crypto.h"
#include "format.h"
#include "queue.h"
#include "randomness.h"
#include "sexp_commands.h"
#include "werror.h"
#include "xalloc.h"

#include <assert.h>

/* Forward declarations */
struct command spki_add_acl_command;
#define SPKI_ADD_ACL (&spki_add_acl_command.super)

struct command spki_return_hostkeys;
#define RETURN_HOSTKEYS (&spki_return_hostkeys.super)

struct command spki_add_hostkey_command;
#define SPKI_ADD_HOSTKEY (&spki_add_hostkey_command.super)

struct command spki_return_userkeys;
#define RETURN_USERKEYS (&spki_return_userkeys.super)

struct command spki_add_userkey_command;
#define SPKI_ADD_USERKEY (&spki_add_userkey_command.super)


#include "spki_commands.c.x"

#define SA(x) sexp_a(ATOM_##x)

#define SPKI_ERROR(e, msg, expr) \
EXCEPTION_RAISE((e), make_spki_exception(EXC_SPKI_TYPE, (msg), (expr)))


/* Various conversion functions */

DEFINE_COMMAND(spki_signer2verifier)
     (struct command *s UNUSED,
      struct lsh_object *a,
      struct command_continuation *c,
      struct exception_handler *e UNUSED)
{
  CAST_SUBTYPE(signer, private, a);
  COMMAND_RETURN(c, SIGNER_GET_VERIFIER(private));
}

DEFINE_COMMAND(spki_verifier2public)
     (struct command *s UNUSED,
      struct lsh_object *a,
      struct command_continuation *c,
      struct exception_handler *e UNUSED)
{
  CAST_SUBTYPE(verifier, v, a);
  COMMAND_RETURN(c, spki_make_public_key(v));
}


/* Reading keys */

/* FIXME: Ued only by sexp2keypair, move code there? */
static void 
parse_private_key(struct alist *algorithms,
                  struct sexp_iterator *i,
		  struct command_continuation *c,
		  struct exception_handler *e)
{
  struct sexp *expr = SEXP_GET(i);
  int algorithm_name;
  struct signer *s;
  struct verifier *v;
  struct lsh_string *spki_public;
  
  if (!expr)
    {
      werror("parse_private_key: Invalid key.\n");
      SPKI_ERROR(e, "spki.c: Invalid key.", expr); 
      return;
    }

  s = spki_make_signer(algorithms, expr, &algorithm_name);

  if (!s)
    {
      SPKI_ERROR(e, "spki.c: Invalid key.", expr); 
      return;
    }

  v = SIGNER_GET_VERIFIER(s);
  spki_public = sexp_format(spki_make_public_key(SIGNER_GET_VERIFIER(s)),
			    SEXP_CANONICAL, 0);
  
  /* Test key here? */  
  switch (algorithm_name)
    {	  
    case ATOM_DSA:
      COMMAND_RETURN(c, make_keypair(ATOM_SSH_DSS,
				     PUBLIC_KEY(v),
				     s));
      COMMAND_RETURN(c, make_keypair(ATOM_SPKI_SIGN_DSS,
				     spki_public, s));
      break;

    case ATOM_RSA_PKCS1_SHA1:
      COMMAND_RETURN(c, make_keypair(ATOM_SSH_RSA,
				     PUBLIC_KEY(v),
				     s));
      /* Fall through */

    case ATOM_RSA_PKCS1_MD5:
      COMMAND_RETURN(c, make_keypair(ATOM_SPKI_SIGN_RSA,
				     spki_public, s));
      break;
      
    default:
      fatal("Internal error!\n");
#if 0      
      /* Get a corresponding public key. */
      COMMAND_RETURN(c, make_keypair
		     (ATOM_SPKI,
		      sexp_format(spki_make_public_key(SIGNER_GET_VERIFIER(s)),
				  SEXP_CANONICAL, 0),
		      s));
#endif
      
      break;
    }
}


/* (sexp2keypair algorithms sexp) -> one or more keypairs */
DEFINE_COMMAND2(spki_sexp2keypair_command)
     (struct command_2 *s UNUSED,
      struct lsh_object *a1,
      struct lsh_object *a2,
      struct command_continuation *c,
      struct exception_handler *e)
{
  CAST_SUBTYPE(alist, algorithms, a1);
  CAST_SUBTYPE(sexp, key, a2);
  
  struct sexp_iterator *i;
  
  switch (spki_get_type(key, &i)) 
    {
      default:
        SPKI_ERROR(e, "spki.c: Expected private-key expression.", key);
        return;
      case ATOM_PRIVATE_KEY:
	parse_private_key(algorithms, i, c, e);
	break;
    } 
}

/* Reading of ACL:s
 * ****************/

DEFINE_COMMAND(spki_make_context_command)
     (struct command *s UNUSED,
      struct lsh_object *a,
      struct command_continuation *c,
      struct exception_handler *e UNUSED)
{
  CAST_SUBTYPE(alist, algorithms, a);
  trace("spki_make_context_command\n");
  
  COMMAND_RETURN(c, make_spki_context(algorithms));
}


/* Reading of host-keys
 * ********************/

/* GABA:
   (class
     (name spki_read_hostkey_context)
     (super command)
     (vars
       (keys object alist)))
*/

static void
do_spki_add_hostkey(struct command *s,
		    struct lsh_object *a,
		    struct command_continuation *c,
		    struct exception_handler *e UNUSED)
{
  CAST(spki_read_hostkey_context, self, s);
  CAST(keypair, key, a);

  trace("do_spki_add_hostkey\n");
  
  if (ALIST_GET(self->keys, key->type))
    werror("Multiple host keys of type %a.\n", key->type);
  else
    ALIST_SET(self->keys, key->type, &key->super);
    
  COMMAND_RETURN(c, self->keys);
}

/* Ignores its argument */
DEFINE_COMMAND(spki_add_hostkey_command)
     (struct command *s UNUSED,
      struct lsh_object *a UNUSED,
      struct command_continuation *c,
      struct exception_handler *e UNUSED)
{
  NEW(spki_read_hostkey_context, self);

  trace("spki_add_hostkey_command\n");

  self->super.call = do_spki_add_hostkey;
  self->keys = make_alist(0, -1);

  COMMAND_RETURN(c, self);
}     

DEFINE_COMMAND(spki_return_hostkeys)
     (struct command *s UNUSED,
      struct lsh_object *a,
      struct command_continuation *c,
      struct exception_handler *e UNUSED)
{
  CAST(spki_read_hostkey_context, self, a);
  trace("spki_return_hostkeys\n");
  COMMAND_RETURN(c, self->keys);
}

/* GABA:
   (expr
     (name spki_read_hostkeys)
     (params
       (algorithms object alist))
     (expr
       (lambda (file)
         (let ((add (spki_add_hostkey file)))
           (for_sexp (lambda (e)
	   		;; Delay return until we actually get an exception
			(return_hostkeys (prog1 add e)))
	             (lambda (key)
		       (add (sexp2keypair
		               algorithms key)))
		     file)))))
*/

DEFINE_COMMAND(spki_read_hostkeys_command)
     (struct command *s UNUSED,
      struct lsh_object *a,
      struct command_continuation *c,
      struct exception_handler *e UNUSED)
{
  CAST_SUBTYPE(alist, algorithms, a);
  CAST_SUBTYPE(command, res, spki_read_hostkeys(algorithms));

  trace("spki_read_hostkeys_command\n");
  
  COMMAND_RETURN(c, res);
}

/* Reading of private user-keys
 * ****************************/

/* GABA:
   (class
     (name spki_read_userkey_context)
     (super command)
     (vars
       (keys struct object_queue)))
*/

static void
do_spki_add_userkey(struct command *s,
		    struct lsh_object *a,
		    struct command_continuation *c,
		    struct exception_handler *e UNUSED)
{
  CAST(spki_read_userkey_context, self, s);
  CAST(keypair, key, a);

  trace("do_spki_add_userkey\n");
  
  object_queue_add_tail(&self->keys, &key->super);

  COMMAND_RETURN(c, s);
}

/* Ignores its argument */
DEFINE_COMMAND(spki_add_userkey_command)
     (struct command *s UNUSED,
      struct lsh_object *a UNUSED,
      struct command_continuation *c,
      struct exception_handler *e UNUSED)
{
  NEW(spki_read_userkey_context, self);

  trace("spki_add_userkey_command\n");
  self->super.call = do_spki_add_userkey;
  object_queue_init(&self->keys);

  COMMAND_RETURN(c, self);
}     

DEFINE_COMMAND(spki_return_userkeys)
     (struct command *s UNUSED,
      struct lsh_object *a,
      struct command_continuation *c,
      struct exception_handler *e UNUSED)
{
  CAST(spki_read_userkey_context, self, a);
  trace("spki_return_userkeys\n");
  
  COMMAND_RETURN(c,queue_to_list(&self->keys));
}

/* GABA:
   (expr
     (name spki_read_userkeys)
     (params
       (algorithms object alist)
       (decrypt object command))
     (expr
       (lambda (file)
         (let ((ctx (spki_add_userkey file)))
           (for_sexp (lambda (e)
	   		;; Delay return until we actually get an exception
			(return_userkeys (prog1 ctx e)))
	             (lambda (key)
		       (ctx (sexp2keypair
		               algorithms (decrypt key))))
		     file)))))
*/

struct command *
make_spki_read_userkeys(struct alist *algorithms,
			struct alist *signature_algorithms,
			struct interact *tty)
{
  struct command *decrypt;
  trace("make_spki_read_userkeys\n");

  if (tty)
    {
      struct alist *mac = make_alist(0, -1);
      struct alist *crypto = make_alist(0, -1);

      alist_select_l(mac, algorithms,
		     2, ATOM_HMAC_SHA1, ATOM_HMAC_MD5, -1);
      alist_select_l(crypto, algorithms,
		     3, ATOM_3DES_CBC, ATOM_BLOWFISH_CBC,
		     ATOM_RIJNDAEL_CBC_LOCAL, -1);
      decrypt = make_pkcs5_decrypt(mac, crypto, tty);
    }
  else
    decrypt = &command_I;

  {
    CAST_SUBTYPE(command, res,
		 spki_read_userkeys(signature_algorithms,
				    decrypt));

    return res;
  }
}

/* Encryption of private data.
 * For PKCS#5 (version 2) key derivation, we use
 *
 * (password-encrypted LABEL
 *   (Xpkcs5v2 hmac-sha1 (salt #...#)
 *                       (iterations #...#))
 *   ("3des-cbc" (iv #...#) (data #...#)))
 *
 * where the X:s will be removed when the format is more stable.
 *
 */

/* GABA:
   (class
     (name spki_password_decrypt)
     (super command)
     (vars
       (mac_algorithms object alist)
       (crypto_algorithms object alist)
       (tty object interact)))
*/

static void
do_spki_decrypt(struct command *s,
		struct lsh_object *a,
		struct command_continuation *c,
		struct exception_handler *e)
{
  CAST(spki_password_decrypt, self, s);
  CAST_SUBTYPE(sexp, expr, a);

  struct sexp_iterator *i;
  
  if (!(i = sexp_check_type(expr, ATOM_PASSWORD_ENCRYPTED)))
    COMMAND_RETURN(c, expr);

  else
    {
      const struct lsh_string *label;
      struct sexp *key_info;
      struct sexp *payload;

      struct crypto_algorithm *crypto;
      struct mac_algorithm *mac;
      
      const struct lsh_string *salt;
      const struct lsh_string *iv;
      const struct lsh_string *data;
      UINT32 iterations;
      
      if (SEXP_LEFT(i) != 3)
	{
	  SPKI_ERROR(e, "Invalid (password-encrypted ...) expression.",
		     expr);
	  return;
	}
	
      /* NOTE: This is a place where it might make sense to use a sexp
       * display type, but we don't support that for now. */
      label = sexp2string(SEXP_GET(i));

      if (!label)
	{
	  SPKI_ERROR(e, "Invalid label in (password-encrypted ...) expression.",
		     expr);
	  return;
	}

      SEXP_NEXT(i);
      key_info = SEXP_GET(i);
      assert(key_info);

      SEXP_NEXT(i);
      payload = SEXP_GET(i);
      assert(payload);

      /* Examine the payload expression first, before asking for a
       * pass phrase. */

      {
	int algorithm_name = spki_get_type(payload, &i);
	CAST_SUBTYPE(crypto_algorithm, tmp,
		     ALIST_GET(self->crypto_algorithms, algorithm_name));
	crypto = tmp;
      }

      if (!crypto)
	{
	  SPKI_ERROR(e, "Unknown encryption algorithm for pkcs5v2.", payload);
	  return;
	}

      iv = sexp2string(sexp_assq(i, ATOM_IV));

      if (crypto->iv_size)
	{
	  if (!iv || (iv->length != crypto->iv_size))
	    {
	      SPKI_ERROR(e, "Invalid IV for pkcs5v2.", payload);
	      return;
	    }
	}
      else if (iv)
	{
	  if (iv->length)
	    {
	      SPKI_ERROR(e, "Unexpected iv provided for pkcs5v2.", payload);
	      return;
	    }
	  iv = NULL;
	}
	
      data = sexp2string(sexp_assq(i, ATOM_DATA));

      if (!data)
	{
	  SPKI_ERROR(e, "Payload data missing for pkcs5v2.", payload);
	  return;
	}

      if (crypto->block_size && (data->length & crypto->block_size))
	{
	  SPKI_ERROR(e, "Payload data doesn't match block size for pkcs5v2.", payload);
	  return;
	}

      /* Get key */
      switch (spki_get_type(key_info, &i)) 
	{
	default:
	  SPKI_ERROR(e, "Unknown key derivation mechanism.", key_info);
	  return;

	case ATOM_XPKCS5V2:
	  if (SEXP_LEFT(i) != 3)
	    {
	      SPKI_ERROR(e, "Invalid pkcs5v2 parameters.", key_info);
	      return;
	    }
	  
	  {
	    int algorithm_name = sexp2atom(SEXP_GET(i));
	    
	    CAST_SUBTYPE(mac_algorithm, tmp,
			 ALIST_GET(self->mac_algorithms,
				   algorithm_name));

	    mac = tmp;
	  }

	  if (!mac)
	    {
	      SPKI_ERROR(e, "Unknown mac for pkcs5v2.", key_info);
	      return;
	    }

	  SEXP_NEXT(i);
	  if (!sexp2uint32(sexp_assq(i, ATOM_ITERATIONS), &iterations)
	      || !iterations)
	    {
	      SPKI_ERROR(e, "Invalid iteration count for pkcs5v2.", key_info);
	      return;
	    }
	    
	  salt = sexp2string(sexp_assq(i, ATOM_SALT));

	  if (!salt)
	    {
	      SPKI_ERROR(e, "Invalid salt for pkcs5v2.", key_info);
	      return;
	    }

	  /* Do the work */

	  {
	    struct lsh_string *password
	      = INTERACT_READ_PASSWORD(self->tty, 500, label, 0);
	    struct lsh_string *clear;
	    struct sexp *res;
	    UINT8 *key;
	    
	    if (!password)
	      {
		SPKI_ERROR(e, "No password provided for pkcs5v2.", key_info);
		return;
	      }

	    key = alloca(crypto->key_size);
	    pkcs5_derive_key(mac,
			     password->length, password->data,
			     salt->length, salt->data,
			     iterations,
			     crypto->key_size, key);

	    lsh_string_free(password);

	    clear = crypt_string_unpad(MAKE_DECRYPT(crypto,
						    key,
						    iv ? iv->data : NULL),
				       data, 0);

	    if (!clear)
	      {
		SPKI_ERROR(e, "Bad password for pkcs5v2.", key_info);
		return;
	      }

	    res = string_to_sexp(SEXP_CANONICAL, clear, 1);

	    if (res)
	      COMMAND_RETURN(c, res);
	    else
	      {
		SPKI_ERROR(e, "Bad password for pkcs5v2.", key_info);
		return;
	      }
	  }
	}
    }
}

struct command *
make_pkcs5_decrypt(struct alist *mac_algorithms,
		   struct alist *crypto_algorithms,
		   struct interact *tty)
{
  NEW(spki_password_decrypt, self);
  self->super.call = do_spki_decrypt;
  self->mac_algorithms = mac_algorithms;
  self->crypto_algorithms = crypto_algorithms;
  self->tty = tty;

  return &self->super;
}
