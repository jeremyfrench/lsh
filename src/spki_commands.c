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
#warning spki_commands.h is obsolete

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



#define SA(x) sexp_a(ATOM_##x)

#define SPKI_ERROR(e, msg, expr) \
EXCEPTION_RAISE((e), make_spki_exception(EXC_SPKI_TYPE, (msg), (expr)))

#if 0
/* Reading keys */

/* FIXME: Used only by sexp2keypair, move code there? */
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
#endif

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
#if 0
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

/* ;;GABA:
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
#endif

