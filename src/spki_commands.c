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

#include "sexp_commands.h"
#include "werror.h"
#include "xalloc.h"

/* Forward declarations */
struct command_simple spki_add_acl_command;
#define SPKI_ADD_ACL (&spki_add_acl_command.super.super)

struct command_simple spki_return_hostkeys;
#define RETURN_HOSTKEYS (&spki_return_hostkeys.super.super)

struct command_simple spki_add_hostkey_command;
#define SPKI_ADD_HOSTKEY (&spki_add_hostkey_command.super.super)

struct command_simple spki_add_userkey_command;
#define SPKI_ADD_USERKEY (&spki_add_userkey_command.super.super)

#include "spki_commands.c.x"


/* GABA:
   (class
     (name spki_command)
     (super command)
     (vars
       (ctx object spki_context)))
*/

/* Reading of ACL:s
 * ****************/
 
/* Adds an ACL s-expression to an SPIK-context. Returns the context. */
/* ;; GABA:
   (class
     (name spki_add_acl_command_1)
     (super command)
     (vars
       (ctx object spki_context)))
*/

static void
do_spki_add_acl(struct command *s,
		struct lsh_object *a,
		struct command_continuation *c,
		struct exception_handler *e UNUSED)
{
  CAST(spki_command, self, s);
  CAST_SUBTYPE(sexp, expr, a);

  trace("do_spki_add_acl\n");
  spki_add_acl(self->ctx, expr);

  COMMAND_RETURN(c, self->ctx);
}

COMMAND_SIMPLE(spki_add_acl_command)
{
  CAST_SUBTYPE(spki_context, ctx, a);

  NEW(spki_command, self);
  self->super.call = do_spki_add_acl;
  self->ctx = ctx;

  trace("spki_add_acl_command\n");

  return &self->super.super;
}

COMMAND_SIMPLE(spki_make_context_command)
{
  CAST_SUBTYPE(alist, algorithms, a);
  trace("spki_make_context_command\n");
  
  return &make_spki_context(algorithms)->super;
}


/* Reads a file of ACL:s, and returns an spki_context. */

/* GABA:
   (expr
     (name spki_read_acl)
     (params
       (algorithms object alist))
     (expr
       (lambda (file)
         (let ((ctx (spki_make_context
	              ;; Delay call, so that we really
		      ;; create one context for each file.
	              (prog1 algorithms file))))
	   (for_sexp
	     (lambda (e) ctx) ; Return ctx
  	     ;; Keep on reading until an SEXP_EOF or
	     ;; SEXP_SYNTAX exception is raised. 
	     (spki_add_acl ctx)
	     file)))))
*/

struct command *
make_spki_read_acls(struct alist *algorithms)
{
  CAST_SUBTYPE(command, res, spki_read_acl(algorithms));

  trace("make_spki_read_acl()\n");
  return res;
}

COMMAND_SIMPLE(spki_read_acls_command)
{
  CAST_SUBTYPE(alist, algorithms, a);
  CAST_SUBTYPE(command, res, spki_read_acl(algorithms));

  return &res->super;
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
    ALIST_SET(self->keys, key->type, key);

  COMMAND_RETURN(c, self->keys);
}

/* Ignores its argument */
COMMAND_SIMPLE(spki_add_hostkey_command)
{
  NEW(spki_read_hostkey_context, self);

  trace("spki_add_hostkey_command\n");

  (void) a;
  
  self->super.call = do_spki_add_hostkey;
  self->keys = make_alist(0, -1);

  return &self->super.super;
}     

COMMAND_SIMPLE(spki_return_hostkeys)
{
  CAST(spki_read_hostkey_context, self, a);
  trace("spki_return_hostkeys\n");
  return &self->keys->super;
}

/* GABA:
   (expr
     (name spki_read_hostkeys)
     (params
       (algorithms object alist))
     (expr
       (lambda (file)
         (let ((add (spki_add_hostkey file)))
           (for_sexp (lambda (e) (return_hostkeys add))
	             (lambda (key)
		       (add (spki_parse_private_key
		               algorithms key)))
		     file)))))
*/

COMMAND_SIMPLE(spki_read_hostkeys_command)
{
  CAST_SUBTYPE(alist, algorithms, a);
  CAST_SUBTYPE(command, res, spki_read_hostkeys(algorithms));

  trace("spki_read_hostkeys_command\n");
  
  return &res->super;
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
COMMAND_SIMPLE(spki_add_userkey_command)
{
  NEW(spki_read_userkey_context, self);
  (void) a;

  trace("spki_add_userkey_command\n");
  self->super.call = do_spki_add_userkey;
  object_queue_init(&self->keys);

  return &self->super.super;
}     

COMMAND_SIMPLE(spki_return_userkeys)
{
  CAST(spki_read_userkey_context, self, a);
  trace("spki_return_userkeys\n");
  
  return &queue_to_list(&self->keys)->super.super;
}

/* GABA:
   (expr
     (name spki_read_userkeys)
     (params
       (algorithms object alist))
     (expr
       (lambda (file)
         (let ((ctx (spki_add_userkey file)))
           (for_sexp (lambda (e) (return_hostkeys ctx))
	             (lambda (key)
		       (ctx (spki_parse_private_key
		               algorithms key)))
		     file)))))
*/

COMMAND_SIMPLE(spki_read_userkeys_command)
{
  CAST_SUBTYPE(alist, algorithms, a);
  CAST_SUBTYPE(command, res, spki_read_userkeys(algorithms));

  trace("spki_read_userkeys_command\n");
  
  return &res->super;
}

#if 0
/* This class keeps track of the keypairs we have read, and it also
 * works as the exception handler for catching sexp-exceptions. */

/* ;;GABA:
   (class
     (name user_key_context)
     (super command)
     (vars
       (algorithms object alist)
       (keys struct object_queue)))
*/

static void do_user_key_context(struct command *s,
				struct lsh_object *a,
				struct command_continuation *c,
				struct exception_handler *e)
{
  CAST(user_key_context, self, s);
  CAST_SUBTYPE(exception, exc, a);

  switch(exc->type)
    {
    case SEXP_EOF:
      COMMAND_RETURN(c, queue_to_list(&self->keys));
      break;
    default:
      EXCEPTION_RAISE(e, exc);
      break;
    }
}

static void user_key_context_add(struct user_key_context *ctx, struct keypair *key)
{
  object_queue_add_tail(&ctx->keys, &key->super);
  
COMMAND_SIMPLE(make_user_key_context)
{
  CAST_SUBTYPE(alist, algorithms, a);

  NEW(user_key_context, self);
  self->super.call = do_user_key_context;
  self->algorithms = algorithms;
  object_queue_init(&self->keys);

  return &self->super.super;
}
 
/* ;; GABA:
   (expr
     (name spki_read_private_keys)
     (params
       (algorithms object alist)
       (add_key))
     (expr
       (lambda (file)
         (catch_sexp ctx (add_key ctx (spki_parse_private_key (read_sexp file)))))))
*/

 
/* ;; GABA:
   (class
     (name add_user_key)
     (command 
*/
#endif
