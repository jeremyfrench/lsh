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
struct command_simple spki_add_acl_command;
#define SPKI_ADD_ACL (&spki_add_acl_command.super.super)

struct command_simple spki_return_hostkeys;
#define RETURN_HOSTKEYS (&spki_return_hostkeys.super.super)

struct command_simple spki_add_hostkey_command;
#define SPKI_ADD_HOSTKEY (&spki_add_hostkey_command.super.super)

struct command_simple spki_return_userkeys;
#define RETURN_USERKEYS (&spki_return_userkeys.super.super)

struct command_simple spki_add_userkey_command;
#define SPKI_ADD_USERKEY (&spki_add_userkey_command.super.super)


#include "spki_commands.c.x"

#define SA(x) sexp_a(ATOM_##x)

/* GABA:
   (class
     (name spki_command)
     (super command)
     (vars
       (ctx object spki_context)))
*/

/* Reading of ACL:s
 * ****************/
 
/* Adds an ACL s-expression to an SPKI-context. Returns the context. */
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
           (for_sexp (lambda (e)
	   		;; Delay return until we actually get an exception
			(return_hostkeys (prog1 add e)))
	             (lambda (key)
		       (add (sexp2keypair
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
           (for_sexp (lambda (e)
	   		;; Delay return until we actually get an exception
			(return_userkeys (prog1 ctx e)))
	             (lambda (key)
		       (ctx (sexp2keypair
		               algorithms key)))
		     file)))))
*/

struct command *
make_spki_read_userkeys(struct alist *algorithms)
{
  CAST_SUBTYPE(command, res, spki_read_userkeys(algorithms));
  trace("make_spki_read_userkeys\n");

  return res;
}

COMMAND_SIMPLE(spki_read_userkeys_command)
{
  CAST_SUBTYPE(alist, algorithms, a);
  
  return &make_spki_read_userkeys(algorithms)->super;
}


/* Encryption of private data.
 * For PKCS#5 (version 2) key derivation, we use
 *
 * (password-encrypted LABEL (Xpkcs5v2 hmac-sha1 (salt #...#))
 *                           ("3des-cbc" (iv #...#) (data #...#)))
 *
 * where the X:s will be removed when the format is more stable.
 *
 */

/* GABA:
   (class
     (name spki_password_encrypt)
     (super command)
     (vars
       (label string)
       (method object sexp)
       (algorithm_name . UINT32)
       (algorithm object crypto_algorithm)
       (r object randomness)
       (key string)))
*/

static void
do_spki_encrypt(struct command *s,
		struct lsh_object *a,
		struct command_continuation *c,
		struct exception_handler *e UNUSED)
{
  CAST(spki_password_encrypt, self, s);
  CAST_SUBTYPE(sexp, expr, a);

  struct lsh_string *iv = NULL;
  UINT8 noiv[1] = { 0 };
  
  if (self->algorithm->iv_size)
    {
      iv = lsh_string_alloc(self->algorithm->iv_size);
      RANDOM(self->r, iv->length, iv->data);
    }
  
  COMMAND_RETURN(c,
		 sexp_l(4,
			SA(PASSWORD_ENCRYPTED),
			sexp_s(NULL, lsh_string_dup(self->label)),
			self->method,
			sexp_l(3,
			       sexp_a(self->algorithm_name),
			       sexp_l(2, SA(IV), sexp_s(NULL, iv), -1),
			       sexp_l(2, SA(DATA),
				      sexp_s(NULL, crypt_string_pad
					     (MAKE_ENCRYPT(self->algorithm,
							   self->key->data, iv ? iv->data : noiv),
					      SEXP_FORMAT(expr, SEXP_CANONICAL, 0), 1)),
				      -1),
			       -1),
			-1));
}

/* Consumes the label and password arguments. */
struct command *
make_pkcs5_encrypt(struct randomness *r,
		   struct lsh_string *label,
		   UINT32 prf_name,
		   struct mac_algorithm *prf,
		   UINT32 crypto_name,
		   struct crypto_algorithm *crypto,
		   UINT32 salt_length,
		   struct lsh_string *password,
		   UINT32 iterations)
{
  NEW(spki_password_encrypt, self);

  struct lsh_string *key;
  struct lsh_string *salt;
    
  assert(crypto);
  assert(prf);

  salt = lsh_string_alloc(salt_length);
  RANDOM(r, salt->length, salt->data);
    
  key = lsh_string_alloc(crypto->key_size);

  pkcs5_derive_key(prf,
		   password->length, password->data,
		   salt->length, salt->data,
		   iterations,
		   key->length, key->data);

  lsh_string_free(password);
  
  self->super.call = do_spki_encrypt;
  self->r = r;
  self->label = label;
  self->method = sexp_l(3, SA(XPKCS5V2), sexp_a(prf_name),
			sexp_l(2, SA(SALT), sexp_s(NULL, salt), -1), -1);
  self->algorithm_name = crypto_name;
  self->algorithm = crypto;
  self->key = key;

  return &self->super;
}
