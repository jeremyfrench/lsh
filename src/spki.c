/* spki.c
 *
 * An implementation of SPKI certificate checking
 *
 * $Id$ */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1999 Balazs Scheidler, Niels Möller
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

#include "spki.h"

#include "atoms.h"
#include "crypto.h"
#include "format.h"
#include "parse.h"
#include "publickey_crypto.h"
#include "sexp.h"
#include "werror.h"
#include "xalloc.h"
#include "alist.h"

#include <assert.h>

#include <sys/types.h>
#include <fcntl.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#define GABA_DEFINE
#include "spki.h.x"
#undef GABA_DEFINE

#include "spki.c.x"

#define SA(x) sexp_a(ATOM_##x)

struct exception *
make_spki_exception(UINT32 type, const char *msg, struct sexp *expr)
{
  NEW(spki_exception, self);
  assert(type & EXC_SPKI);

  self->super.type = type;
  self->super.msg = msg;
  self->expr = expr;

  return &self->super;
}

#define SPKI_ERROR(e, msg, expr) \
EXCEPTION_RAISE((e), make_spki_exception(EXC_SPKI_TYPE, (msg), (expr)))

struct sexp *keyblob2spki(struct lsh_string *keyblob)
{
  struct simple_buffer buffer;
  UINT32 kbtype;
  struct sexp *e = NULL;
  
  simple_buffer_init(&buffer, keyblob->length, keyblob->data);

  if (parse_atom(&buffer, &kbtype))
    switch(kbtype)
      {
      case ATOM_SSH_DSS:
	{
	  struct dsa_public dsa;
	  init_dsa_public(&dsa);
      
	  if (parse_dsa_public(&buffer, &dsa))
	    e = sexp_l(2, SA(PUBLIC_KEY),
		       sexp_l(5, SA(DSA),
			      /* FIXME: Should we use unsigned format? */
			      sexp_l(2, SA(P), sexp_un(dsa.p), -1),
			      sexp_l(2, SA(Q), sexp_un(dsa.q), -1),
			      sexp_l(2, SA(G), sexp_un(dsa.g), -1),
			      sexp_l(2, SA(Y), sexp_un(dsa.y), -1),
			      -1),
		       -1);
	  else
	    werror("Invalid dsa keyblob.");
      
	  dsa_public_free(&dsa);
	  break;
	}
      default:
	werror("Unknown keyblob format, only ssh-dss is supported\n");
      }
  else
    werror("Invalid keyblob.\n");

  return e;
}

/* Returns 0 or an atom */
int spki_get_type(struct sexp *e, struct sexp_iterator **res)
{
  struct sexp_iterator *i;
  UINT32 type;
  
  if (sexp_atomp(e) || sexp_nullp(e))
    return 0;

  i = SEXP_ITER(e);

  type = sexp2atom(SEXP_GET(i));
  if (type && res)
    {
      SEXP_NEXT(i);
      *res = i;
    }
  else
    KILL(i);

  return type;
}

/* Returns 1 if the type matches. */
int
spki_check_type(struct sexp *e, int type, struct sexp_iterator **res)
{
  struct sexp_iterator *i =
    sexp_check_type(e, get_atom_length(type), get_atom_name(type));

  if (i)
    {
      if (res)
	*res = i;
      else
	KILL(i);
      return 1;
    }
  return 0;
}

/* NOTE: This function requires a particular order. */
static struct sexp *dsa_private2public(struct sexp_iterator *i)
{
  struct sexp *p;
  struct sexp *q;
  struct sexp *g;
  struct sexp *y;
  struct sexp *x;

  /* FIXME: Check length? */
  if ( (p = sexp_assq(i, ATOM_P))
       && (q = sexp_assq(i, ATOM_Q))
       && (g = sexp_assq(i, ATOM_G))
       && (y = sexp_assq(i, ATOM_Y))
       && (x = sexp_assq(i, ATOM_X)))
    return sexp_l(2, SA(PUBLIC_KEY),
		  sexp_l(5, SA(DSA), p, q, g, y, -1), -1);
  else
    return NULL;
      
}


static void
do_spki_private2public(struct command *s UNUSED,
		       struct lsh_object *a,
		       struct command_continuation *c,
		       struct exception_handler *e)
{
  CAST_SUBTYPE(sexp, key, a);
  struct sexp_iterator *i;
  struct sexp *expr;
  struct sexp *pub;

  if (!spki_check_type(key, ATOM_PRIVATE_KEY, &i))
    {
      SPKI_ERROR(e, "spki.c: Expected private key.", key);
      return;
    }

  expr = SEXP_GET(i);
  KILL(i);
  switch (spki_get_type(expr, &i))
    {
    default:
      SPKI_ERROR(e, "spki.c: Unknown key type (only dsa is supported).", key);
      break;
    case ATOM_DSA:
      {
	pub = dsa_private2public(i);
	if (!pub)
	  {
	    SPKI_ERROR(e, "spki.c: Invalid DSA key.", key);
	  }
	else
	  COMMAND_RETURN(c, pub);	
      }
    }
}

struct command spki_public2private
= STATIC_COMMAND(do_spki_private2public);


/* Create an SPKI hash from an s-expression. */
/* GABA:
   (class
     (name spki_hash)
     (super command)
     (vars
       (name . int)
       (algorithm object hash_algorithm)))
*/

static void do_spki_hash(struct command *s,
			 struct lsh_object *a,
			 struct command_continuation *c,
			 struct exception_handler *e UNUSED)
{
  CAST(spki_hash, self, s);
  CAST_SUBTYPE(sexp, o, a);

  struct lsh_string *canonical = SEXP_FORMAT(o, SEXP_CANONICAL, 0);
  struct hash_instance *hash = MAKE_HASH(self->algorithm);
  struct lsh_string *digest = lsh_string_alloc(hash->hash_size);
  
  HASH_UPDATE(hash, canonical->length, canonical->data);
  HASH_DIGEST(hash, digest->data);

  lsh_string_free(canonical);
  KILL(hash);
  
  COMMAND_RETURN(c, sexp_l(3,
			   sexp_a(ATOM_HASH),
			   sexp_a(self->name),
			   make_sexp_string(NULL, digest),
			   -1));
}

struct command *
make_spki_hash(int name, struct hash_algorithm *algorithm)
{
  NEW(spki_hash, self);
  self->super.call = do_spki_hash;
  self->name = name;
  self->algorithm = algorithm;

  return &self->super;
}

const struct spki_hash spki_hash_md5 =
{ STATIC_COMMAND(do_spki_hash), ATOM_MD5, &md5_algorithm };

const struct spki_hash spki_hash_sha1 =
{ STATIC_COMMAND(do_spki_hash), ATOM_SHA1, &sha1_algorithm };


  
/* Processes an already parsed S-expression, and inserts it into an alist.
 * FIXME: No, it doesn't; it returns the keypair to its continuation. */
/* GABA:
   (class
     (name spki_parse_key)
     (super command)
     (vars
       (random object randomness)))
*/

/* FIXME: Perhaps this function should throw exceptions? */
static struct keypair *
parse_dsa_private_key(struct randomness *random,
		      struct sexp_iterator *i
		      /*, struct exception_handler *e */)
{
  struct dsa_signer *key = make_dsa_spki_signer(i, random);

  if (key)
    {
      /* Test key */
      mpz_t tmp;
      int valid;
      
      mpz_init_set(tmp, key->public.g);
      mpz_powm(tmp, tmp, key->a, key->public.p);
      valid = !mpz_cmp(tmp, key->public.y);
      mpz_clear(tmp);      

      if (valid)
	{
	  struct lsh_string *public
	    = ssh_format("%a%n%n%n%n", ATOM_SSH_DSS,
			 key->public.p, key->public.q,
			 key->public.g, key->public.y);

	  debug("spki.c: parse_dsa_private_key: Using (public) key:\n"
		"  p=%xn\n"
		"  q=%xn\n"
		"  g=%xn\n"
		"  y=%xn\n",
		key->public.p, key->public.q,
		key->public.g, key->public.y);
	  
	  return make_keypair(ATOM_SSH_DSS, public, &key->super);
	}
      else
	werror("spki.c: parse_dsa_private_key: Key doesn't work.");
    }

  return NULL;
}

/* FIXME: Use exceptions here? */
static struct keypair *
parse_private_key(struct randomness *random,
                  struct sexp_iterator *i
		  /* , struct exception_handler *e */)
{
  struct sexp *expr;
  
  expr = SEXP_GET(i);
  switch (spki_get_type(expr, &i)) 
    {
      default:
        /* SPKI_ERROR(e, "spki.c: Unknown key type (only dsa is supported).", expr); */
	werror("spki.c: Unknown key type (only dsa is supported).");
	break;
      case ATOM_DSA:
        return parse_dsa_private_key(random, i /* , e */);
    }
  return NULL;
}

#if 0
static struct keypair *
publickey2keypair(struct sexp_iterator *i,
		  struct exception_handler *e)
{
}
#endif

static void do_spki_parse_key(struct command *s, 
	                      struct lsh_object *a,
			      struct command_continuation *c,
			      struct exception_handler *e)
{
  CAST(spki_parse_key, self, s);
  CAST_SUBTYPE(sexp, key, a);
  
  struct sexp_iterator *i;
  
  switch (spki_get_type(key, &i)) 
    {
      default:
        SPKI_ERROR(e, "Keyfile is not a private nor a public key.", key);
        return;
      case ATOM_PRIVATE_KEY:
	{
	  struct keypair *key = parse_private_key(self->random, i /* , e */);

	  if (key)
	    COMMAND_RETURN(c, key);
	  else
	    SPKI_ERROR(e, "Invalid key.", NULL);
	  
	  break;
	}
#if 0
      case ATOM_PUBLIC_KEY:
        break;
#endif
    } 
}

struct command *
make_spki_parse_key(struct randomness *random)
{
  NEW(spki_parse_key, self);
  
  self->super.call = do_spki_parse_key;
  self->random = random;
  return &self->super;
}

/* GABA:
   (class
     (name handle_key)
     (super command_continuation)
     (vars
       (key simple "struct keypair **")))
*/

static void
do_handle_key(struct command_continuation *c, struct lsh_object *r)
{
  CAST(handle_key, self, c);
  CAST(keypair, key, r);

  *self->key = key;
}

/* FIXME: We should really use some command instead. */
/* NOTE: Reads only the first key from the file. */
struct keypair *
read_spki_key_file(const char *name,
		   struct randomness *r,
		   struct exception_handler *e)
{
  int fd = open(name, O_RDONLY);
  if (fd < 0)
    {
      EXCEPTION_RAISE(e, make_io_exception(EXC_IO_OPEN_READ, NULL, errno, NULL));
    }
  else
    {
      struct keypair *keypair = NULL;
      int res;

      NEW(handle_key, handler);
      handler->super.c = do_handle_key;
      handler->key = &keypair;

      e = make_report_exception_handler(EXC_SEXP, EXC_SEXP, "Reading keyfile: ",
					e, HANDLER_CONTEXT);
					
      res = blocking_read(fd,
			  make_read_sexp(SEXP_TRANSPORT, 0,
					 make_apply(make_spki_parse_key(r), 
					            &handler->super, 
					            e), 
					 e));
      close(fd);
      KILL(handler);

      return keypair;
    }
  return NULL;
}

#if 0

struct signer *
spki_signer(struct sexp *e, struct alist *algorithms, int *t)
{
  struct sexp_iterator *i;
  
  if (spki_check_type(e, ATOM_PRIVATE_KEY, &i))
    {
      struct sexp *key = SEXP_GET(i);
      struct sexp_iterator *inner;
      int type = spki_get_type(key, &inner);
      
      if (type)
	{
	  CAST_SUBTYPE(spki_algorithm, algorithm, ALIST_GET(algorithms, type));

	  if (algorithm)
	    {
	      *t = type;
	      return SPKI_SIGNER(algorithm, i);
	    }
	}
    }
  return NULL;
}

struct verifier *
spki_verifier(struct sexp *e, struct alist *algorithms, int *t)
{
  struct sexp_iterator *i;
  
  if (spki_check_type(e, ATOM_PRIVATE_KEY, &i))
    {
      struct sexp *key = SEXP_GET(i);
      struct sexp_iterator *inner;
      int type = spki_get_type(key, &inner);
      
      if (type)
	{
	  CAST_SUBTYPE(spki_algorithm, algorithm, ALIST_GET(algorithms, type));

	  if (algorithm)
	    {
	      *t = type;
	      return SPKI_VERIFIER(algorithm, i);
	    }
	}
    }
  return NULL;
}

/* ;; GABA:
   (class
     (name spki_dsa)
     (super spki_algorithm)
     (vars
       (random object randomness)))
*/

static int do_spki_dsa_verify(struct verifier *s,
			      UINT32 length,
			      UINT8 *msg,
			      UINT32 signature_length,
			      UINT8 * signature_data)
{
  CAST(dsa_verifier, self, s);
  struct simple_buffer buffer;
  struct sexp *e;
  mpz_t r, s;
  
  simple_buffer_init(&buffer, signature_length, signature_data);

  if ( (e = sexp_parse_canonical(&buffer))
       && parse_eod(buffer) )
    {
    }
}
    
static verifier *
make_spki_dsa_verifier(struct spki_algorithm *s UNUSED,
		       struct sexp_iterator *i)
{
  NEW(dsa_verifier, res);
  init_dsa_public(&res->public);

  if (spki_dsa_init_public_key(&res->public, i))
    {
      res->super.verify = do_spki_dsa_verify;
      return &res->super;
    }
  else
    {
      KILL(res);
      return NULL;
    }
}

static signer *
make_spki_dsa_signer(struct spki_algorithm *s,
		     struct sexp_iterator *i)
{
  NEW(dsa_signer, signer);
  
}
#endif


#if 0
/* Encryption of private data.
 * Uses the format
 *
 * (password-encrypted LABEL sha1 ("3des-cbc" (iv #...#) (data #...#)))
 */
/* ;; GABA:
   (class
     (name spki_password_encrypt)
     (super command)
     (vars
       (label string)
       (hash . UINT32)
       (algorithm . UINT32)
       (iv string)
       (random object randomness)
       (crypto object crypto_instance)))
*/

static void
do_spki_encrypt(struct command *s,
		struct lsh_object *a,
		struct command_continuation *c,
		struct exception_handler *e)
{
  CAST(spki_password_encrypt, self, s);
  CAST_SUBTYPE(sexp, key, a);
  UINT32 pad;
  
  string lsh_string *s = SEXP_FORMAT(key, SEXP_CANONICAL, 0);
  pad = self->crypto->block_size - (s->length % self->crypto->block_size);

  if (pad)
    {
      UINT8 *p;
      s = ssh_format("%lfS%lr", s, pad, &p);
      RANDOM(self->random, pad, p);
    }

  CRYPT(self->crypto, s->length, s->data, s->data);

  COMMAND_RETURN(c,
		 sexp_l(4,
			SA(PASSWORD_ENCRYPTED),
			make_sexp_string(lsh_string_dup(self->label), NULL),
			sexp_a(self->hash),
			sexp_l(3,
			       sexp_a(self->algorithm),
			       make_sexp_string(lsh_string_dup(self->iv), NULL),
			       make_sexp_string(s, NULL),
			       -1),
			-1));
}

#endif
