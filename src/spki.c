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
#include "format.h"
#include "parse.h"
#include "publickey_crypto.h"
#include "sexp.h"
#include "werror.h"
#include "xalloc.h"

#include <assert.h>

#define GABA_DEFINE
#include "spki.h.x"
#undef GABA_DEFINE

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
UINT32 spki_get_type(struct sexp *e, struct sexp_iterator **res)
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
int spki_check_type(struct sexp *e, UINT32 type, struct sexp_iterator **res)
{
  struct sexp_iterator *i;
  struct lsh_string *tag;
  
  if (sexp_atomp(e) || sexp_nullp(e))
    return 0;

  i = SEXP_ITER(e);

  tag = sexp2string(SEXP_GET(i));

  if (tag && (!lsh_string_cmp_l(tag, get_atom_length(type), get_atom_name(type))))
    {
      SEXP_NEXT(i);
      *res = i;
      return 1;
    }
  else
    {
      KILL(i);
      return 0;
    }
}

/* NOTE: This function requires a particular order. */
static struct sexp *dsa_private2public(struct sexp_iterator *i)
{
  struct sexp *p;
  struct sexp *q;
  struct sexp *g;
  struct sexp *y;
  struct sexp *x;
  
  p = SEXP_GET(i);

  /* FIXME: Rewrite to use spki_get_type() */
  
  if (!(p && sexp_check_type(p, "p", NULL)))
    return NULL;

  SEXP_NEXT(i); q = SEXP_GET(i);
  
  if (!(q && sexp_check_type(q, "q", NULL)))
    return NULL;

  SEXP_NEXT(i); g = SEXP_GET(i);
  
  if (!(g && sexp_check_type(g, "g", NULL)))
    return NULL;

  SEXP_NEXT(i); y = SEXP_GET(i);
  
  if (!(y && sexp_check_type(y, "y", NULL)))
    return NULL;

  SEXP_NEXT(i); x = SEXP_GET(i);
  
  if (!(x && sexp_check_type(x, "x", NULL)))
    return NULL;

  SEXP_NEXT(i);
  if (SEXP_GET(i))
    return NULL;

  return sexp_l(2, SA(PUBLIC_KEY),
		sexp_l(5, SA(DSA), p, q, g, y, -1), -1);
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
