/* algorithms.c
 *
 * Translate algorithm identifiers (or names) to algorithm objects.
 *
 * $Id$ */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998 Niels Möller
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

#include "algorithms.h"

#include "atoms.h"
#include "compress.h"
#include "crypto.h"
#include "publickey_crypto.h"
#include "xalloc.h"

#include "lsh_argp.h"

#include <assert.h>
#include <stdarg.h>

#define GABA_DEFINE
#include "algorithms.h.x"
#undef GABA_DEFINE

struct alist *
many_algorithms(unsigned n, ...)
{
  va_list args;
  
  struct alist *a
    = make_alist(9
#if WITH_IDEA
		 +1
#endif
#if WITH_ZLIB
		 +1
#endif
		 ,
		 ATOM_ARCFOUR, &crypto_arcfour_algorithm,
		 ATOM_BLOWFISH_CBC, crypto_cbc(make_blowfish()),
		 ATOM_TWOFISH_CBC, crypto_cbc(make_twofish()),
		 ATOM_RIJNDAEL_CBC, crypto_cbc(make_rijndael()),
		 ATOM_SERPENT_CBC, crypto_cbc(make_serpent()),
		 ATOM_3DES_CBC, crypto_cbc(make_des3()),
		 ATOM_CAST128_CBC, crypto_cbc(make_cast()),
#if WITH_IDEA
		 ATOM_IDEA_CBC, crypto_cbc(&idea_algorithm),
#endif
		 ATOM_HMAC_SHA1, make_hmac_algorithm(&sha1_algorithm),
		 ATOM_HMAC_MD5, make_hmac_algorithm(&md5_algorithm),
#if WITH_ZLIB
		 ATOM_ZLIB, make_zlib(),
#endif
		 -1);
  va_start(args, n);
  alist_addv(a, n, args);
  va_end(args);
  
  return a;
}

/* This is not really efficient, but it doesn't matter. */
static int strcmp_list(const char *name, ...)
{
  va_list args;
  char *s;
  int res = 0;
  
  va_start(args, name);
  while ( (s = va_arg(args, char *)) )
    {
      if (!strcmp(name, s))
	{
	  res = 1;
	  break;
	}
    }
  va_end(args);

  return res;
}
    
int
lookup_crypto(struct alist *algorithms, const char *name,
	      struct crypto_algorithm **ap)
{
  int atom;

  if (!strcmp(name, "none"))
    {
      if (ap)
	*ap = NULL;

      return ATOM_NONE;
    }
  
  if (strcmp_list(name, "arcfour", NULL))
    atom = ATOM_ARCFOUR;
  else if (strcmp_list(name, "twofish-cbc", "twofish", NULL))
    atom = ATOM_TWOFISH_CBC;
  else if (strcmp_list(name, "blowfish-cbc", "blowfish", NULL))
    atom = ATOM_BLOWFISH_CBC;
  else if (strcmp_list(name, "3des-cbc", "3des", NULL))
    atom = ATOM_3DES_CBC;
  else if (strcmp_list(name, "rijndael-cbc", "rijndael", NULL))
    atom = ATOM_RIJNDAEL_CBC;
  else if (strcmp_list(name, "serpent-cbc", "serpent", NULL))
    atom = ATOM_SERPENT_CBC;
  else if (strcmp_list(name, "idea-cbc", "idea", NULL))
    atom = ATOM_IDEA_CBC;
  else if (strcmp_list(name, "cast128-cbc", "cast",
		       "cast-cbc", "cast128", NULL))
    atom = ATOM_CAST128_CBC;
  else
    return 0;

  /* Is this crypto supported? */
  {
    CAST_SUBTYPE(crypto_algorithm, a, ALIST_GET(algorithms, atom));
    if (a)
      {
	if (ap)
	  *ap = a;
	
	return atom;
      }
    else
      return 0;
  }
}

int
lookup_mac(struct alist *algorithms, const char *name,
	   struct mac_algorithm **ap)
{
  int atom;

  if (!strcmp(name, "none"))
    {
      if (ap)
	*ap = NULL;

      return ATOM_NONE;
    }
  if (strcmp_list(name, "hmac-sha1", "sha", "hmac-sha", "sha1", NULL))
    atom = ATOM_HMAC_SHA1;
  else if (strcmp_list(name, "hmac-md5", "md5", NULL))
    atom = ATOM_HMAC_MD5;
  else
    return 0;
  
  /* Is this mac supported? */
  {
    CAST_SUBTYPE(mac_algorithm, a, ALIST_GET(algorithms, atom));
    if (a)
      {
	if (ap)
	  *ap = a;
	
	return atom;
      }
    else
      return 0;
  }
}

int
lookup_compression(struct alist *algorithms, const char *name,
		   struct compress_algorithm **ap)
{
  int atom;

  if (!strcmp(name, "none"))
    {
      if (ap)
	*ap = NULL;
      return ATOM_NONE;
    }
  if (strcmp_list(name, "zlib", "z", NULL))
    atom = ATOM_ZLIB;
  else
    return 0;
  
  /* Is this compression algorithm supported? */
  {
    CAST_SUBTYPE(compress_algorithm, a, ALIST_GET(algorithms, atom));
    if (a)
      {
	if (ap)
	  *ap = a;
	return atom;
      }
    else
      return 0;
  }
}

int
lookup_hash(struct alist *algorithms, const char *name,
	    struct hash_algorithm **ap, int none_is_valid)
{
  int atom;

  if (none_is_valid && !strcmp(name, "none"))
    {
      if (ap)
	*ap = NULL;
      
      return ATOM_NONE;
    }
  if (strcmp_list(name, "md5", NULL))
    atom = ATOM_MD5;
  else if (strcmp_list(name, "sha1", NULL))
    atom = ATOM_SHA1;
  else
    return 0;

  /* Is this hash algorithm supported? */
  {
    CAST_SUBTYPE(hash_algorithm, a, ALIST_GET(algorithms, atom));
    if (a)
      {
	if (ap)
	  *ap = a;
	
	return atom;
      }
    else
      return 0;
  }
}

struct int_list *default_crypto_algorithms(void)
{
  return make_int_list(7
#if WITH_IDEA
		       + 1
#endif
		       , ATOM_3DES_CBC,
#if WITH_IDEA
		       ATOM_IDEA_CBC,
#endif
		       ATOM_BLOWFISH_CBC,
		       ATOM_CAST128_CBC,
		       ATOM_RIJNDAEL_CBC,
		       ATOM_SERPENT_CBC,
		       ATOM_TWOFISH_CBC, ATOM_ARCFOUR, -1);
}

struct int_list *default_mac_algorithms(void)
{
  return make_int_list(2, ATOM_HMAC_SHA1, ATOM_HMAC_MD5, -1);
}

struct int_list *default_compression_algorithms(void)
{
#if WITH_ZLIB
  return make_int_list(2, ATOM_NONE, ATOM_ZLIB, -1);
#else /* !WITH_ZLIB */
  return make_int_list(1, ATOM_NONE, -1);
#endif
}

struct int_list *prefer_compression_algorithms(void)
{
#if WITH_ZLIB
  return make_int_list(2, ATOM_ZLIB, ATOM_NONE, -1);
#else /* !WITH_ZLIB */
  return make_int_list(1, ATOM_NONE, -1);
#endif
}
  
void
vlist_algorithms(const struct argp_state *state,
		 struct alist *algorithms,
		 unsigned n,
		 va_list args)
{
  unsigned i;
  int atom;
  int separate = 0;

  for (i = 0; i<n; i++)
    {
      atom = va_arg(args, int);
      assert(atom > 0);
      
      if ( (atom == ATOM_NONE) || ALIST_GET(algorithms, atom))
	{
	  fprintf(state->out_stream, "%s%s",
		  (separate ? ", " : ""),
		  /* NOTE: This is the only place where we use that
		   * atom names are NUL-terminated. */
		  get_atom_name(atom));
	  separate = 1;
	}
    }
  putc('\n', state->out_stream);
  atom = va_arg(args, int);
  assert(atom == -1);
}

void
list_algorithms(const struct argp_state *state,
		struct alist *algorithms,
		char *prefix,
		unsigned n, ...)
{
  va_list args;
  
  fprintf(state->out_stream, "%s", prefix);
  
  va_start(args, n);
  vlist_algorithms(state, algorithms, n, args);
  va_end(args);
}

void
list_crypto_algorithms(const struct argp_state *state,
		       struct alist *algorithms)
{
  list_algorithms(state, algorithms,
		  "Supported crypto algorithms: ", 9,
		  ATOM_3DES_CBC, ATOM_BLOWFISH_CBC,
		  ATOM_TWOFISH_CBC, ATOM_RIJNDAEL_CBC, ATOM_SERPENT_CBC,
		  ATOM_ARCFOUR,
		  ATOM_IDEA_CBC, ATOM_CAST128_CBC,
		  ATOM_NONE, -1);
}

void
list_mac_algorithms(const struct argp_state *state,
		    struct alist *algorithms)
{
  list_algorithms(state, algorithms,
		  "Supported crypto algorithms: ", 5,
		  ATOM_HMAC_SHA1, ATOM_HMAC_SHA_96,
		  ATOM_HMAC_MD5, ATOM_HMAC_MD5_96,
		  ATOM_NONE, -1);
}

void
list_compression_algorithms(const struct argp_state *state,
			    struct alist *algorithms)
{
  list_algorithms(state, algorithms,
		  "Supported MAC algorithms: ", 2,
		  ATOM_ZLIB, ATOM_NONE, -1);
}


#define OPT_LIST_ALGORITHMS 0x100

static const struct argp_option
algorithms_options[] =
{
  /* Name, key, arg-name, flags, doc, group */
  { NULL, 0, NULL, 0, "Algorithm selection:", 0},
  { "crypto", 'c', "Algorithm", 0, "", 0 },
  { "compression", 'z', "Algorithm",
    OPTION_ARG_OPTIONAL, "Default is zlib.", 0 },
  { "mac", 'm', "Algorithm", 0, "", 0 },
  { "list-algorithms", OPT_LIST_ALGORITHMS, NULL, 0,
    "List supported algorithms.", 0 },
  { NULL, 0, NULL, 0, NULL, 0 }  
};

void
init_algorithms_options(struct algorithms_options *self,
			struct alist *algorithms)
{
  self->algorithms = algorithms;

  self->crypto_algorithms = NULL;
  self->mac_algorithms = NULL;
  self->compression_algorithms = NULL;
}

static error_t
algorithms_argp_parser(int key, char *arg, struct argp_state *state)
{
  CAST_SUBTYPE(algorithms_options, self, state->input);
  
  switch(key)
    {
    default:
      return ARGP_ERR_UNKNOWN;
    case ARGP_KEY_END:
      if (!self->crypto_algorithms)
	self->crypto_algorithms = default_crypto_algorithms();
      if (!self->mac_algorithms)
	self->mac_algorithms = default_mac_algorithms();
      if (!self->compression_algorithms)
	self->compression_algorithms = default_compression_algorithms();
      break;
    case 'c':
      {
	int crypto = lookup_crypto(self->algorithms, arg, NULL);
	if (crypto)
	  self->crypto_algorithms = make_int_list(1, crypto, -1);
	else
	  {
	    list_crypto_algorithms(state, self->algorithms);
	    argp_error(state, "Unknown crypto algorithm '%s'.", arg);
	  }
	break;
      }
    case 'm':
      {
	int mac = lookup_mac(self->algorithms, arg, NULL);
	if (mac)
	  self->mac_algorithms = make_int_list(1, mac, -1);
	else
	  {
	    list_mac_algorithms(state, self->algorithms);
	    argp_error(state, "Unknown message authentication algorithm '%s'.", arg);
	  }	
	break;
      }
    case 'z':
      {
	int compression;
	if (!arg)
	  self->compression_algorithms = prefer_compression_algorithms();
	else
	  {
	    compression = lookup_compression(self->algorithms, arg, NULL);
	    if (compression)
	      self->compression_algorithms = make_int_list(1, compression, -1);
	    else
	      {
		list_compression_algorithms(state, self->algorithms);
		argp_error(state, "Unknown compression algorithm '%s'.", arg);
	      }
	  }
	break;
      }
    case OPT_LIST_ALGORITHMS:
      list_crypto_algorithms(state, self->algorithms);
      list_compression_algorithms(state, self->algorithms);
      list_mac_algorithms(state, self->algorithms);

      if (! (state->flags & ARGP_NO_EXIT))
	exit (0);
    }
  return 0;
}

const struct argp algorithms_argp =
{
  algorithms_options,
  algorithms_argp_parser,
  NULL, NULL, NULL, NULL, NULL
};
