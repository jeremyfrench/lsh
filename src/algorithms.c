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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "algorithms.h"

#include "atoms.h"
#include "compress.h"
#include "crypto.h"
#include "publickey_crypto.h"

#include <stdarg.h>

struct alist *many_algorithms(unsigned n, ...)
{
  va_list args;
  
  struct alist *a
    = make_alist(5
#ifdef WITH_CAST
		 +1
#endif
#ifdef WITH_IDEA
		 +1
#endif
#ifdef WITH_ZLIB
		 +1
#endif
		 ,
		 ATOM_ARCFOUR, &crypto_arcfour_algorithm,
		 ATOM_BLOWFISH_CBC, crypto_cbc(make_blowfish()),
		 ATOM_3DES_CBC, crypto_cbc(make_des3()),
#ifdef WITH_CAST
		 ATOM_CAST128_CBC, crypto_cbc(make_cast()),
#endif
#ifdef WITH_IDEA
		 ATOM_IDEA_CBC, crypto_cbc(&idea_algorithm),
#endif
		 ATOM_HMAC_SHA1, make_hmac_algorithm(&sha_algorithm),
		 ATOM_HMAC_MD5, make_hmac_algorithm(&md5_algorithm),
#ifdef WITH_ZLIB
		 ATOM_ZLIB, make_zlib(),
#endif
		 -1);
  va_start(args, n);
  alist_addv(a, n, args);
  va_end(args);
  
  return a;
}

/* This is not really efficient, but it doesn't matter. */
static int strcmp_list(char *name, ...)
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
    
int lookup_crypto(struct alist *algorithms, char *name)
{
  int atom;

  if (!strcmp(name, "none"))
    return ATOM_NONE;
  
  if (strcmp_list(name, "arcfour", NULL))
    atom = ATOM_ARCFOUR;
  else if (strcmp_list(name, "blowfish-cbc", "blowfish", NULL))
    atom = ATOM_BLOWFISH_CBC;
  else if (strcmp_list(name, "3des-cbc", "3des", NULL))
    atom = ATOM_3DES_CBC;
  else if (strcmp_list(name, "idea-cbc", "idea", NULL))
    atom = ATOM_IDEA_CBC;
  else if (strcmp_list(name, "cast128-cbc", "cast", "cast-cbc", "cast128", NULL))
    atom = ATOM_CAST128_CBC;
  else
    return 0;

  /* Is this crypto supported? */
  if (ALIST_GET(algorithms, atom))
    return atom;
  else
    return 0;
}

int lookup_mac(struct alist *algorithms, char *name)
{
  int atom;

  if (!strcmp(name, "none"))
    return ATOM_NONE;
  
  if (strcmp_list(name, "hmac-sha1", "sha", "hmac-sha", "sha1", NULL))
    atom = ATOM_HMAC_SHA1;
  else if (strcmp_list(name, "hmac-md5", "md5", NULL))
    atom = ATOM_HMAC_MD5;
  else
    return 0;
  
  /* Is this mac supported? */
  if (ALIST_GET(algorithms, atom))
	return atom;
  else
    return 0;
}

int lookup_compression(struct alist *algorithms, char *name)
{
  int atom;

  if (!strcmp(name, "none"))
    return ATOM_NONE;
  
  if (strcmp_list(name, "zlib", "z", NULL))
    atom = ATOM_ZLIB;
  else
    return 0;
  
  /* Is this compression algorithm supported? */
  if (ALIST_GET(algorithms, atom))
    return atom;
  else
    return 0;
}


struct int_list *default_crypto_algorithms(void)
{
  return make_int_list(3, ATOM_3DES_CBC, ATOM_BLOWFISH_CBC, ATOM_ARCFOUR, -1);
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
    
