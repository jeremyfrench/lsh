/* abstract_crypto.c
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

#include "abstract_crypto.h"

#include "crypto.h"
#include "format.h"
#include "werror.h"
#include "xalloc.h"

#include <assert.h>
#include <string.h>

#define GABA_DEFINE
#include "abstract_crypto.h.x"
#undef GABA_DEFINE


struct lsh_string *
hash_string(struct hash_algorithm *a,
	    struct lsh_string *in,
	    int free)
{
  struct hash_instance *hash = MAKE_HASH(a);
  struct lsh_string *out = lsh_string_alloc(hash->hash_size);

  HASH_UPDATE(hash, in->length, in->data);
  HASH_DIGEST(hash, out->data);

  KILL(hash);
  if (free)
    lsh_string_free(in);

  return out;
}

struct lsh_string *
mac_string(struct mac_algorithm *a,
	   struct lsh_string *key,
	   int kfree,
	   struct lsh_string *in,
	   int ifree)
{
  struct mac_instance *mac = MAKE_MAC(a, key->length, key->data);
  struct lsh_string *out = lsh_string_alloc(mac->mac_size);

  HASH_UPDATE(mac, in->length, in->data);
  HASH_DIGEST(mac, out->data);

  KILL(mac);
  
  if (kfree)
    lsh_string_free(key);
  if (ifree)
    lsh_string_free(in);

  return out;
}

struct lsh_string *
crypt_string(struct crypto_instance *c,
	     const struct lsh_string *in,
	     int free)
{
  struct lsh_string *out;

  if (free)
    {
      /* Do the encryption in place. The type cast is permissible
       * because we're conceptually freeing the string and reusing the
       * storage. */
      out = (struct lsh_string *) in;
    }
  else
    /* Allocate fresh storage. */
    out = lsh_string_alloc(in->length);
  
  CRYPT(c, in->length, in->data, out->data);
  
  return out;
}

/* FIXME: Missing testcases. This is only used for encrypted private
 * keys */
struct lsh_string *
crypt_string_pad(struct crypto_instance *c,
		 const struct lsh_string *in,
		 int free)
{
  struct lsh_string *s;
  UINT8 *p;
  UINT32 pad = c->block_size - (in->length % c->block_size);
  
  assert(pad);
  
  s = ssh_format(free ? "%lfS%lr" : "%lS%lr", in, pad, &p);
  /* Use RFC 1423 and "generalized RFC 1423" as described in
   * PKCS#5 version 2. */
  memset(p, pad, pad);

  return crypt_string(c, s, 1);
}

struct lsh_string *
crypt_string_unpad(struct crypto_instance *c,
		   const struct lsh_string *in,
		   int free)
{
  struct lsh_string *out;
  UINT32 pad;
  
  assert(in->length);
  
  out = crypt_string(c, in, free);
  pad = out->data[out->length - 1];

  if ( (pad > 0) && (pad <= c->block_size) )
    {
      out->length -= pad;
      return out;
    }
  else
    {
      lsh_string_free(out);
      return NULL;
    }
}
