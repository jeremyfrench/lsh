/* spki-decrypt.c
 *
 * Decryption of private keys.
 *
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1999, 2003, 2008, Niels Möller
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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include "nettle/sexp.h"

#include "spki.h"

#include "atoms.h"
#include "interact.h"
#include "format.h"
#include "lsh_string.h"
#include "sexp.h"
#include "werror.h"
#include "xalloc.h"

static int
parse_pkcs5(struct sexp_iterator *i, struct alist *mac_algorithms,
	    struct mac_algorithm **mac, uint32_t *iterations,
	    const struct lsh_string **salt)
{
  switch (lsh_sexp_get_type(i)) 
    {
    default:
      werror("Unknown key derivation mechanism.\n");
      return 0;

    case ATOM_XPKCS5V2:
      {
	const uint8_t *names[2] = { "salt", "iterations" };
	struct sexp_iterator values[2];
	    
	CAST_SUBTYPE(mac_algorithm, tmp,
		     ALIST_GET(mac_algorithms, lsh_sexp_to_atom(i)));

	*mac = tmp;
	if (!*mac)
	  {
	    werror("Unknown mac for pkcs5v2.\n");
	    return 0;
	  }

	return (sexp_iterator_assoc(i, 2, names, values)
		&& (*salt = lsh_sexp_to_string(&values[0], NULL))
		&& sexp_iterator_get_uint32(&values[1], iterations)
		&& *iterations);
      }
    }
}

static int
parse_pkcs5_payload(struct sexp_iterator *i, struct alist *crypto_algorithms,
		    struct crypto_algorithm **crypto,
		    const struct lsh_string **iv,
		    const struct lsh_string **data)
{
  const uint8_t *names[2] = { "data", "iv" };
  struct sexp_iterator values[2];

  CAST_SUBTYPE(crypto_algorithm, tmp,
	       spki_algorithm_lookup(crypto_algorithms, i, NULL));
	
  *crypto = tmp;

  if (!*crypto)
    {
      werror("Unknown encryption algorithm for pkcs5v2.\n");
      return 0;
    }

  if ((*crypto)->iv_size)
    {
      if (!sexp_iterator_assoc(i, 2, names, values))
	return 0;

      *iv = lsh_sexp_to_string(&values[1], NULL);

      if (lsh_string_length(*iv) != (*crypto)->iv_size)
	return 0;
    }
  else if (!sexp_iterator_assoc(i, 1, names, values))
    return 0;

  *data = lsh_sexp_to_string(&values[0], NULL);
    
  if ((*crypto)->block_size
      && (lsh_string_length(*data) % (*crypto)->block_size))
    {
      werror("Payload data doesn't match block size for pkcs5v2.\n");
      return 0;
    }

  return 1;
}

/* Frees input string. */
struct lsh_string *
spki_pkcs5_decrypt(struct alist *mac_algorithms,
                   struct alist *crypto_algorithms,
                   struct lsh_string *expr)
{
  struct sexp_iterator i;
  
  if (! (sexp_iterator_first(&i, STRING_LD(expr))
	 && sexp_iterator_check_type(&i, "password-encrypted")))
    return expr;

  else
    {
      struct crypto_algorithm *crypto;
      struct mac_algorithm *mac;

      const struct lsh_string *label = NULL;
      const struct lsh_string *salt = NULL;
      const struct lsh_string *iv = NULL;
      const struct lsh_string *data = NULL;
      uint32_t iterations;
      
      /* NOTE: This is a place where it might make sense to use a sexp
       * display type, but we don't support that for now. */
      label = lsh_sexp_to_string(&i, NULL);

      if (!label)
	{
	  werror("Invalid label in (password-encrypted ...) expression.\n");
	fail:
	  lsh_string_free(data);
	  lsh_string_free(expr);
	  lsh_string_free(iv);
	  lsh_string_free(salt);
	  lsh_string_free(label);
	  return NULL;
	}

      if (!parse_pkcs5(&i, mac_algorithms, &mac, &iterations, &salt))
	goto fail;

      if (!parse_pkcs5_payload(&i, crypto_algorithms,
			       &crypto, &iv, &data))
	goto fail;
      
      /* Do the work */
      
      {
	struct lsh_string *password
	  = interact_read_password(ssh_format("Passphrase for key `%lS': ",
					      label));
	struct lsh_string *clear;
	struct lsh_string *key;
	
	if (!password)
	  {
	    werror("No password provided for pkcs5v2.\n");
	    goto fail;
	  }

	key = pkcs5_derive_key(mac,
			       password, salt, iterations,
			       crypto->key_size);

	clear
	  = crypt_string_unpad(MAKE_DECRYPT(crypto,
					    lsh_string_data(key),
					    iv ? lsh_string_data(iv) : NULL),
			       data);
	lsh_string_free(expr);
	lsh_string_free(iv);
	lsh_string_free(password);
	lsh_string_free(salt);
	lsh_string_free(label);
	lsh_string_free(key);
	    	    
	if (!clear)
	  werror("Bad password for pkcs5v2.\n");

	return clear;
      }
    }
}
