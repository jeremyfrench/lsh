/* srp_exchange.c
 *
 * Thomas Wu's Secure Remote Password Protocol
 *
 * $Id$ */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 2000 Niels Möller
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

#include "srp.h"

#include "format.h"
#include "sexp.h"
#include "ssh.h"
#include "werror.h"
#include "xalloc.h"

#include <assert.h>

#define GABA_DEFINE
#include "srp.h.x"
#undef GABA_DEFINE

#if WITH_SRP

/* We use the following syntax for verifiers:
 *
 * (srp-verifier ssh-group1 <salt> <verifier>)
 *
 * For now, the second element is the name of a group; we could also substitute
 * ( (modulo <n>) (generator <g>) ) or something like that.
 */

/* Copies the name,rather than consuming it. */
struct srp_entry *
make_srp_entry(struct lsh_string *name, struct sexp *e)
{
  struct sexp_iterator *i;

  if (sexp_check_type(e, ATOM_SRP_VERIFIER, &i)
      && (SEXP_LEFT(i) == 3)
      && sexp_atom_eq(SEXP_GET(i), ATOM_SSH_GROUP1) )
    {
      NEW(srp_entry, res);
      struct lsh_string *salt;

      mpz_init(res->verifier);
      
      SEXP_NEXT(i);

      salt = sexp2string(SEXP_GET(i));
      if (!salt)
	{
	  KILL(res);
	  return NULL;
	}
      res->salt = lsh_string_dup(salt);

      SEXP_NEXT(i);

      if (!sexp2bignum_u(SEXP_GET(i), res->verifier))
	{
	  KILL(res);
	  return NULL;
	}
      
      res->name = lsh_string_dup(name);

      return res;
    }
  else
    return NULL;
}

/* Consumes the salt */
struct sexp *
srp_make_verifier(struct abstract_group *G,
		  struct hash_algorithm *H,
		  struct lsh_string *salt,
		  struct lsh_string *name,
		  struct lsh_string *passwd)
{
  mpz_t x;
  struct sexp *e;
  
  mpz_init(x);

  srp_hash_password(x, H, salt, name, passwd);  
  GROUP_POWER(G, x, G->generator, x);

  e = sexp_l(4,
	     sexp_a(ATOM_SRP_VERIFIER), sexp_a(ATOM_SSH_GROUP1),
	     sexp_s(NULL, salt),
	     sexp_un(x),
	     -1);

  mpz_clear(x);

  return e;
}

/* Thomas Wu's Secure Remote Password Protocol, with a fixed group. */

/* ;; GABA:
   (struct
     (name srp_instance)
     (vars
       ;; FIXME: Use super for the dh_instance
       (dh struct dh_instance)
       (user string)  ; User name
       (salt string)
       (u . UINT32)
       (v bignum)))
*/

void
srp_hash_password(mpz_t x,
		  struct hash_algorithm *H,
		  struct lsh_string *salt,
		  struct lsh_string *name,
		  struct lsh_string *passwd)
{
  struct lsh_string *h
    = hash_string(H, ssh_format("%S%fS", salt,
				hash_string(H, ssh_format("%S%S", name, passwd), 1)),
		  1);

  bignum_parse_u(x, h->length, h->data);
  lsh_string_free(h);
}

/* dh_instance, name */
struct lsh_string *
srp_make_init_msg(struct dh_instance *dh, struct lsh_string *name)
{
  dh_generate_secret(dh->method, dh->secret, dh->e);
  dh_hash_update(dh, ssh_format("%S", name), 1);
  return ssh_format("%c%S%n", SSH_MSG_KEXSRP_INIT, name, dh->e);
}

/* dh_instance, packet -> name */
struct lsh_string *
srp_process_init_msg(struct dh_instance *self, struct lsh_string *packet)
{
  struct simple_buffer buffer;
  unsigned msg_number;

  struct lsh_string *name;
  
  simple_buffer_init(&buffer, packet->length, packet->data);

  if (parse_uint8(&buffer, &msg_number)
      && (msg_number == SSH_MSG_KEXSRP_INIT)
      && ( (name = parse_string_copy(&buffer) ))
      && parse_bignum(&buffer, self->e)
      && (mpz_cmp_ui(self->e, 1) > 0)
      && GROUP_RANGE(self->method->G, self->e)
      && parse_eod(&buffer) )

    return name;

  else
    {
      werror("Invalid SSH_MSG_KEXSRP_INIT message.\n");
      return NULL;
    }
}

/* dh_instance */
static UINT32
srp_select_u(struct dh_instance *dh)
{
  struct lsh_string *h;
  UINT32 u;
  
  h = hash_string(dh->method->H, ssh_format("%ln", dh->f), 1);

  u = READ_UINT32(h->data);
  lsh_string_free(h);

  return u;
}

/* dh_instance, v */
struct lsh_string *
srp_make_reply_msg(struct dh_instance *dh, struct srp_entry *entry)
{
  UINT32 u;
  
  for (;;)
    {
      /* Loop, in case f or u turns out to be zero */
      dh_generate_secret(dh->method, dh->secret, dh->f);

      zn_ring_add(dh->method->G, dh->f, dh->f, entry->verifier);

      if (!mpz_sgn(dh->f))
	{
	  werror("srp_exchange.c: Found cleartext password by mistake!\n");
	  continue;
	}

      u = srp_select_u(dh);
      if (u)
	break;
    }

  /* Compute (e v^u) ^ b */
  GROUP_SMALL_POWER(dh->method->G, dh->K, entry->verifier, u);
  GROUP_COMBINE(dh->method->G, dh->K, dh->e, dh->K);
  GROUP_POWER(dh->method->G, dh->K, dh->K, dh->secret);

  /* Update the exchange hash */
  
  dh_hash_update(dh, ssh_format("%S%S", entry->name, entry->salt), 1);
  dh_hash_digest(dh);
  
  return ssh_format("%c%S%n", SSH_MSG_KEXSRP_REPLY, entry->salt, dh->f);
}

/* dh_instance, packet -> salt */
struct lsh_string *
srp_process_reply_msg(struct dh_instance *dh, struct lsh_string *packet)
{
  struct simple_buffer buffer;
  unsigned msg_number;
  struct lsh_string *salt;
  
  simple_buffer_init(&buffer, packet->length, packet->data);

  if (parse_uint8(&buffer, &msg_number)
      && (msg_number == SSH_MSG_KEXSRP_REPLY)
      && ( (salt = parse_string_copy(&buffer) ))
      && parse_bignum(&buffer, dh->f)
      && (mpz_cmp_ui(dh->f, 1) > 0)
      && GROUP_RANGE(dh->method->G, dh->f)
      && parse_eod(&buffer))
    {
      /* FIXME: It would be better to keep the u around. Now, we have
       * to compute it again later. */
      if (!srp_select_u(dh))
	{
	  werror("Recived SSH_MSG_KEXSRP_REPLY messge with u = 0.\n");
	  lsh_string_free(salt);
	  return NULL;
	}
      dh_hash_update(dh, ssh_format("%S", salt), 1);      
      return salt;
    }
  else
    {
      werror("Invalid SSH_MSG_KEXSRP_REPLY message.\n");
      return NULL;
    }
}

/* x is derived from the password using srp_hash_password */
struct lsh_string *
srp_make_client_proof(struct dh_instance *dh,
		      mpz_t x)
{
  UINT32 u = srp_select_u(dh);
  mpz_t v;
  mpz_t tmp;

  assert(u);
  
  mpz_init(v);
  mpz_init(tmp);

  /* Compute the verifier */
  GROUP_POWER(dh->method->G, v, dh->method->G->generator, x);

  zn_ring_subtract(dh->method->G, dh->K, dh->f, v);

  /* Compute the exponent */
  mpz_mul_ui(tmp, x, u);
  mpz_add(tmp, tmp, dh->secret);

  GROUP_POWER(dh->method->G, dh->K, dh->K, tmp);

  mpz_clear(v);
  mpz_clear(tmp);

  dh_hash_digest(dh);
  
  return ssh_format("%c%S", SSH_MSG_KEXSRP_PROOF,
		    dh->exchange_hash);
}

static struct lsh_string *
srp_format_m2(struct dh_instance *dh)
{
  return hash_string(dh->method->H,
		     ssh_format("%n%S%n",
				dh->e, dh->exchange_hash, dh->K),
		     1);
}

struct lsh_string *
srp_process_client_proof(struct dh_instance *dh, struct lsh_string *packet)
{
  struct simple_buffer buffer;
  unsigned msg_number;

  UINT32 length;
  const UINT8 *m1;
  
  simple_buffer_init(&buffer, packet->length, packet->data);

  if (parse_uint8(&buffer, &msg_number)
      && (msg_number == SSH_MSG_KEXSRP_PROOF)
      && parse_string(&buffer, &length, &m1)
      && parse_eod(&buffer))
    {
      if (!lsh_string_eq_l(dh->exchange_hash, length, m1))
	{
	  werror("SRP failed: Received invalid m1 from client.\n");
	  return NULL;
	}
      return ssh_format("%c%fS", SSH_MSG_KEXSRP_PROOF,
			srp_format_m2(dh));
    }
  return NULL;
}

int
srp_process_server_proof(struct dh_instance *dh, struct lsh_string *packet)
{
  struct simple_buffer buffer;
  unsigned msg_number;

  UINT32 length;
  const UINT8 *m2;
  
  simple_buffer_init(&buffer, packet->length, packet->data);

  if (parse_uint8(&buffer, &msg_number)
      && (msg_number == SSH_MSG_KEXSRP_PROOF)
      && parse_string(&buffer, &length, &m2)
      && parse_eod(&buffer))
    {
      struct lsh_string *my_m2 = srp_format_m2(dh);
      int res = lsh_string_eq_l(my_m2, length, m2);
      lsh_string_free(my_m2);

      if (!res)
	{
	  werror("SRP failed: Received invalid m2 from server.\n");
	  return 0;
	}
      return 1;
    }
  return 0;
}

#endif /* WITH_SRP */
