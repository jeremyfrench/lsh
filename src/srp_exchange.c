/* srp_exchange.h
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

#if 0
/* GABA:
   (class
     (name srp_entry)
     (vars
       (name string)
       (salt string)
       (verifier bignum)))
*/


/* GABA:
   (class
     (name srp_server_exchange)
     (super keyexchange_algorithm)
     (vars
       (dh object diffie_hellman_method)
       (db object user_db)
       ;; Remove this?
       ;; (keys object alist)))
*/

/* Thomas Wu's Secure Remote Password Protocol, with a fixed group. */

/* GABA:
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
    = hash_string(H, ssh_format("%s%s", salt,
				hash_string(H, ssh_format("%s%s", name, passwd), 1),
				1));

  bignum_parse_u(r, h->length, h->data);
  lsh_string_free(h);
}

/* dh_instance, name */
struct lsh_string *
srp_make_init_msg(struct srp_instance *self)
{
  dh_generate_secret(&self->dh, self->dh.e);
  return ssh_format("%c%s%n", SSH_MSG_KEXSRP_INIT, self->name, self->dh.e);
}

/* dh_instance, packet -> name */
struct lsh_string *
srp_process_init_msg(struct srp_instance *self, struct lsh_string *packet)
{
  struct simple_buffer buffer;
  unsigned msg_number;
  
  simple_buffer_init(&buffer, packet->length, packet->data);

  return (parse_uint8(&buffer, &msg_number)
	  && (msg_number == SSH_MSG_KEXSRP_INIT)
	  && ( (self->name = parse_string_copy(&buffer) ))
	  && parse_bignum(&buffer, self->e)
	  && (mpz_cmp_ui(self->e, 1) > 0)
	  && GROUP_RANGE(self->method->G, self->e)
	  && parse_eod(&buffer) );
}

/* dh_instance */
static UINT32
srp_select_u(struct srp_instance *self)
{
  struct lsh_string *h;

  h = hash_string(self->dh.method->H, ssh_format("%ln", self->dh.f), 1);

  self->u = READ_UINT32(h->data);
  lsh_string_free(h);

  return self->u;
}

/* dh_instance, v */
struct lsh_string *
srp_make_reply_msg(struct srp_instance *self)
{
  for (;;)
    {
      /* Loop, in case f or u turns out to be zero */
      dh_generate_secret(&self->dh, &self->dh.f);

      /* FIXME: We use XOR rather than addition modulo p */
      mpz_xor(&self->dh.f, &self.dh.f, self->v);

      if (!mpz_sgn(&self->df.h))
	{
	  werror("srp_exchange.c: Found cleartext password by mistake!\n");
	  continue;
	}

      if (srp_select_u(self))
	break;
    }

  /* Compute (e v^u) ^ b */
  GROUP_SMALL_POWER(self->dh.G, self->dh.K, self->v, self->u);
  GROUP_COMBINE(self->dh.G, self->dh.K, self->dh.e, self->dh.K);
  GROUP_POWER(self->dh.G, self->dh.K, self->dh.K, self->dh.secret);
  
  return ssh_format("%c%s%n", SSH_MSG_KEXSRP_REPLY, self->salt, self->dh.f);
}

/* dh_instance, packet -> salt */
int
srp_process_reply_msg(struct srp_instance *self, struct lsh_string *packet)
{
  struct simple_buffer buffer;
  unsigned msg_number;
  UINT32 u;
  mpz_t t;
  
  simple_buffer_init(&buffer, packet->length, packet->data);

  if (! (parse_uint8(&buffer, &msg_number)
	 && (msg_number == SSH_MSG_KEXSRP_REPLY)
	 && ( (self->salt = parse_string_copy(&buffer) ))
	 && parse_bignum(&buffer, self->f)
	 && (mpz_cmp_ui(self->f, 1) > 0)
	 && GROUP_RANGE(self->method->G, self->f)
	 && parse_eod(&buffer)))
    return 0;

  u = srp_select_u(...);

  if (!u)
    return 0;

  return 1;
}

struct lsh_string *make_
#endif
