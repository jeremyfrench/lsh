/* publickey_crypto.h
 *
 *
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

#ifndef LSH_PUBLICKEY_CRYPTO_H_INCLUDED
#define LSH_PUBLICKEY_CRYPTO_H_INCLUDED

#include "abstract_crypto.h"
#include "parse.h"

#define GABA_DECLARE
#include "publickey_crypto.h.x"
#undef GABA_DECLARE

/* GABA:
   (class
     (name keypair)
     (vars
       ; Atom identifying algorithm type. Needed mostly to know when to invoke the
       ; ssh2 ssh-dss bug-compatibility kludge. 
       (type . int)
       (public string)
       (private object signer)))
*/

struct keypair *
make_keypair(UINT32 type,
	     struct lsh_string *public,
	     struct signer *private);

/* DSA definitions */
/* GABA:
   (struct
     (name dsa_public)
     (vars
       (p bignum)
       (q bignum)
       (g bignum)
       (y bignum)))
*/

/* DSA signatures */

/* NOTE: These definitions should not really be public. But the
 * structures are needed for both plain ssh-dss and spki-style dsa. */

/* GABA:
   (class
     (name dsa_signer)
     (super signer)
     (vars
       (random object randomness)
       (public struct dsa_public)
       (a bignum)))
*/

/* GABA:
   (class
     (name dsa_verifier)
     (super verifier)
     (vars
       (public struct dsa_public)))
*/

void init_dsa_public(struct dsa_public *public);

/* parse an ssh keyblob */
int parse_dsa_public(struct simple_buffer *buffer,
		     struct dsa_public *public);

struct signature_algorithm *make_dsa_algorithm(struct randomness *random);

/* Non spki keys */
struct dsa_verifier *
make_ssh_dss_verifier(UINT32 public_length,
		      const UINT8 *public);

struct lsh_string *
ssh_dss_public_key(struct signer *s);

#if DATAFELLOWS_WORKAROUNDS

struct verifier *make_dsa_verifier_kludge(struct verifier *v);
struct signer *make_dsa_signer_kludge(struct signer *dsa);

/* struct signature_algorithm *make_dsa_kludge_algorithm(struct randomness *random); */
#endif

struct signer *make_dsa_signer_classic(struct signer *s);
struct verifier *make_dsa_verifier_classic(struct verifier *v);

struct signature_algorithm *
make_rsa_algorithm(struct hash_algorithm *hash,
		   UINT32 prefix_length,
		   const UINT8 *prefix);

/* Groups. For now, assume that all group elements are represented by
 * bignums. */
/* GABA:
   (class
     (name abstract_group)
     (vars
       (order bignum)
       (generator bignum)
       
       ;; Checks if a bignum is in the correct range for being a group element. 
       (range method int "mpz_t x")

       ; (member method int "mpz_t x")
       
       (invert method void "mpz_t res" "mpz_t x")
       (combine method void "mpz_t res" "mpz_t a" "mpz_t b")

       ; This provides operations G x G -> G that is unrelated to the
       ; group operation above. It is needed by SRP. For the group Z/n,
       ; it can simply be ring addition and subtraction.

       ; The operations may fail (for instance if the result is
       ; zero, which is not a member of the multiplicative group). In
       ; that case, the method returns zero.

       (add method int "mpz_t res" "mpz_t a" "mpz_t b")
       (subtract method int "mpz_t res" "mpz_t a" "mpz_t b")
       
       ; FIXME: Doesn't handle negative exponents
       (power method void "mpz_t res" "mpz_t g" "mpz_t e")
       (small_power method void "mpz_t res" "mpz_t g" "UINT32 e"))) */

#define GROUP_RANGE(group, x) ((group)->range((group), (x)))
#define GROUP_INVERT(group, res, x) ((group)->invert((group), (res), (x)))
#define GROUP_COMBINE(group, res, a, b) \
((group)->combine((group), (res), (a), (b)))
#define GROUP_POWER(group, res, g, e) \
((group)->power((group), (res), (g), (e)))
#define GROUP_SMALL_POWER(group, res, g, e) \
((group)->small_power((group), (res), (g), (e)))
#define GROUP_ADD(group, res, a, b) \
((group)->add((group), (res), (a), (b)))
#define GROUP_SUBTRACT(group, res, a, b) \
((group)->subtract((group), (res), (a), (b)))

struct abstract_group *
make_group_zn(mpz_t p, mpz_t g, mpz_t order);

struct abstract_group *
make_ring_zn(mpz_t p, mpz_t g);

/* NOTE: The object system is not powerful enough for a proper ring
 * class, as we would like
 *
 *   abstract_ring inherits abstract_group,
 *   group_zn      inherits abstract_group
 *   ring_zn       inherits abstract_ring, group_zn
 *
 * and we don't have multiple inheritance.
 */

/* ;; GABA:
   (class
     (name abstract_ring)
     ; The group refers to the multiplicative group.
     ; For SRP, the generator should generate the entire group.
     (super abstract_group)
     (vars
       (add method void "mpz_t res" "mpz_t a" "mpz_t b")))
*/

struct abstract_group *
make_ssh_group1(void);


struct abstract_group *
make_ssh_ring_srp_1(void);

/* DH key exchange, with authentication */
/* GABA:
   (class
     (name dh_method)
     (vars
       (G object abstract_group)
       (H object hash_algorithm)
       (random object randomness)))
*/

/* GABA:
   (struct
     (name dh_instance)
     (vars
       (method object dh_method)
       (e bignum)       ; Client value
       (f bignum)       ; Server value
       ;; FIXME: Move these somewhere else?
       (server_key string)
       (signature string)
       (secret bignum)  ; This side's secret exponent
       (K bignum)
       (hash object hash_instance)
       (exchange_hash string)))
*/

/* Creates client message */
struct lsh_string *
dh_make_client_msg(struct dh_instance *self);

/* Receives client message */
int
dh_process_client_msg(struct dh_instance *self,
		      struct lsh_string *packet);

/* Includes more data to the exchange hash. */
void
dh_hash_update(struct dh_instance *self,
	       struct lsh_string *s, int free);

/* Generates server's secret exponent */
void
dh_make_server_secret(struct dh_instance *self);

/* Creates server message */
struct lsh_string *
dh_make_server_msg(struct dh_instance *self,
		   struct signer *s);

/* Decodes server message, but does not verify its signature */
int
dh_process_server_msg(struct dh_instance *self,
		      struct lsh_string *packet);

/* Verifies server's signature */
int
dh_verify_server_msg(struct dh_instance *self,
		     struct verifier *v);

void
dh_generate_secret(struct dh_method *self,
		   mpz_t r, mpz_t v);

void
dh_hash_digest(struct dh_instance *self);

struct dh_method *
make_dh(struct abstract_group *G, struct hash_algorithm *H,
	struct randomness *r);

struct dh_method *
make_dh1(struct randomness *r);

void
init_dh_instance(struct dh_method *m,
		 struct dh_instance *self,
		 struct ssh_connection *c);

#endif /* LSH_PUBLICKEY_CRYPTO_H_INCLUDED */
