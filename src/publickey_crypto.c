/* publickey_crypto.c
 *
 */

#include "bignum.h"
#include "sha.h"
#include "atoms.h"

struct dss_public
{
  bignum p;
  bignum q;
  bignum g;
  bignum y;
};

struct dss_signer
{
  struct signer super;
  struct randomness *random;
  struct dss_public public;
  bignum a;
};

struct dss_verifier
{
  struct verifier super;
  struct dss_public public;
};
  
struct dss_algorithm
{
  struct signature_algorithm super;
  struct randomness *random;
};

static void dss_hash(bignum h, UINT32 length, UINT8 *msg)
{
  /* Compute hash */
  hash = MAKE_HASH(&sha_algorithm);
  digest = alloca(hash->hash_size);
  HASH_UPDATE(hash, length, data);
  HASH_DIGEST(hash, digest);

  bignum_parse_u(h, digest, hash->hash_size);

  lsh_free(hash);
}

static struct lsh_string *do_dss_sign(struct signer *s,
				      UINT32 length,
				      UINT8 *msg)
{
  struct dss_signer *closure = (struct dss_signer *) s;
  bignum k, r, s, tmp;
  struct hash_instance *hash;
  UINT8 *digest;
  struct lsh_string *signature;
  
  /* Select k, 0<k<q, randomly */
  mpz_init_set(tmp, closure->public.q);
  mpz_sub_ui(tmp, tmp, 1);

  mpz_init(k);
  bignum_random(k, closure.random, tmp);
  mpz_add_ui(k, k, 1);

  /* Compute r = (g^k (mod p)) (mod q) */
  mpz_init(r);
  mpz_powm(r, closure->public.g, k, closure->public.p);
  mpz_tdiv_r(r, r, closure->public.q);
  
  /* Compute hash */
  dss_hash(tmp, length, msg);

  /* Compute k^-1 (mod q) */
  if (!mpz_invert(k, k, closure->public.q))
    {
      werror("do_dss_sign: k non-invertible\n");
      mpz_clear(tmp);
      mpz_clear(k);
      mpz_clear(r);
      return NULL;
    }

  /* Compute signature s = k^-1(h + ar) (mod q) */
  mpz_init(s);
  mpz_mul(s, r, closure->secret);
  mpz_tdiv_r(s, s, closure->public.q);
  mpz_add(s, s, tmp);
  mpz_mul(s, s, k);
  mpz_tdiv_r(s, s, closure->public.q);
  
  /* Build signature */
  signature = ssh_format("%a%n%n", ATOM_SSH_DSS, r, s);

  mpz_clear(k);
  mpz_clear(r);
  mpz_clear(s);
  mpz_clear(tmp);

  return signature;
}

ind do_dss_verify(struct verifier *closure,
		  UINT32 length,
		  UINT8 *msg,
		  UINT32 signature_length,
		  UINT8 * signature_data)
{
  struct dss_signer *closure = (struct dss_signer *) s;
  struct simple_buffer buffer;

  int res;
  
  int atom;
  bignum r, s;

  bignum w, tmp, u, v;
  
  simple_buffer_init(&buffer, signature_length, signature_data);
  if (!parse_atom(&buffer, &atom)
      || (atom != ATOM_SSH_DSS) )
    return 0;

  mpz_init(r);
  mpz_init(s);
  if (! (parse_bignum(&buffer, r)
	 && parse_bignum(&buffer, s)
	 && parse_eod(&buffer)
	 && (mpz_sgn(r) == 1)
	 && (mpz_sgn(s) == 1)
	 && (mpz_cmp(r, closure->public.q) < 0)
	 && (mpz_cmp(s, closure->public.q) < 0) ))
    {
      mpz_clear(r);
      mpz_clear(s);
      return 0;
    }

  /* Compute w = s^-1 (mod q) */
  mpz_init(w);
  if (!mpz_invert(s, closure->public.q))
    {
      werror("do_dss_verify: s non-invertible.\n");
      mpz_clear(r);
      mpz_clear(s);
      mpz_clear(w);
      return 0;
    }

  /* Compute hash */
  mpz_init(tmp);
  dss_hash(tmp, length, msg);

  /* g^{w * h (mod q)} (mod p)  */

  mpz_init(v);

  mpz_mul(tmp, tmp, w);
  mpz_tdiv_r(tmp, tmp, closure->public.q);

  mpz_powm(v, closure->public.g, tmp, closure->public.p);

  /* y^{w * r (mod q) } (mod p) */
  mpz_mul(tmp, r, w);
  mpz_tdiv_r(tmp, tmp, closure->public.q);
  mpz_powm(tmp, closure->public.y, tmp, closure->public.p);

  /* (g^{w * h} * y^{w * r} (mod p) ) (mod q) */
  mpz_mul(v, v, tmp);
  mpz_tdiv_r(v, v, closure->public.q);

  res = mpz_cmp(v, r);

  mpz_clear(r);
  mpz_clear(s);
  mpz_clear(w);
  mpz_clear(tmp);
  mpz_clear(v);

  return !res;
}

int parse_dss_public(struct simple_buffer *buffer, struct dss_public *public)
{
#if 0
  mpz_init(public->p);
  mpz_init(public->q);
  mpz_init(public->g);
  mpz_init(public->y);
#endif
  
  return (parse_bignum(&buffer, public.p)
	  && parse_bignum(&buffer, public->p)
	  && (mpz_sgn(public->p) == 1)
	  && parse_bignum(&buffer, public->q)
	  && (mpz_sgn(public->q) == 1)
	  && (mpz_cmp(public->q, public->p) < 0) /* q < p */ 
	  && parse_bignum(&buffer, public->g)
	  && (mpz_sgn(public->g) == 1)
	  && (mpz_cmp(public->g, public->p) < 0) /* g < p */ 
	  && parse_bignum(&buffer, public->y) 
	  && (mpz_sgn(public->y) == 1)
	  && (mpz_cmp(public->y, public->p) < 0) /* y < p */  );
#if 0
      mpz_clear(public->p);
      mpz_clear(public->q);
      mpz_clear(public->g);
      mpz_clear(public->y);
      return 0;
#endif
}

/* FIXME: Outside of the protocol transactions, keys should be stored
 * in SPKI-style S-expressions. */
struct signer *make_dss_signer(struct signature_algorithm *closure,
			       UINT32 public_length,
			       UINT8 *public,
			       UINT32 secret_length,
			       UINT8 *secret)
{
  struct dss_signer *res;
  struct simple_buffer buffer;
  int atom;

  simple_buffer_init(&buffer, signature_length, signature_data);
  if (!parse_atom(&buffer, &atom)
      || (atom != ATOM_SSH_DSS) )
    return 0;

  res = xalloc(sizeof(struct dss_signer));

  mpz_init(res->public.p);
  mpz_init(res->public.q);
  mpz_init(res->public.g);
  mpz_init(res->public.y);
  mpz_init(res->secret);
  
  if (! (parse_dss_public(&buffer, &res->public)
  	 && parse_bignum(&buffer, res->secret)
	 /* FIXME: Perhaps do some more sanity checks? */
	 && mpz_sign(res->secret) == 1))
    {
      mpz_clear(res->public.p);
      mpz_clear(res->public.q);
      mpz_clear(res->public.g);
      mpz_clear(res->public.y);
      mpz_clear(res->secret);
      lsh_free(res);
      return NULL;
    }
  
  res->super.sign = do_dss_sign;
  return &res->super;
}

struct verifier *make_dss_verifier(struct signature_algorithm *closure,
				   UINT32 public_length,
				   UINT8 *public)
{
  struct dss_verifier *res;
  struct simple_buffer buffer;
  int atom;

  simple_buffer_init(&buffer, public_length, public);
  if (!parse_atom(&buffer, &atom)
      || (atom != ATOM_SSH_DSS) )
    return 0;

  res = xalloc(sizeof(struct dss_verifier));

  mpz_init(res->public.p);
  mpz_init(res->public.q);
  mpz_init(res->public.g);
  mpz_init(res->public.y);
  
  if (!parse_dss_public(&buffer, &res->public))
    /* FIXME: Perhaps do some more sanity checks? */
    {
      mpz_clear(res->public.p);
      mpz_clear(res->public.q);
      mpz_clear(res->public.g);
      mpz_clear(res->public.y);
          lsh_free(res);
      return NULL;
    }

  res->super.verify = do_dss_verify;
  return &res->super;
}

struct make_dss_algorithm(struct randomness *random)
{
  struct dss_algorithm *res = xalloc(sizeof(struct dss_algorithm));

  dss->super.make_signer = make_dss_signer;
  dss->super.make_verifier = make_dss_verifier;
  dss->random = random;

  return &dss->super;
}
    
