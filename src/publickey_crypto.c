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


struct lsh_string *do_dss_sign(struct signer *s,
			       UINT32 length,
			       UINT8 *data)
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

  /* Compute r = (a^k (mod p)) (mod q) */
  mpz_init(r);
  mpz_powm(r, a, k, closure->p);
  mpz_tdiv_r(r, r, closure->q);
  
  /* Compute hash */
  hash = MAKE_HASH(&sha_algorithm);
  digest = alloca(hash->hash_size);
  HASH_UPDATE(hash, length, data);
  HASH_DIGEST(hash, digest);

  bignum_parse_u(tmp, digest, hash->hash_size);

  lsh_free(hash);

  /* Compute k^-1 (mod q) */
  if (!mpz_invert(k, k, closure->q))
    fatal("publickey.c: k non-invertible\n");

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
		  UINT8 *data,
		  UINT32 signature_length,
		  UINT8 * signature_data)
{
  struct dss_signer *closure = (struct dss_signer *) s;
  struct simple_buffer buffer;

  int atom;
  bignum r, s;
  
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

  
       

