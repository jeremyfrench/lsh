m4_dnl LSH testsuite driver
m4_dnl (progn (modify-syntax-entry ?» "(«") (modify-syntax-entry ?« ")»"))
m4_dnl (progn (modify-syntax-entry 187 "(«") (modify-syntax-entry 170 ")»"))
m4_dnl (progn (modify-syntax-entry ?{ "(}") (modify-syntax-entry ?} "){"))
m4_changequote(», «)
m4_changecom(/*, */)
m4_define(»TS_DEFINE«, m4_defn(»m4_define«))

TS_DEFINE(»TS_WRITE«, »fputs("$1", stderr);«)
TS_DEFINE(»TS_MESSAGE«, »TS_WRITE($1 ... )«)
TS_DEFINE(»TS_OK«, »TS_WRITE(ok.\n)«)
TS_DEFINE(»TS_FAIL«, »{ TS_WRITE(failed.\n); exit(1); }«)
TS_DEFINE(»TS_CHECK«, »if ($1) TS_OK else TS_FAIL«)
TS_DEFINE(»TS_STRING«,
»m4_ifelse(m4_index(»$1«, »"«), 0,
  »ssh_format("%lz", »$1«)«, »simple_decode_hex("m4_translit(»$1«, »0-9a-zA-Z
# 	«, »0-9a-zA-Z«)")«) «)

TS_DEFINE(»TS_SEXP«, »string_to_sexp(SEXP_TRANSPORT, TS_STRING(»$1«), 1)«)

m4_dnl TS_DEFINE(»TS_SEXP_L«, »sexp_l($#, $@, -1)«)
m4_dnl TS_DEFINE(»TS_SEXP_A«, »sexp_a(TS_STRING($1))«)

TS_DEFINE(»TS_TEST_STRING_EQ«,
»
  {
    struct lsh_string *a, *b;
    TS_MESSAGE($1)
    a = $2;
    b = $3;
    if (!lsh_string_eq(a, b))
      TS_FAIL
    TS_OK
    lsh_string_free(a);
    lsh_string_free(b);
  }
«)

m4_dnl TS_TEST_HASH(name, algorithm, data, digest)
TS_DEFINE(»TS_TEST_HASH«,
  »TS_TEST_STRING_EQ(»$1«, hash_string(»$2«, TS_STRING(»$3«), 1), TS_STRING(»$4«))«)

m4_dnl TS_TEST_HMAC(name, algorithm, key, data, digest)
TS_DEFINE(»TS_TEST_HMAC«, »
  {
    struct mac_algorithm *hmac = make_hmac_algorithm($2);
    struct lsh_string *key = TS_STRING(»$3«);

    TS_TEST_STRING_EQ(»$1«, mac_string(hmac, key, 1,
                                       TS_STRING(»$4«), 1),
                      TS_STRING(»$5«));
  }
«)

m4_dnl TS_TEST_CRYPTO(name, algorithm, key, clear, cipher [, iv])
TS_DEFINE(»TS_TEST_CRYPTO«, »
  {
    struct crypto_instance *c;
    struct crypto_algorithm *algorithm = »$2«;
    struct lsh_string *key = TS_STRING(»$3«);
    struct lsh_string *plain = TS_STRING(»$4«);
    struct lsh_string *cipher = TS_STRING(»$5«);

m4_ifelse(»$6«,,»
    UINT8 *iv = NULL;
    assert(!algorithm->iv_size);
«,»
    struct lsh_string *ivs = TS_STRING(»$6«);
    UINT8 *iv = ivs->data;
    assert(ivs->length == algorithm->iv_size);
«)
    assert(key->length == algorithm->key_size);

    c = MAKE_ENCRYPT(algorithm, key->data, iv);
    TS_TEST_STRING_EQ(»Encrypting with $1«,
	  	      »crypt_string(c, plain, 0)«,
		      »lsh_string_dup(cipher)«)
    KILL(c);
    c = MAKE_DECRYPT(algorithm, key->data, iv);
    TS_TEST_STRING_EQ(»Decrypting with $1«,
         	      »crypt_string(c, cipher, 0)«,
		      »plain«)
    KILL(c);
    
m4_ifelse(»$6«,,,»
    lsh_string_free(ivs);
«)
    lsh_string_free(key);
    lsh_string_free(cipher);
  }
«)    

m4_dnl TS_TEST_VERIFY(name, key, msg, signature)
TS_DEFINE(»TS_TEST_VERIFY«,
»
{
  struct alist *algorithms = all_signature_algorithms(make_bad_random());
  struct sexp *key = TS_SEXP(»$2«);
  struct lsh_string *msg = TS_STRING(»$3«);
  struct sexp *sign = TS_SEXP(»$4«);
  struct verifier *v = spki_make_verifier(algorithms, key);

  TS_MESSAGE($1);
  if (!v)
    /* Invalid key. */
    TS_FAIL; 

  if (!VERIFY_SPKI(v, msg->length, msg->data, sign))
    /* Unexpected verification failure. */
    TS_FAIL;

  /* Modify message slightly. */
  assert(msg->length > 10);

  msg->data[5] ^= 0x40;

  if (VERIFY_SPKI(v, msg->length, msg->data, sign))
    /* Unexpected verification success. */
    TS_FAIL;

  TS_OK;
}«)

m4_dnl TS_TEST_SIGN(name, key, msg [, signature])
TS_DEFINE(»TS_TEST_SIGN«,
»
{
  struct alist *algorithms = all_signature_algorithms(make_bad_random());
  struct sexp *key = TS_SEXP(»$2«);
  struct lsh_string *msg = TS_STRING(»$3«);
  struct sexp *sign;
  struct signer *s = spki_make_signer(algorithms, key, NULL);
  struct verifier *v;

  TS_MESSAGE($1);
  if (!s)
    /* Invalid key. */
    TS_FAIL; 

  sign = SIGN_SPKI(s, msg->length, msg->data);

  m4_ifelse($4,,,
  »
  {
    struct lsh_string *s2 = TS_STRING(»$4«);
    if (!lsh_string_eq(s2, sexp_format(sign, SEXP_CANONICAL, 0)))
      TS_FAIL
  }
  «)
  v = SIGNER_GET_VERIFIER(s);
  if (!v)
    /* Can't create verifier */
    TS_FAIL

  if (!VERIFY_SPKI(v, msg->length, msg->data, sign))
    /* Unexpected verification failure. */
    TS_FAIL;

  /* Modify message slightly. */
  assert(msg->length > 10);

  msg->data[5] ^= 0x40;

  if (VERIFY_SPKI(v, msg->length, msg->data, sign))
    /* Unexpected verification success. */
    TS_FAIL;

  TS_OK
}«)

m4_dnl TS_TAG_GRANT(msg, tag-set, access)
TS_DEFINE(»TS_TAG_GRANT«,
»
{
  struct spki_tag *tag = spki_sexp_to_tag(TS_SEXP(»$2«), 17);
  struct sexp *access = TS_SEXP(»$3«);
  TS_MESSAGE(»Granting access $1«)
  assert(tag);
  assert(access);
  
  if (SPKI_TAG_MATCH(tag, access))
    TS_OK
  else
    TS_FAIL
  KILL(tag);
  KILL(access);
}«)

m4_dnl TS_TAG_DENY(msg, tag-set, access)
TS_DEFINE(»TS_TAG_DENY«,
»
{
  struct spki_tag *tag = spki_sexp_to_tag(TS_SEXP(»$2«), 17);
  struct sexp *access = TS_SEXP(»$3«);
  TS_MESSAGE(»Denying access $1«)
  assert(tag);
  assert(access);
  
  if (!SPKI_TAG_MATCH(tag, access))
    TS_OK
  else
    TS_FAIL
  KILL(tag);
  KILL(access);
}«)



m4_divert(1)
  return 0;
}
m4_divert

m4_dnl C code
#include "lsh.h"

#include "algorithms.h"
#include "crypto.h"
#include "digits.h"
#include "format.h"
#include "randomness.h"
#include "sexp.h"
#include "spki.h"
#include "werror.h"
#include "xalloc.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
  argp_parse(&werror_argp, argc, argv, 0, NULL, NULL);
