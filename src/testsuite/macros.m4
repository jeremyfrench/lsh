m4_dnl LSH testsuite driver
m4_dnl (progn (modify-syntax-entry ?» "(«") (modify-syntax-entry ?« ")»"))
m4_dnl (progn (modify-syntax-entry 187 "(«") (modify-syntax-entry 170 ")»"))
m4_dnl (progn (modify-syntax-entry ?{ "(}") (modify-syntax-entry ?} "){"))
m4_changequote(», «)
m4_changecom(/*, */)
m4_define(»TS_DEFINE«, m4_defn(»m4_define«))

TS_DEFINE(»TS_WRITE«, »fputs("$1", stderr);«)
TS_DEFINE(»TS_MESSAGE«, »TS_WRITE($1... )«)
TS_DEFINE(»TS_OK«, »TS_WRITE(ok.\n)«)
TS_DEFINE(»TS_FAIL«, »{ TS_WRITE(failed.\n); exit(1); }«)

TS_DEFINE(»TS_STRING«,
»m4_ifelse(m4_index(»$1«, »"«), 0,
  »ssh_format("%lz", »$1«)«, »simple_decode_hex("m4_translit(»$1«, »0-9a-zA-Z
# 	«, »0-9a-zA-Z«)")«) «)

TS_DEFINE(»TS_SEXP«, »string_to_sexp(TS_STRING(»$1«), 1)«)

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

m4_dnl TS_TEST_CRYPTO(name, algorithm, key, clear, cipher)
TS_DEFINE(»TS_TEST_CRYPTO«, »
  {
    struct crypto_algorithm *algorithm = »$2«;
    struct lsh_string *key = TS_STRING(»$3«);
    struct lsh_string *plain = TS_STRING(»$4«);
    struct lsh_string *cipher = TS_STRING(»$5«);
    struct crypto_instance *c;

    assert(key->length == algorithm->key_size);
    assert(!algorithm->iv_size);

    c = MAKE_ENCRYPT(algorithm, key->data, NULL);
    TS_TEST_STRING_EQ(»Encrypting with $1«,
	  	      »crypt_string(c, plain, 0)«,
		      »lsh_string_dup(cipher)«)
    KILL(c);
    c = MAKE_DECRYPT(algorithm, key->data, NULL);
    TS_TEST_STRING_EQ(»Decrypting with $1«,
         	      »crypt_string(c, cipher, 0)«,
		      »plain«)
    KILL(c);
    
    lsh_string_free(key);
    lsh_string_free(cipher);
  }
«)    


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

#include "crypto.h"
#include "digits.h"
#include "format.h"
#include "sexp.h"
#include "spki.h"
#include "xalloc.h"

#include <assert.h>
#include <stdio.h>

int main(int argc UNUSED, char **argv UNUSED)
{
