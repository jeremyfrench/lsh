#include "testutils.h"

#include "format.h"
#include "xalloc.h"

/* -1 means invalid */
static const signed char hex_digits[0x100] =
  {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
     0, 1, 2, 3, 4, 5, 6, 7, 8, 9,-1,-1,-1,-1,-1,-1,
    -1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
  };

static unsigned
decode_hex_length(const char *h)
{
  const unsigned char *hex = (const unsigned char *) h;
  unsigned count;
  unsigned i;
  
  for (count = i = 0; hex[i]; i++)
    {
      if (isspace(hex[i]))
	continue;
      if (hex_digits[hex[i]] < 0)
	abort();
      count++;
    }

  if (count % 2)
    abort();
  return count / 2;  
}

const struct lsh_string *
decode_hex(const char *h)
{  
  const unsigned char *hex = (const unsigned char *) h;
  UINT32 length = decode_hex_length(h);
  UINT8 *dst;
  
  unsigned i = 0;
  struct lsh_string *s = ssh_format("%lr", length, &dst);

  for (;;)
    {
      int high, low;
    
      while (*hex && isspace(*hex))
	hex++;

      if (!*hex)
	return s;

      high = hex_digits[*hex++];
      if (high < 0)
	return NULL;

      while (*hex && isspace(*hex))
	hex++;

      if (!*hex)
	return NULL;

      low = hex_digits[*hex++];
      if (low < 0)
	return NULL;

      dst[i++] = (high << 4) | low;
    }
}

int
main(int argc, char **argv)
{
  (void) argc; (void) argv;
  return test_main();
}

void
test_cipher(const char *name, struct crypto_algorithm *algorithm,
	    const struct lsh_string *key,
	    const struct lsh_string *plain,
	    const struct lsh_string *cipher,
	    const struct lsh_string *iv)
{
  struct crypto_instance *c;
  struct lsh_string *x;

  (void) name;
  
  if (iv)
    {
      if (algorithm->iv_size != iv->length)
	FAIL();
    }
  else if (algorithm->iv_size)
    FAIL();

  c = MAKE_ENCRYPT(algorithm, key->data, iv ? iv->data : NULL);

  x = crypt_string(c, plain, 0);
  if (!lsh_string_eq(x, cipher))
    FAIL();
  
  KILL(c);
  
  c = MAKE_DECRYPT(algorithm, key->data, iv ? iv->data : NULL);

  x = crypt_string(c, x, 1);
  if (!lsh_string_eq(x, plain))
    FAIL();

  KILL(c);
  lsh_string_free(x);
}
