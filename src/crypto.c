/* crypto.c
 *
 */

#include "crypto.h"

static void do_crypt_none(struct crypto_instance *ignored,
			  UINT32 length, UINT8 *dst, UINT8 *src)
{
  if (src != dst)
    memcpy(dst, src, length);
}

struct crypto_instance crypto_none_instance =
{
  8,
  do_crypt_none
};
