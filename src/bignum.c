/* bignum.c
 *
 */

#include "bignum.h"
#include "werror.h"

static void limbs_to_octets(mpz_t n, UINT32 length,
			    UINT8 pad, UINT8 *data)
{
  UINT8 *dst = data + length - 1;
	
  mp_limb_t *l = n->_mp_d;  /* Starts at the least significant limb */
  int left;
	
  for (left = n->_mp_size;
      (length > 0) && (left  > 0);
      left--)
    {
      int i;
      mp_limb_t word = *l++;
      for(i = 0; i<sizeof(mp_limb_t); i++)
	{
	  *dst-- = word & 0xff;
	  word >>= 8;
	  length--;
	  if (!length)
	    break;
	}
    }
  while (length > 0)
    {
      *dst-- = pad;
      length--;
    }
}

/* Formatting of signed numbers */
void bignum_parse_s(mpz_t n, UINT32 length, UINT8 *data)
{
  int negative = length && (*data & 0x80);
  int i;
  mpz_t digit;

  mpz_init(digit);
  mpz_set_ui(n, 0);
  for (i = 0; i < length; i++)
    {
      mpz_set_ui(digit, data[i]);
      mpz_mul_2exp(digit, digit, (length - i - 1) * 8);
      mpz_ior(n, n, digit);
    }
  if (negative)
    {
      mpz_set_ui(digit, 1);
      mpz_mul_2exp(digit, digit, length*8);
      mpz_sub(n, n, digit);
    }
  mpz_clear(digit);
}

int mpz_size_of_complement(mpz_t n)
{
  int bits;
	
  /* One's complement(x) = - x - 1 */
  mpz_t complement;
  mpz_init(complement);
  mpz_com(complement, n);
  
  /* Note that bits == 1 if complement == 0, i.e n = -1 */
  bits = mpz_sizeinbase(complement, 2);
  
  mpz_clear(complement);
  
  return bits;
}

/* This function should handle both positive and negative numbers */
UINT32 bignum_format_s_length(mpz_t n)
{
  switch(mpz_sgn(n))
    {
    case 0:
      return 0;
    case 1:
      return mpz_sizeinbase(n, 2)/8 + 1;
    case -1:
      return mpz_size_of_complement(n)/8 + 1;
    default:
      fatal("Internal error");
    }
}
  
UINT32 bignum_format_s(mpz_t n, UINT8 *data)
{
  switch(mpz_sgn(n))
    {
    case 0:
      return 0;
    case 1:
      {
	int length = mpz_sizeinbase(n, 2)/8 + 1;

	limbs_to_octets(n, length, 0, data);
	return length;
      }
    case -1:
      {
	mpz_t complement;
	int length;
	int i;
	
	mpz_init(complement);
	mpz_com(complement, n);

	/* Note that mpz_sizeinbase(0) == 0.*/
	length = mpz_sizeinbase(complement, 2)/8 + 1;
	
	for (i = 0; i<complement->_mp_size; i++)
	  complement->_mp_d[i] = ~complement->_mp_d[i];
	
	limbs_to_octets(complement, length, 0xff, data);

	mpz_clear(complement);
	return length;
      }
    default:
      fatal("Internal error");
    }
}

/* Formatting of unsigned numbers */
void bignum_parse_u(mpz_t n, UINT32 length, UINT8 *data)
{
  int i;
  mpz_t digit;

  mpz_init(digit);
  mpz_set_ui(n, 0);
  for (i = 0; i < length; i++)
    {
      mpz_set_ui(digit, data[i]);
      mpz_mul_2exp(digit, digit, (length - i - 1) * 8);
      mpz_ior(n, n, digit);
    }
  mpz_clear(digit);
}

UINT32 bignum_format_u_length(mpz_t n)
{
  switch(mpz_sgn(n))
    {
    case 0:
      return 0;
    case 1:
      return (mpz_sizeinbase(n, 2) + 7) / 8;
    default:
      fatal("Internal error: Negative number to bignum_format_u_length()\n");
    }
}

UINT32 bignum_format_u(mpz_t n, UINT8 *data)
{
  switch(mpz_sgn(n))
    {
    case 0:
      return 0;
    case 1:
      {
	int length = (mpz_sizeinbase(n, 2) + 7) / 8;

	limbs_to_octets(n, length, 0, data);
	return length;
      }
    default:
      fatal("Internal error: Negative number to bignum_format_u()\n");
    }
}

void bignum_random(mpz_t x, struct randomness *random, mpz_t n)
{
  /* Add a few bits extra */
  int length = (mpz_sizeinbase(n) + 17) / 8;
  UINT8 *data = alloca(length);

  RANDOM(random, length, data);

  bignum_parse_u(x, length, data);

  mpz_tdiv_r(x, x, n);
}
