/* digit_table.c
 *
 * Generate the tables for reading hex and base64.
 *
 * $Id$ */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998 Niels M�ller
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

/* Defines int sexp_char_classes[0x100] */
#define CHAR_CLASSES_TABLE sexp_char_classes
#include "sexp_table.h"
#undef CHAR_CLASSES_TABLE
#include "sexp_table.h"

#include "lsh_types.h"

#include <stdio.h>

static void write_table(int *table)
{
  unsigned i;

  printf("{");
  for (i = 0; i<0x100; i++)
    {
      if (!(i % 16))
	printf("\n  ");
      printf("%2d", table[i]);
      if (i != 0xff)
	printf(",");
    }
  printf("\n}");
}

int main(int argc UNUSED, char **argv UNUSED)
{
  int table[0x100];
  unsigned i;
  const UINT8 base64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";
    
  printf("/* Automatically generated by digits_table.c.\n"
	 " * Do not edit. */\n\n");

  printf("#define HEX_INVALID -1\n");
  printf("#define HEX_END -2\n");

  for (i = 0; i<0x100; i++)
    table[i] = -1;

  for (i = 0; i <= 9; i++)
    table['0' + i] = i;

  table['#'] = -2;

  printf("static int hex_digits[0x100] =\n");
  write_table(table);
  printf(";\n\n");

  printf("#define BASE64_INVALID -1\n");
  printf("#define BASE64_END -2\n");
  printf("#define BASE64_SPACE -3\n");

  for (i = 0; i<0x100; i++)
    table[i] = (sexp_char_classes[i] & CHAR_base64_space)
		? -3 : -1;

  for(i = 0; i<64; i++)
    table[base64[i]] = i;

  printf("static int base64_digits[0x100] =\n");
  write_table(table);
  printf(";\n\n");

  return 0;
}
