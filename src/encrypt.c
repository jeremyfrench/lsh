/* encrypt.c */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 2003, 2004, 2005, Niels Möller
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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>

#include "nettle/macros.h"

#include "crypto.h"
#include "compress.h"
#include "format.h"
#include "lsh_string.h"

struct lsh_string *
encrypt_packet(struct lsh_string *packet, struct compress_instance *compress,
	       struct crypto_instance *crypt, struct mac_instance *mac,
	       struct randomness *random, uint32_t seqno)
{
  uint32_t block_size;
  uint32_t new_size;
  uint8_t padding_length;
  uint32_t padding;

  uint32_t mac_length;
  uint32_t mac_start;

  uint32_t length = lsh_string_length(packet);
  assert(length);
  
  /* Deflate, pad, mac, encrypt. */
  if (compress)
    {
      packet = CODEC(compress, packet, 1);
      assert(packet);
      length = lsh_string_length(packet);      
    }

  block_size = crypt ? crypt->block_size : 8;
  mac_length = mac ? mac->mac_size : 0;
  
  /* new_size is (length + 9) rounded up to a multiple of
   * block_size */
  new_size = block_size * (1 + (8 + length) / block_size);
  
  padding_length = new_size - length - 5;
  assert(padding_length >= 4);

  packet = ssh_format("%i%c%lfS%lr%lr",
		      length + padding_length + 1,
		      padding_length,
		      packet,
		      padding_length, &padding,
		      mac_length, &mac_start);

  assert(new_size + mac_length == lsh_string_length(packet));

  lsh_string_write_random(packet, padding, random, padding_length);

  if (mac)
    {
      uint8_t s[4];
      assert(new_size == mac_start);      

      WRITE_UINT32(s, seqno);
      MAC_UPDATE(mac, 4, s);
      MAC_UPDATE(mac, new_size, lsh_string_data(packet));
      MAC_DIGEST(mac, packet, mac_start);
    }
  if (crypt)
    CRYPT(crypt, new_size, packet, 0, packet, 0);

  return packet;
}
