/* encrypt.h
 *
 * Processor to pad, encrypt and authenticate
 */

#ifndef LSH_ENCRYPT_H_INCLUDED
#define LSH_ENCRYPT_H_INCLUDED

#include "abstract_io.h"
#include "abstract_crypto.h"

struct packet_encrypt
{
  struct abstract_write_pipe super;

  UINT32 sequence_number;
  struct mac_instance *mac;
  struct crypto_instance *crypto;
};

struct abstract_write *
make_packet_encrypt(struct abstract_write *continuation,
		    struct mac_instance *mac,
		    struct crypto_instance *crypto);
		       
		    
#endif /* LSH_ENCRYPT_H_INCLUDED */
