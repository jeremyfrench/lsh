/* encrypt.h
 *
 * Processor to pad, encrypt and authenticate
 */

#ifndef LSH_ENCRYPT_H_INCLUDED
#define LSH_ENCRYPT_H_INCLUDED

#include "transport.h"
#include "abstract_crypto.h"

struct encrypt_processor
{
  struct abstract_write_pipe c;

  struct mac_instance *mac;
  stryct crypto_instance *crypto;
};

struct abstract_write *
make_encrypt_processor(struct abstract_write *continue,
		       unsigned mac_size,
		       transform_function mac_function,
		       void *mac_state,
		       transform_function encrypt_function,
		       void *encrypt_state);
		       
		    
#endif /* LSH_ENCRYPT_H_INCLUDED */
