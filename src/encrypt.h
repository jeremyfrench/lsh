/* encrypt.h
 *
 * Processor to pad, encrypt and authenticate
 */

#ifndef LSH_ENCRYPT_H_INCLUDED
#define LSH_ENCRYPT_H_INCLUDED

#include "transport.h"
#include "crypto_common.h"

struct encrypt_processor
{
  struct chained_processor c;

  unsigned mac_size;

  transform_function mac_function;
  void *mac_state;
  
  transform_function encrypt_function;
  void *encrypt_state;
};

struct packet_processor *
make_encrypt_processor(struct packet_processor *containing,
		       unsigned mac_size,
		       transform_function mac_function,
		       void *mac_state,
		       transform_function encrypt_function,
		       void *encrypt_state);
		       
		    
#endif /* LSH_ENCRYPT_H_INCLUDED */
