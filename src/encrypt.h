/* encrypt.h
 *
 * Processor to pad, encrypt and authenticate
 */

#ifndef LSH_ENCRYPT_H_INCLUDED
#define LSH_ENCRYPT_H_INCLUDED

/* FIXME: Perhaps cryptographic algoritms should be encapsulated into
 * objects, to avoid passing a lot of extra state parameters? */

typedef (*transform_function)(void *state,
			      UINT32 size, UINT8 *src, UINT8 *dst);

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
