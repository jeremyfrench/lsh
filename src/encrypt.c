/* encrypt.c
 *
 */

#include "encrypt.h"
#include "xalloc.h"

static int do_encrypt(struct abstract_write **w,
		      struct lsh_string *packet)
{
  struct packet_encrypt *closure
    = (struct packet_encrypt *) *w;
  
  /* FIXME: Use ssh_format() */
  struct lsh_string *new
    = lsh_string_alloc(packet->length + closure->mac->mac_size);

  CRYPT(closure->crypto, packet->length, packet->data, new->data);

  if (closure->mac->mac_size)
  {
    UINT8 s[4];
    WRITE_UINT32(s, closure->sequence_number);

    closure->sequence_number++;
    
    HASH_UPDATE(closure->mac, 4, s);
    HASH_UPDATE(closure->mac, packet->length, packet->data);
    HASH_DIGEST(closure->mac, new->data + packet->length);
  }
  lsh_string_free(packet);

  return A_WRITE(closure->super.next, new);
}

struct abstract_write *
make_packet_encrypt(struct abstract_write *continuation,
		    struct mac_instance *mac,
		    struct crypto_instance *crypto)
{
  struct packet_encrypt *closure = xalloc(sizeof(struct packet_encrypt));

  closure->super.super.write = do_encrypt;
  closure->super.next = continuation;
  closure->sequence_number = 0;
  closure->mac = mac;
  closure->crypto = crypto;

  return &closure->super.super;
}

    
