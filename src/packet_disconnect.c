/* packet_disconnect.c
 *
 */

#include "packet_disconnect.h"

#include "parse.h"
#include "ssh.h"
#include "xalloc.h"

static int do_disconnect(struct packet_handler *closure,
			 struct ssh_connection *connection,
			 struct lsh_string *packet)
{
  struct simple_buffer buffer;
  UINT8 msg;
  UINT32 length;
  UINT32 reason;
  UINT8 *start;
  
  simple_buffer_init(&buffer, packet->length, packet->data);

  if (parse_uint8(&buffer, &msg)
      && (msg != SSH_MSG_DISCONNECT)
      && (parse_uint32(&buffer, &reason))
      && (parse_string(&buffer, &length, &start))
      /* FIXME: Language tag is ignored */ )
    {
      /* FIXME: Display message */
    }
  lsh_string_free(packet);
  
  /* FIXME: Mark the file as closed, somehow (probably a variable in
   * the write buffer) */

  return WRITE_CLOSED;
}

struct packet_handler *make_disconnect_handler()
{
  struct packet_handler *res =  xalloc(sizeof(struct packet_handler));

  res->handler = do_disconnect;
  return res;
}
  
