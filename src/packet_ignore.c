/* packet_ignore.c
 *
 */

#include "packet_ignore.h"

#include "xalloc.h"

static int do_ignore(struct packet_handler *closure,
		     struct ssh_connection *connection,
		     struct lsh_string *packet)
{
  lsh_string_free(packet);
  return WRITE_OK;
}

struct packet_handler *make_ignore_handler(struct packet_handler *closure,
					   struct ssh_connection *connection,
					   struct lsh_string *packet)
{
  struct packet_handler *res =  xalloc(sizeof(struct packet_handler));

  res->handler = do_ignore;
  return res;
}

