/* connection.c
 *
 */

#include "connection.h"
#include "xalloc.h"
#include "ssh.h"
#include "format.h"

static int handle_connection(struct abstract_write **w,
			     struct lsh_String *packet)
{
  struct ssh_connection *closure = (struct ssh_connection *) *w;

  /* First handle special messages: debug, ignore, disconnect, ... */

  /* Next see if we are expecting a newkey message */

  /* Dispatch by packet type, and later by channel number */

  
}

struct abstract_write *make_ssh_connection()
{
  struct ssh_connection *connection = xalloc(sizeof(struct ssh_connection));

  connection->super.write = handle_connection;
  connection->max_packet = 0x8000;

  return connection;
}

static int handle_unimplemented(struct abstract_write **w,
				struct lsh_string *packet)
{
  struct abstract_write_pipe *closure = (struct abstract_write_pipe *) *w;

  return A_WRITE(closure->next,
		 ssh_format("%c%i",
			    SSH_MSG_UNIMPLEMENTED,
			    packet->sequence_number));
}

struct abstract_write *make_unimplemented(struct abstract_write *w)
{
  struct abstract_write_pipe *res = xalloc(sizeof(struct abstract_write_pipe));

  res->super.write = handle_unimplemented;
  res->next = w;

  return &res->super;
}


  
