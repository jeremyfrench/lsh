/* connection.c
 *
 */

#include "connection.h"

#include "format.h"
#include "packet_disconnect.h"
#include "packet_ignore.h"

#include "ssh.h"
#include "werror.h"
#include "xalloc.h"

static int handle_connection(struct abstract_write **w,
			     struct lsh_string *packet)
{
  struct ssh_connection *closure = (struct ssh_connection *) *w;
  UINT8 msg;
  
  if (!packet->length)
    {
      werror("connection.c: Recieved empty packet!\n");
      return 0;
    }

  msg = packet->data[0];

  if (closure->ignore_one_packet)
    {
      closure->ignore_one_packet = 0;
      lsh_string_free(packet);
      return WRITE_OK;
    }
  
  return HANDLE_PACKET(closure->dispatch[msg], closure, packet);
}

static int do_fail(struct packet_handler *closure,
			 struct ssh_connection *connection,
			 struct lsh_string *packet)
{
  lsh_string_free(packet);
  return WRITE_CLOSED;
}

struct packet_handler * make_fail_handler()
{
  struct packet_handler *res =  xalloc(sizeof(struct packet_handler));

  res->handler = do_fail;
  return res;
}

static int do_unimplemented(struct packet_handler *closure,
			    struct ssh_connection *connection,
			    struct lsh_string *packet)
{
  int res =  A_WRITE(connection->write,
		     ssh_format("%c%i",
				SSH_MSG_UNIMPLEMENTED,
				packet->sequence_number));
  lsh_string_free(packet);
  return res;
}

struct packet_handler * make_unimplemented_handler()
{
  struct packet_handler *res =  xalloc(sizeof(struct packet_handler));

  res->handler = do_unimplemented;
  return res;
}


struct ssh_connection *make_ssh_connection(struct packet_handler *kex_handler)
{
  struct ssh_connection *connection = xalloc(sizeof(struct ssh_connection));
  int i;
  
  connection->super.write = handle_connection;
  connection->max_packet = 0x8000;

  connection->ignore = make_ignore_handler();
  connection->unimplemented = make_unimplemented_handler();
  connection->fail = make_fail_handler();
  
  for (i = 0; i < 0x100; i++)
    connection->dispatch[i] = connection->unimplemented;

  connection->dispatch[0] = connection->fail;
  connection->dispatch[SSH_MSG_DISCONNECT] = make_disconnect_handler();
  connection->dispatch[SSH_MSG_IGNORE] = connection->ignore;
  connection->dispatch[SSH_MSG_UNIMPLEMENTED] = connection->ignore;

  /* FIXME: Write a debug handler */
  connection->dispatch[SSH_MSG_DEBUG] = connection->ignore;

  connection->dispatch[SSH_MSG_KEXINIT] = kex_handler;

  /* Make all other known message types terminate the connection */

  connection->dispatch[SSH_MSG_SERVICE_REQUEST] = connection->fail;
  connection->dispatch[SSH_MSG_SERVICE_ACCEPT] = connection->fail;
  connection->dispatch[SSH_MSG_NEWKEYS] = connection->fail;
  connection->dispatch[SSH_MSG_KEXDH_INIT] = connection->fail;
  connection->dispatch[SSH_MSG_KEXDH_REPLY] = connection->fail;
  connection->dispatch[SSH_MSG_USERAUTH_REQUEST] = connection->fail;
  connection->dispatch[SSH_MSG_USERAUTH_FAILURE] = connection->fail;
  connection->dispatch[SSH_MSG_USERAUTH_SUCCESS] = connection->fail;
  connection->dispatch[SSH_MSG_USERAUTH_BANNER] = connection->fail;
  connection->dispatch[SSH_MSG_USERAUTH_PK_OK] = connection->fail;
  connection->dispatch[SSH_MSG_USERAUTH_PASSWD_CHANGEREQ] = connection->fail;
  connection->dispatch[SSH_MSG_GLOBAL_REQUEST] = connection->fail;
  connection->dispatch[SSH_MSG_REQUEST_SUCCESS] = connection->fail;
  connection->dispatch[SSH_MSG_REQUEST_FAILURE] = connection->fail;
  connection->dispatch[SSH_MSG_CHANNEL_OPEN] = connection->fail;
  connection->dispatch[SSH_MSG_CHANNEL_OPEN_CONFIRMATION] = connection->fail;
  connection->dispatch[SSH_MSG_CHANNEL_OPEN_FAILURE] = connection->fail;
  connection->dispatch[SSH_MSG_CHANNEL_WINDOW_ADJUST] = connection->fail;
  connection->dispatch[SSH_MSG_CHANNEL_DATA] = connection->fail;
  connection->dispatch[SSH_MSG_CHANNEL_EXTENDED_DATA] = connection->fail;
  connection->dispatch[SSH_MSG_CHANNEL_EOF] = connection->fail;
  connection->dispatch[SSH_MSG_CHANNEL_CLOSE] = connection->fail;
  connection->dispatch[SSH_MSG_CHANNEL_REQUEST] = connection->fail;
  connection->dispatch[SSH_MSG_CHANNEL_SUCCESS] = connection->fail;
  connection->dispatch[SSH_MSG_CHANNEL_FAILURE] = connection->fail;
  
  return connection;
}
