/* connection.c
 *
 */

#include "connection.h"
#include "xalloc.h"

struct ssh_connection *ssh_connection_alloc()
{
  struct ssh_connection *connection = xalloc(sizeof(struct ssh_connection));

  memset(connection, 0, sizeof(struct ssh_connection));

  connection->max_packet = 0x8000;

  return connection;
}
