/* client.h
 *
 */

#ifndef LSH_CLIENT_H_INCLUDED
#define LSH_CLIENT_H_INCLUDED

#include "io.h"

struct client_callback
{
  struct fd_callback c;
  struct io_backend *backend;
  UINT32 block_size;
};

struct fd_callback *make_client_callback(struct io_backend *b,
					 UINT32 block_size);

struct client_session
{
  struct read_handler handler;
  UINT32 *
#endif /* LSH_CLIENT_H_INCLUDED */
