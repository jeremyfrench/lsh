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
  char *id_comment;
};

struct fd_callback *make_client_callback(struct io_backend *b,
					 char *comment,
					 UINT32 block_size);

#if 0
struct client_session
{
  struct read_handler handler;
  UINT32 *
#endif
  
#endif /* LSH_CLIENT_H_INCLUDED */
