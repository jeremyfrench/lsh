/* server.h
 *
 */

#ifndef LSH_SERVER_H_INCLUDED
#define LSH_SERVER_H_INCLUDED

#include "io.h"

struct server_callback
{
  struct fd_callback super;
  struct io_backend *backend;
  UINT32 block_size;
  char *id_comment;
};

struct fd_callback *make_server_callback(struct io_backend *b,
					 char *comment,
					 UINT32 block_size);

#endif /* LSH_SERVER_H_INCLUDED */
