/* client.h
 *
 * Utility functions for the client side of the protocol.
 *
 * $Id$
 */

#ifndef SFTP_CLIENT_H_INCLUDED
#define SFTP_CLIENT_H_INCLUDED

#include "buffer.h"

struct client_ctx
{
  struct sftp_input *i;
  struct sftp_output *o;

  /* Status from latest message. */
  UINT32 status;
};

/* Handles are strings, choosen by the server. */
struct client_handle
{
  UINT32 length;
  UINT8 *data;
};

/* Creates a file handle */
struct client_handle *
sftp_open(struct client_ctx *ctx,
	  const char *name,
	  UINT32 flags,
	  const struct sftp_attrib *a);

/* Destroys a file or directory handle */
int
sftp_close(struct client_ctx *ctx,
	   struct client_handle *handle);


#endif /* SFTP_CLIENT_H_INCLUDED */
