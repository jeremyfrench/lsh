/* client.c
 *
 * Utility functions for the client side of the protocol.
 *
 * $Id$
 */

#include "client.h"

#include "buffer.h"
#include "werror.h"
#include "xmalloc.h"

#include "sftp.h"

/* We never have several pending calls at once. */
static UINT32 
sftp_client_new_id(void)
{ return 17; }

static struct client_handle *
client_get_handle(struct sftp_input *i)
{
  UINT32 length;
  UINT8 *data;
  struct client_handle *handle;
  
  data = sftp_get_string(i, &length);
  if (!data)
    fatal("Protocol error, client_get_handle");

  handle = xmalloc(sizeof(*handle));
  handle->length = length;
  handle->data = data;

  return handle;
}

static UINT8
client_get_msg(struct client_ctx *ctx, UINT32 expected)
{
  UINT8 msg;
  UINT32 id;
  
  if (sftp_get_uint8(ctx->i, &msg)
      && sftp_get_uint32(ctx->i, &id)
      && (expected == id))
    return msg;
  
  else
    fatal("Protocol error, client_get_msg");
}

static UINT32
client_get_status(struct client_ctx *ctx, UINT32 id)
{
  UINT32 status;
  
  if ( (client_get_msg(ctx, id) == SSH_FXP_STATUS)
       && sftp_get_uint32(ctx->i, &status))
    return status;
  
  else
    fatal("Protocol error, client_get_status");
}

static void
client_put_handle(struct client_ctx *ctx, struct client_handle *handle)
{
  sftp_put_string(ctx->o, handle->length, handle->data);
}

/* Creates a file handle */
  struct client_handle *
sftp_open(struct client_ctx *ctx,
	  const char *name,
	  UINT32 flags,
	  const struct sftp_attrib *a)
{
  UINT8 msg;
  UINT32 id = sftp_client_new_id();
  
  /* Send a OPEN message */
  sftp_set_msg(ctx->o, SSH_FXP_OPEN);
  sftp_set_id(ctx->o, id);
  sftp_put_string(ctx->o, strlen(name), name );
  sftp_put_uint32(ctx->o, flags);
  sftp_put_attrib(ctx->o, a);

  if (!sftp_write_packet(ctx->o))
    return 0;

  if (sftp_read_packet(ctx->i) <= 0)
    return 0;

  msg = client_get_msg(ctx, id);

  switch (msg)
    {
    case SSH_FXP_HANDLE:
      return client_get_handle(ctx->i);
    case SSH_FXP_STATUS:
      if (!sftp_get_uint32(ctx->i, &ctx->status))
	fatal("Protocol error, sftp_open");
      return NULL;
    default:
      fatal("Unexpected message from server.");
    }
}

/* Destroys a file or directory handle */
int
sftp_close(struct client_ctx *ctx,
	   struct client_handle *handle)
{
  UINT32 id = sftp_client_new_id();

  sftp_set_msg(ctx->o, SSH_FXP_CLOSE); /* Send a close message */
  sftp_set_id(ctx->o, id);
  client_put_handle(ctx, handle);

  if (!sftp_write_packet(ctx->o))
    return 0;

  if (sftp_read_packet(ctx->i) <= 0)
    return 0;

  /* None of these may fail */
  ctx->status = client_get_status(ctx, id);

  return (ctx->status == SSH_FX_OK);
}


