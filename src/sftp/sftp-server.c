/* sftp-server.c
 *
 */

#include "buffer.h"
#include "sftp.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include <sys/stat.h>

#define SFTP_VERSION 3

#define FATAL(x) do { fputs("sftp-server: " x "\n", stderr); exit(EXIT_FAILURE); } while (0)

struct sftp_attrib
{
  UINT32 flags;
  UINT64 size;
  UINT32 uid;
  UINT32 gid;
  UINT32 permissions;

  /* NOTE: The representations of times is about to change. */
  UINT32 atime;
  UINT32 mtime;
};

static void
sftp_clear_attrib(struct sftp_attrib *a)
{
  a->flags = 0;
  a->size = 0;
  a->uid = 0;
  a->gid = 0;
  a->permissions = 0;
  a->atime = 0;
  a->mtime = 0;
};

int
sftp_skip_extension(struct sftp_input *i)
{
  UINT32 length;
  UINT8 *data;
  unsigned j;
  
  /* Skip name and value*/
  for (j = 0; j<2; j++)
    {
      if (!(data = sftp_get_string(i, &length)))
	return 0;
      
      sftp_free_string(data);
    }
  return 1;
}

int
sftp_get_attrib(struct sftp_input *i, struct sftp_attrib *a)
{
  sftp_clear_attrib(a);
  
  if (!sftp_get_uint32(i, &a->flags))
    return 0;

  if (a->flags & SSH_FILEXFER_ATTR_SIZE)
    {
      if (!sftp_get_uint64(i, &a->size))
	return 0;
    }

  if (a->flags & SSH_FILEXFER_ATTR_UIDGID)
    {
      if (!sftp_get_uint32(i, &a->uid))
	return 0;

      if (!sftp_get_uint32(i, &a->gid))
	return 0;
    }

  if (a->flags & SSH_FILEXFER_ATTR_PERMISSIONS)
    {
      if (!sftp_get_uint32(i, &a->permissions))
	return 0;
    }

  if (a->flags & SSH_FILEXFER_ATTR_ACMODTIME)
    {
      if (!sftp_get_uint32(i, &a->atime))
	return 0;

      if (!sftp_get_uint32(i, &a->mtime))
	return 0;
    }

  if (a->flags & SSH_FILEXFER_ATTR_EXTENDED)
    {
      UINT32 count;
      UINT32 n;

      if (!sftp_get_uint32(i, &count))
	return 0;

      /* Just skip the extensions */
      for (n = 0; n < count; n++)
	if (!sftp_skip_extension(i))
	  return 0;
    }
  return 1;
}

void
sftp_put_attrib(struct sftp_output *o, const struct sftp_attrib *a)
{
  assert(!a->flags & SSH_FILEXFER_ATTR_EXTENDED);
  
  sftp_put_uint32(o, a->flags);

  if (a->flags & SSH_FILEXFER_ATTR_SIZE)
    sftp_put_uint64(o, a->size);

  if (a->flags & SSH_FILEXFER_ATTR_UIDGID)
    {
      sftp_put_uint32(o, a->uid);
      sftp_put_uint32(o, a->gid);
    }

  if (a->flags & SSH_FILEXFER_ATTR_PERMISSIONS)
    sftp_put_uint32(o, a->permissions);

  if (a->flags & SSH_FILEXFER_ATTR_ACMODTIME)
    {
      sftp_put_uint32(o, a->atime);
      sftp_put_uint32(o, a->mtime);
    }
}

#define SFTP_MAX_FDS 200

/* A handle is simply an fd */
#define handle_t UINT32

struct sftp_ctx
{
  struct sftp_input *i;
  struct sftp_output *o;
  
  enum sftp_handle_type
  { HANDLE_UNUSED = 0, HANDLE_FILE, HANDLE_DIR } handles[SFTP_MAX_FDS];
};

void
sftp_init(struct sftp_ctx *ctx, FILE *in, FILE *out)
{
  struct sftp_input *input;
  struct sftp_output *output;
  unsigned i;

  if (!(input = sftp_make_input(stdin)))
    FATAL("sftp_make_input failed");

  if (!(output = sftp_make_output(stdout)))
    FATAL("sftp_make_input failed");

  ctx->i = input;
  ctx->o = output;

  for (i = 0; i < SFTP_MAX_FDS; i++)
    ctx->handles[i] = HANDLE_UNUSED;
}

int 
sftp_handle_used(struct sftp_ctx *ctx, handle_t handle)
{
  return (handle < SFTP_MAX_FDS)
    && (ctx->handles[handle] != HANDLE_UNUSED);
}

void
sftp_register_handle(struct sftp_ctx *ctx,
		     UINT32 handle,
		     enum sftp_handle_type type)
{
  assert(handle < SFTP_MAX_FDS);
  assert(ctx->handles[handle] == HANDLE_UNUSED);
  assert(type != HANDLE_UNUSED);

  ctx->handles[handle] = type;
}

int
sftp_get_handle(struct sftp_ctx *ctx, handle_t *handle)
{
  UINT32 length;
  UINT32 value;
  
  if ((sftp_get_uint32(ctx->i, &length))
      && (length == 4)
      && sftp_get_uint32(ctx->i, &value)
      && sftp_handle_used(ctx, value))
    {
      *handle = value;
      return 1;
    }
  return 0;
}

void
sftp_put_handle(struct sftp_ctx *ctx, handle_t handle)
{
  sftp_put_uint32(ctx->o, 4);
  sftp_put_uint32(ctx->o, handle);
}

/* NOTE: The status message should be expanded with a human-readable
 * message and a language tag. */
int
sftp_send_status(struct sftp_ctx *ctx, UINT32 status)
{
  sftp_set_msg(ctx->o, SSH_FXP_STATUS);
  sftp_put_uint32(ctx->o, status);
  return 1;
}

int
sftp_send_errno(struct sftp_ctx *ctx)
{
  UINT32 status;
  
  switch(errno)
    {
    case ENOENT:
      status = SSH_FX_NO_SUCH_FILE;
      break;
    case EACCES:
      status = SSH_FX_PERMISSION_DENIED;
      break;
    default:
      status = SSH_FX_FAILURE;
      break;
    }
  return sftp_send_status(ctx, status);
}

int
sftp_bad_message(struct sftp_ctx *ctx)
{
  sftp_send_status(ctx, SSH_FX_BAD_MESSAGE);
  return 0;
}

typedef int sftp_process_func(struct sftp_ctx *ctx);

static int
sftp_process_unsupported(struct sftp_ctx *ctx)
{
  return sftp_bad_message(ctx);
}

/* A filename must not contain any NUL-characters. */
static int
sftp_check_filename(UINT32 length, const UINT8 *data)
{
  return !memchr(data, 0, length);
}

static int
sftp_process_open(struct sftp_ctx *ctx)
{
  UINT32 length;
  UINT8 *name;
  UINT32 pflags;
  struct sftp_attrib a;

  if ((name = sftp_get_string(ctx->i, &length))
      && sftp_get_uint32(ctx->i, &pflags)
      && sftp_get_attrib(ctx->i, &a))
    {
      /* Empty name is a synonym to ".", which isn't a file. */
      if (length && sftp_check_filename(length, name))
	{
	  int fd;
	  int mode;
	  struct stat sb;
	  
	  switch (pflags & (SSH_FXF_READ | SSH_FXF_WRITE))
	    {
	    case 0:
	      sftp_send_status(ctx, SSH_FX_FAILURE);
	      return 1;
	    case SSH_FXF_READ:
	      mode = O_RDONLY;
	      break;
	    case SSH_FXF_WRITE:
	      mode = O_WRONLY;
	      break;
	    case SSH_FXF_READ | SSH_FXF_WRITE:
	      mode = O_RDWR;
	      break;
	    default:
	      abort();
	    }
	  if (pflags & SSH_FXF_APPEND)
	    mode |= O_APPEND;

	  if (pflags & SSH_FXF_CREAT)
	    mode |= O_CREAT;
	  else if (pflags & SSH_FXF_EXCL)
	    /* We can't have EXCL without CREAT. */
	    sftp_send_status(ctx, SSH_FX_FAILURE);
	  
	  if (pflags & SSH_FXF_TRUNC)
	    mode |= O_TRUNC;
	  if (pflags & SSH_FXF_EXCL)
	    mode |= O_EXCL;

	  /* Look at the atributes. For now, we care only about the
	   * permission bits. */
	  if (a.flags & SSH_FILEXFER_ATTR_PERMISSIONS)
	    {
	      /* Use the client's permission bits with no umask filtering */
	      mode_t old = umask(0);
	      fd = open(name, mode, a.permissions);
	      umask(old);
	    }
	  else
	    /* Default flags, filtered through our umask */
	    fd = open(name, mode, 0666);

	  if (fd < 0)
	    return sftp_send_errno(ctx);

	  if (fd > SFTP_MAX_FDS)
	    {
	      close(fd);
	      return sftp_send_status(ctx, SSH_FX_FAILURE);
	    }

	  if (fstat(fd, &sb) < 0)
	    {
	      close(fd);
	      return sftp_send_errno(ctx);
	    }

	  if (S_ISDIR(sb.st_mode))
	    {
	      close(fd);
	      return sftp_send_status(ctx, SSH_FX_NO_SUCH_FILE);
	    }

	  /* Open successful */
	  sftp_register_handle(ctx, fd, HANDLE_FILE);
	  sftp_put_handle(ctx, fd);
	  return 1;
	}
      else
	return sftp_send_status(ctx, SSH_FX_NO_SUCH_FILE);
    }
  else
    return sftp_bad_message(ctx);
}

static void
sftp_process(sftp_process_func **dispatch,
	     struct sftp_ctx *ctx)
{
  UINT8 msg;
  UINT32 id;
  
  int ok;

  switch (sftp_read_packet(ctx->i))
    {
    case 1:
      break;
    case 0:
      exit(EXIT_FAILURE);
    case -1: /* EOF */
      exit(EXIT_SUCCESS);
    }
  
  /* All packets start with a msg byte and a 32-bit id. */
  if (!sftp_get_uint8(ctx->i, &msg))
    FATAL("Invalid packet.");

  if (!sftp_get_uint32(ctx->i, &id))
    FATAL("Invalid packet.");

  /* Every reply starts with the id, so copy it through */
  sftp_set_id(ctx->o, id);
    
  /* Calls FATAL on protocol errors. */
  ok = dispatch[msg](ctx);
    
  /* Every handler should result in at least one message */
  if (!sftp_write_packet(ctx->o))
    exit(EXIT_FAILURE);
  
  if (!ok)
    exit(EXIT_FAILURE);
}  

/* The handshake packets are special, because they don't include any
 * request id. */
int
sftp_handshake(struct sftp_ctx *ctx)
{
  UINT8 msg;
  UINT32 version;
  
  if (sftp_read_packet(ctx->i) <= 0)
    return 0;

  if (sftp_get_uint8(ctx->i, &msg)
      && (msg == SSH_FXP_INIT)
      && sftp_get_uint32(ctx->i, &version))
    {
      while (!sftp_get_eod(ctx->i))
	if (!sftp_skip_extension(ctx->i))
	  return 0;

      if (version < SFTP_VERSION)
	return 0;

      /* The VERSION message puts the version number where
       * the id is usually located. */

      sftp_set_msg(ctx->o, SSH_FXP_VERSION);
      sftp_set_id(ctx->o, SFTP_VERSION);

      return sftp_write_packet(ctx->o);
    }
  return 0;
}

int
main(int argc, char **argv)
{
  unsigned i;
  
  struct sftp_ctx ctx;
  sftp_process_func *dispatch[0x100];

  sftp_init(&ctx, stdin, stdout);

  if (!sftp_handshake(&ctx))
    return EXIT_FAILURE;
  
  for (i = 0; i<0x100; i++)
    dispatch[i] = sftp_process_unsupported;
  
  dispatch[SSH_FXP_OPEN] = sftp_process_open;
  
  for(;;)
    sftp_process(dispatch, &ctx);
}
