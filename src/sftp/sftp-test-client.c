/* sftp-test-client.c
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

#define FATAL(x) do { fputs("sftp-test-client: " x "\n", stderr); exit(EXIT_FAILURE); } while (0)
#define _FATAL(x) do { fputs("sftp-test-client: " x "\n", stderr); _exit(EXIT_FAILURE); } while (0)

struct client_ctx
{
  struct sftp_input *i;
  struct sftp_output *o;
};

static void
fork_server(char *name,
	    struct client_ctx *ctx)
{
  /* [0] for reading, [1] for writing */
  int stdin_pipe[2];
  int stdout_pipe[2];

  if (pipe(stdin_pipe) < 0)
    FATAL("Creating stdin_pipe failed.");

  if (pipe(stdout_pipe) < 0)
    FATAL("Creating stdout_pipe failed.");

  switch(fork())
    {
    case -1:
      FATAL("fork failed.");
    default: /* Parent */
      {
	FILE *i;
	FILE *o;

	close(stdin_pipe[0]);
	close(stdout_pipe[1]);
	
	i = fdopen(stdout_pipe[0], "r");
	if (!i)
	  FATAL("fdopen stdout_pipe failed.");

	o = fdopen(stdin_pipe[1], "w");
	if (!o)
	  FATAL("fdopen stdin_pipe failed.");

	ctx->i = sftp_make_input(i);
	ctx->o = sftp_make_output(o);

	return;
      }
    case 0: /* Child */
      if (dup2(stdin_pipe[0], STDIN_FILENO) < 0)
	_FATAL("dup2 for stdin failed.");
      if (dup2(stdout_pipe[1], STDOUT_FILENO) < 0)
	_FATAL("dup2 for stdout failed.");
	
      close(stdin_pipe[0]);
      close(stdin_pipe[1]);
      close(stdout_pipe[0]);
      close(stdout_pipe[1]);
      
      execl(name, name, NULL);

      _FATAL("execl failed.");
    }
}

/* The handshake packets are special, because they don't include any
 * request id. */
int
client_handshake(struct client_ctx *ctx)
{
  UINT8 msg;
  UINT32 version;

  sftp_set_msg(ctx->o, SSH_FXP_INIT);
  sftp_set_id(ctx->o, SFTP_VERSION);

  if (!sftp_write_packet(ctx->o))
    return 0;

  if (sftp_read_packet(ctx->i) <= 0)
    return 0;

  return (sftp_get_uint8(ctx->i, &msg)
	  && (msg == SSH_FXP_VERSION)
	  && sftp_get_uint32(ctx->i, &version)
	  && (version == SFTP_VERSION)
	  && sftp_get_eod(ctx->i));
}   
  
int main(int argc, char **argv)
{
  struct client_ctx ctx;
  if (argc != 2)
    FATAL("Bad args.");

  fork_server(argv[1], &ctx);

  if (!client_handshake(&ctx))
    FATAL("Handshake failed.");

  return EXIT_SUCCESS;
}
