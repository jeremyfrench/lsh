/* lshd.c
 *
 * main server program.
 */

#include <getopt.h>

#include "io.h"
#include "werror.h"
#include "server.h"

/* Global variable */
struct io_backend backend;

void usage() NORETURN;

void usage()
{
  exit(1);
}

int main(int argc, char **argv)
{
  char *port = "ssh";
  int verbose;
  int option;

  /* For filtering messages. Could perhaps also be used when converting
   * strings to and from UTF8. */
  setlocale(LC_CTYPE, "");
  
  while((option = getopt(argc, argv, "dp:q")) != -1)
    switch(option)
      {
      case 'p':
	port = optarg;
	break;
      case 'q':
	quiet_flag = 1;
	break;
      case 'd':
	debug_flag = 1;
	break;
      default:
	usage();
      }

  if ( (argc - optind) != 0)
    usage();

  if (!get_inaddr(&remote, NULL, port, "tcp"))
    {
      fprintf(stderr, "No such host or service");
      exit(1);
    }

  {
    struct server_callback connected = {
      { (fd_callback_f) server_initiate },
      &backend,
      BLOCK_SIZE;
    };

    io_connect(&backend, &remote, NULL,
	       make_client_callback(backend, BLOCK_SIZE));
  }
  
  io_run();

  return 0;
}
