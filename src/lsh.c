/* lsh.c
 *
 * client main program
 */

#include <getopt.h>

#include "io.h"
#include "werror.h"
#include "client.h"

#define BLOCK_SIZE 32768

/* Global variable */
struct io_backend backend;

void usage() NORETURN;

void usage()
{
  exit(1);
}

int main(int argc, char **argv)
{
  char *host = NULL;
  char *port = "ssh";
  int verbose;
  int option;

  struct sockaddr_in remote;
  
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

  if ( (argc - optind) < 1)
    usage();

  host = argv[optind];

  if (!get_inaddr(&remote, host, port, "tcp"))
    {
      fprintf(stderr, "No such host or service");
      exit(1);
    }

  {
    struct client_callback connected = {
      { (fd_callback_f) client_initiate },
      &backend,
      BLOCK_SIZE;
    };

    io_connect(&backend, &remote, NULL,
	       make_client_callback(backend, BLOCK_SIZE));
  }
  
  io_run();

  return 0;
}

  
