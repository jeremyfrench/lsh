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
  char *host = NULL;  /* Interface to bind */
  char *port = "ssh";
  int verbose;
  int option;

  struct sockaddr_in local;
    
  /* For filtering messages. Could perhaps also be used when converting
   * strings to and from UTF8. */
  setlocale(LC_CTYPE, "");
  
  while((option = getopt(argc, argv, "dp:qi:")) != -1)
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
      case 'i':
	host = optarg;
	break;
      default:
	usage();
      }

  if ( (argc - optind) != 0)
    usage();

  if (!get_inaddr(&local, host, port, "tcp"))
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

    io_listen(&backend, &local, 
	      make_server_callback(backend, BLOCK_SIZE));
  }
  
  io_run();

  return 0;
}
