/* lsh.c
 *
 * client main program
 */

#include <stdio.h>
#include <locale.h>

#include "getopt.h"

#include "io.h"
#include "werror.h"
#include "client.h"
#include "format.h"
#include "crypto.h"
#include "xalloc.h"

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
  int option;

  struct lsh_string *random_seed;
  
  struct sockaddr_in remote;

  /* For filtering messages. Could perhaps also be used when converting
   * strings to and from UTF8. */
  setlocale(LC_CTYPE, "");
  
  while((option = getopt(argc, argv, "dp:qv")) != -1)
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
      case 'v':
	verbose_flag = 1;
	break;
      default:
	usage();
      }

  if ( (argc - optind) < 1)
    usage();

  host = argv[optind];

  if (!get_inaddr(&remote, host, port, "tcp"))
    {
      fprintf(stderr, "No such host or service\n");
      exit(1);
    }

  random_seed = ssh_format("%z", "gazonk");
  
  io_connect(&backend, &remote, NULL,
	     make_client_callback(&backend,
				  "lsh - a free ssh",
				  BLOCK_SIZE,
				  make_poor_random(&sha_algorithm,
						   random_seed)));

  lsh_string_free(random_seed);
  
  io_run(&backend);

  return 0;
}

  
