/* io.h
 *
 */

#ifndef LSH_IO_H_INCLUDED
#define LSH_IO_H_INCLUDED

#include <time.h>
#include <netdb.h>

#include "abstract_io.h"
#include "write_buffer.h"

struct io_fd
{
  struct io_fd *next;
  int fd;

  int please_close;
  
  /* Reading */
  struct read_handler *handler;
  int on_hold; /* For flow control */

  /* Writing */
  struct write_buffer *buffer;
  struct callback *close_callback;
};

/* A closed function with a file descriptor as argument */
struct fd_callback;
typedef int (*fd_callback_f)(struct callback *closure, int fd);
struct fd_callback
{
  fd_callback_f f;
};

#define FD_CALLBACK(c, fd) ((c)->f(c, (fd)))

struct listen_fd
{
  struct listen_fd *next;
  int fd;
  struct fd_callback *callback;
};

struct connect_fd
{
  struct connect_fd *next;
  int fd;
  struct fd_callback *callback;

};
  
struct callout
{
  struct callout *next;
  struct callback *callout;
  time_t when;
  /* callback */
};

struct io_backend
{
  unsigned nio;
  struct io_fd *io;
  unsigned nlisten;
  struct listen_fd *listen;
  unsigned nconnect;
  struct connect_fd *connect;
  struct callout *callouts;
};

void io_run(struct io_backend *b);

int get_inaddr(struct sockaddr_in	* addr,
	       const char		* host,
	       const char		* service,
	       const char		* protocol);

void io_set_nonblocking(int fd);

struct connect_fd *io_connect(struct io_backend *b,
			      struct sockaddr_in *remote,
			      struct sockaddr_in *local,
			      struct fd_callback *f);

struct listen_fd *io_listen(struct io_backend *b,
			    struct sockaddr_in *local,
			    struct fd_callback *callback);


struct abstract_write *io_read_write(struct io_backend *b,
				     int fd,
				     struct read_handler *read_callback,
				     UINT32 block_size,
				     struct callback *close_callback);

#endif /* LSH_IO_H_INCLUDED */
