/* io.h
 *
 */

#ifndef LSH_IO_H_INCLUDED
#define LSH_IO_H_INCLUDED

#include "abstract_io.h"
#include "write_buffer"

struct input_fd
{
  struct input_fd *next;
  int fd;
  struct read_handler *callback;
  int on_hold; /* For flow control */
};

struct output_fd
{
  struct output_fd *next;
  int fd;
  struct write_buffer *buffer;
  struct callback close_callback;
};

struct listen_fd
{
  struct listen_fd *next;
  int fd;
  struct callback *callback;
};

struct connect_fd
{
  struct connect_fd *next;
  int fd;
  struct callback *callback;

};
  
struct callout
{
  struct callout_info *next;
  struct callback *callout;
  time_t when;
  /* callback */
};

struct io_backend
{
  unsigned ninput;
  struct input_fd *input;
  unsigned noutput;
  struct output_fd *output;
  unsigned nlisten;
  struct listen_fd *listen;
  unsigned nconnect;
  struct connect_fd *connect;
  struct callout *callouts;
};

#endif /* LSH_IO_H_INCLUDED */
