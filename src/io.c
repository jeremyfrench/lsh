/* io.c
 *
 */

#include "io.h"
#include <unistd.h>
#include <poll.h>
#include <errno.h>

#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>

/* A little more than an hour */
#define MAX_TIMEOUT 4000

struct fd_read
{
  struct abstract_read a;
  int fd;
};

static int do_read(struct fd_read *closure, UINT8 *buffer, UINT32 length)
{
  return read(closure->fd, buffer, length);
};

void io_run(struct io_backend *b)
{
  while(1)
    {
      struct pollfd *fds;
      int i;
      nfds_t nfds;
      int timeout;
      int res;
      
      nfds = b->ninput + b->noutput + b->nlisten + n->nconnect;

      if (b->callouts)
	{
	  time_t now = time();
	  if (now >= b->callout->when)
	    timeout = 0;
	  else
	    {
	      if (b->callout->when > now + MAX_TIMEOUT)
		timeout = MAX_TIMEOUT * 1000;
	      else
		timeout = (b->callout->when - now) * 1000;
	    }
	}
      else
	{
	  if (!nfds)
	    /* All done */
	    break;
	  timeout = -1;
	}
      
      fds = alloca(sizeof(struct pollfd) * nfds);

      /* Handle fds in order: read, accept, connect, write, */
      i = 0;
      {
	struct input_fd *fd = b->input;
	for( ; fd; fd = fd->next, i++)
	  {
	    fds[i]->fd = fd->hold_on ? -1 : fd->fd;
	    fds[i]->events = POLLIN;
	  }
      }
      {
	struct accept_fd *fd = b->accept;
	for( ; fd; fd = fd->next, i++)
	  {
	    fds[i]->fd = fd->fd;
	    fds[i]->events = POLLIN;
	  }
      }
      {
	struct connect_fd *fd = b->connect;
	for( ; fd; fd = fd->next, i++)
	  {
	    fds[i]->fd = fd->fd;
	    fds[i]->events = POLLOUT;
	  }
      }
      {
	struct output_fd *fd = b->output;
	for( ; fd; fd = fd->next, i++)
	  {
	    write_buffer_pre_write(fd->buffer);

	    fds[i]->fd = fd->buffer->empty ? -1 : fd->fd;
	    fds[i]->events = POLLOUT;
	  }
      }

      res = poll(fds, nfds, timeout);

      if (!res)
	{
	  /* Timeout. Run the callout */
	  if (!CALLBACK(b->callouts->callout);)
	    fatal("What now?");
	  b->callouts = b->callouts->next;
	}
      if (res<0)
	{
	  switch(errno)
	    {
	    case EAGAIN:
	    case EINTR:
	      continue;
	    default:
	      fatal("io_run:poll failed: %s", strerror(errno));
	    }
	}
      else
	{ /* Process files */
	  i = 0;
	  {
	    struct input_fd *fd = b->input;
	    for( ; fd; fd = fd->next, i++)
	      {
		if (fds[i]->revents & POLLIN)
		  {
		    struct fd_read r =
		    { { (abstract_read_f) do_read }, fd->fd };
		    
		    if (!fd->callback->handler(fd->callback, &r))
		      /* FIXME: Remove fd, or close, or? */
		      fatal("What now?");
		  }
	      }
	  
	    {
	      struct accept_fd *fd = b->accept;
	      for( ; fd; fd = fd->next, i++)
		{
		  if (fds[i]->revents & POLLIN)
		    if (!CALLBACK(fd->callback))
		      fatal("What now?");
		}
	    }
	    {
	      struct connect_fd *fd = b->connect;
	      for( ; fd; fd = fd->next, i++)
		{
		  if (fds[i]->revents & POLLOUT)
		    if (!CALLBACK(fd->callback))
		      fatal("What now?");
		}
	    }
	    {
	      struct output_fd *fd = b->output;
	      for( ; fd; fd = fd->next, i++)
		{
		  if (fds[i]->revents & POLLOUT)
		    {
		      UINT32 size = MIN(fd->buffer->end - fd->buffer->start,
					fd->buffer->block_size);
		      int res = write(fd->fd, fd->buffer->data + fd->buffer->start,
				      size);
		      if (!res)
			fatal("Closed?");
		      if (res < 0)
			switch(errno)
			  {
			  case EINTR:
			  case EAGAIN:
			    break;
			  default:
			    CALLBACK(fd->close_Callback);
			  }
		      else
			fd->buffer->start += res;
		    }
		}
	    }
	  }
	}
    }
}

void io_set_nonblocking(int fd)
{
  if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0)
    fatal("io_set_nonblocking: fcntl() failed, %s", strerror(errno));
}

int io_connect(struct sockaddr *sa, struct callback *f)
{
  struct connect_fd *file;
  int fd = socket(AF_INET, SOCK_STREAM, ...);
  
  if (fd<0)
    fatal("io_connect: socket() failed, %s", strerror(errno));

  io_set_nonblocking(fd);

  if (connect(fd, sa, ...) < 0)
      ...;
      
  file = xalloc(sizeof(struct connect_fd));
  info->next = ...;
  info->fd = fd;

  /* FIXME: The fd must somehow be passed to the callback. */
  info->callback = callback;

  return info;
}

int io_listen()
     
  
  
