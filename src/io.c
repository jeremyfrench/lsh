/* io.c
 *
 *
 *
 * $Id$ */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998 Niels Möller
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <assert.h>
#include <string.h>

#include <unistd.h>
#include <poll.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <signal.h>

#include "io.h"
#include "werror.h"
#include "write_buffer.h"
#include "xalloc.h"

/* A little more than an hour */
#define MAX_TIMEOUT 4000

struct fd_read
{
  struct abstract_read super;
  int fd;
};

static int do_read(struct abstract_read **r, UINT32 length, UINT8 *buffer)
{
  struct fd_read *closure
    = (struct fd_read *) *r;

  MDEBUG(closure);
  
  while(1)
    {
      int res = read(closure->fd, buffer, length);
      if (!res)
	return A_EOF;
      if (res > 0)
	return res;

      switch(errno)
	{
	case EINTR:
	  continue;  /* FIXME: Is it really worth looping here,
		      * instead of in the select loop? */
	case EWOULDBLOCK:  /* aka EAGAIN */
	  return 0;
	default:
	  werror("io.c: do_read: read() failed (errno %d), %s\n",
		 errno, strerror(errno));
	  debug("  fd = %d, buffer = %p, length = %ud\n",
		closure->fd, buffer, length);
	  return A_FAIL;
	}
    }
}

#define FOR_FDS(type, fd, list, extra)				\
{								\
  type **(_fd);							\
  type *(fd);							\
  for(_fd = &(list); ((fd) = *_fd); (extra)) {


#define END_FOR_FDS _fd = &(*_fd)->next; } }

/* UNLINK_FD must be followed by a continue, to avoid updating _fd */
#define UNLINK_FD (*_fd = (*_fd)->next)

static void close_fd(struct io_fd *fd)
{
  /* FIXME: The value returned from the close callback could be used
   * to choose an exit code. */
  if (fd->close_callback && fd->close_reason)
    (void) CLOSE_CALLBACK(fd->close_callback, fd->close_reason);
  
  close(fd->fd);

  /* Make sure writing to the buffer fails. */
  if (fd->buffer)
    write_buffer_close(fd->buffer);
  
  /* There can be other objects around that may still
   * attempt to write to the buffer. So let gc handle it
   * instead of freeing it explicitly */
#if 0
  lsh_object_free(fd->buffer);
#endif

  /* There may be pointers to fd objects. So don't free them here. */
#if 0
  /* Handlers are not shared, so it should be ok to free them. */
  lsh_object_free(fd->handler);
  lsh_object_free(fd);
#endif
}

static int io_iter(struct io_backend *b)
{
  struct pollfd *fds;
  int i;
  unsigned long nfds; /* FIXME: Should be nfds_t if that type is defined */
  int timeout;
  int res;

  nfds = b->nio + b->nlisten + b->nconnect;

  if (b->callouts)
    {
      time_t now = time(NULL);
      if (now >= b->callouts->when)
	timeout = 0;
      else
	{
	  if (b->callouts->when > now + MAX_TIMEOUT)
	    timeout = MAX_TIMEOUT * 1000;
	  else
	    timeout = (b->callouts->when - now) * 1000;
	}
    }
  else
    {
      if (!nfds)
	/* All done */
	return 0;
      timeout = -1;
    }

  fds = alloca(sizeof(struct pollfd) * nfds);

  /* Handle fds in order: write, read, accept, connect. */
  i = 0;

  FOR_FDS(struct io_fd, fd, b->io, i++)
    {
      fds[i].fd = fd->fd;
      fds[i].events = 0;
      if (fd->handler && !fd->on_hold)
	fds[i].events |= POLLIN;

      /* pre_write returns 0 if the buffer is empty */
      if (fd->buffer)
	{
	  if (write_buffer_pre_write(fd->buffer))
	    fds[i].events |= POLLOUT;
	  else
	    /* Buffer is empty. Should we close? */
	    if (fd->buffer->closed)
	      {
		fd->close_now = 1;
	      }
	}
    }
  END_FOR_FDS;

  FOR_FDS(struct listen_fd, fd, b->listen, i++)
    {
      fds[i].fd = fd->fd;
      fds[i].events = POLLIN;
    }
  END_FOR_FDS;

  FOR_FDS(struct connect_fd, fd, b->connect, i++)
    {
      fds[i].fd = fd->fd;
      fds[i].events = POLLOUT;
    }
  END_FOR_FDS;

  res = poll(fds, nfds, timeout);

  if (!res)
    {
      /* Timeout. Run the callout */
      struct callout *f = b->callouts;

      if (!CALLBACK(f->callout))
	fatal("What now?");
      b->callouts = f->next;
      lsh_object_free(f);
    }
  if (res<0)
    {
      switch(errno)
	{
	case EAGAIN:
	case EINTR:
	  return 1;
	default:
	  fatal("io_run:poll failed: %s", strerror(errno));
	}
    }
  else
    { /* Process files */
      i = 0;

      /* Handle writing first */
      FOR_FDS(struct io_fd, fd, b->io, i++)
	{
	  if (fds[i].revents & POLLOUT)
	    {
	      UINT32 size = MIN(fd->buffer->end - fd->buffer->start,
				fd->buffer->block_size);
	      int res = write(fd->fd,
			      fd->buffer->buffer + fd->buffer->start,
			      size);
	      if (!res)
		fatal("Closed?");
	      if (res < 0)
		switch(errno)
		  {
		  case EINTR:
		  case EAGAIN:
		    break;
		  case EPIPE:
		    werror("Broken pipe\n");
		    fd->close_reason = CLOSE_WRITE_FAILED;
		    fd->close_now = 1;
		    break;
		  default:
		    werror("io.c: write failed, %s\n", strerror(errno));

		    fd->close_reason = CLOSE_WRITE_FAILED;
		    fd->close_now = 1;

		    break;
		  }
	      else
		fd->buffer->start += res;
	    }
	}
      END_FOR_FDS;

      /* Handle reading */
      i = 0; /* Start over */
      FOR_FDS(struct io_fd, fd, b->io, i++)
	{
	  if (!fd->close_now
	      && (fds[i].revents & POLLIN))
	    {
	      int res;
	      
	      struct fd_read r =
	      { { STACK_HEADER, do_read }, fd->fd };

	      /* The handler function may install a new handler */
	      res = READ_HANDLER(fd->handler,
				 &r.super);
	      /* NOTE: These flags are not mutually exclusive. All
	       * combination must be handled correctly. */

	      /* NOTE: (i) If LSH_DIE is set, LSH_CLOSE is ignored.
	       * (ii) If the fd is read_only, LSH_CLOSE is the same as LSH_DIE.
	       */
#if 0
	      if ( (res & (LSH_CLOSE | LSH_DIE)) == (LSH_CLOSE | LSH_DIE) )
		{
		  debug("return code %x, both LSH_CLOSE and LSH_DIE set.\n",
			res);
		  /* LSH_DIE takes precedence */
		  res &= ~LSH_CLOSE;

		  /* FIXME: Perhaps we should always set LSH_FAIL in
		   * this case? */
		}
#endif
	      if (res & LSH_HOLD)
		{
		  /* This flag should not be combined with anything else */
		  assert(res == LSH_HOLD);
		  fd->on_hold = 1;
		}
	      if (res & LSH_DIE)
		{
		  if (fd->buffer)
		    write_buffer_close(fd->buffer);
		  
		  fd->close_reason = LSH_FAILUREP(res)
		    ? CLOSE_PROTOCOL_FAILURE : 0;
		  fd->close_now = 1;
		}
	      else if (res & LSH_CLOSE)
		{
		  if (fd->buffer)
		    write_buffer_close(fd->buffer);
		  else
		    fd->close_now = 1;
		  
		  fd->close_reason
		    = LSH_FAILUREP(res) ? CLOSE_PROTOCOL_FAILURE : CLOSE_EOF;
		}
	      if (res & LSH_KILL_OTHERS)
		{
		  /* Close all other files. We have probably fork()ed. */
		  {
		    struct io_fd *p;
		    struct io_fd *next;
		    
		    for (p = b->io; p; p = next)
		      {
			next = p->next;
			
			if (p->fd != fd->fd)
			  {
			    p->close_reason = 0;
			    
			    /* In this case, it should be safe to
			     * deallocate the buffer immediately */
			    lsh_object_free(p->buffer);
			    close_fd(p);
			  }
		      }
		    if (fd->close_now)
		      {
			/* Some error occured. So close this fd too! */
			close_fd(fd);
			b->io = NULL;
			b->nio = 0;
		      }
		    else
		      { /* Keep this single descriptor open */
			fd->next = NULL;
			b->io = fd;
			b->nio = 1;
		      }
		  }{
		    struct listen_fd *p;
		    struct listen_fd *next;

		    for (p = b->listen; p; p = next)
		      {
			next = p->next;
			close(p->fd);
			lsh_space_free(p);
		      }
		    b->listen = NULL;
		    b->nlisten = 0;
		  }{
		    struct connect_fd *p;
		    struct connect_fd *next;

		    for (p = b->connect; p; p = next)
		      {
			next = p->next;
			close(p->fd);
			lsh_space_free(p);
		      }
		    b->connect = NULL;
		    b->nconnect = 0;
		  }{
		    struct callout *p;
		    struct callout *next;

		    for (p = b->callouts; p; p = next)
		      {
			next = p->next;
			lsh_space_free(p);
		      }
		    b->callouts = NULL;
		  }
		  /* Skip the rest od this iteration */
		  return 1;
		}
	    }
	  if (fd->close_now)
	    {
	      /* FIXME: Cleanup properly...
	       *
	       * After a write error, read state must be freed,
	       * and vice versa. */

	      close_fd(fd);

	      UNLINK_FD;

	      b->nio--;
	      continue;
	    }
	}
      END_FOR_FDS;

      FOR_FDS(struct listen_fd, fd, b->listen, i++)
	{
	  if (fds[i].revents & POLLIN)
	    {
	      /* FIXME: Do something with the peer address? */
	      struct sockaddr_in peer;
	      size_t addr_len = sizeof(peer);
	      int res;
	      
	      int conn = accept(fd->fd,
				(struct sockaddr *) &peer, &addr_len);
	      if (conn < 0)
		{
		  werror("io.c: accept() failed, %s", strerror(errno));
		  continue;
		}
	      res = FD_CALLBACK(fd->callback, conn);
	      if (LSH_ACTIONP(res))
		{
		  werror("Strange: Accepted a connection, "
			 "but failed before writing anything.\n");
		  close(fd->fd);
		  UNLINK_FD;
		  lsh_object_free(fd);
		  continue;
		}
	    }
	}
      END_FOR_FDS;
	  
      FOR_FDS(struct connect_fd, fd, b->connect, i++)
	{
	  if (fds[i].revents & POLLOUT)
	    {
	      int res = FD_CALLBACK(fd->callback, fd->fd);

	      if (LSH_ACTIONP(res))
		werror("Strange: Connected, "
		       "but failed before writing anything.\n");
	      b->nconnect--;
	      UNLINK_FD;
	      lsh_object_free(fd);
	      continue;
	    }
	}
      END_FOR_FDS;
    }
  return 1;
}

/* FIXME: Prehaps this function should return a suitable exit code? */
void io_run(struct io_backend *b)
{
  signal(SIGPIPE, SIG_IGN);
  
  while(io_iter(b))
    ;
}

void init_backend(struct io_backend *b)
{
  b->nio = 0;
  b->io = NULL;
  b->nlisten = 0;
  b->listen = NULL;
  b->nconnect = 0;
  b->connect = NULL;
  b->callouts = NULL;
}

/*
 * Fill in ADDR from HOST, SERVICE and PROTOCOL.
 * Supplying a null pointer for HOST means use INADDR_ANY.
 * Otherwise HOST is an numbers-and-dots ip-number or a dns name.
 *
 * PROTOCOL can be tcp or udp.
 *
 * Supplying a null pointer for SERVICE, means use port 0, i.e. no port.
 * 
 * Returns zero on errors, 1 if everything is ok.
 */
int
get_inaddr(struct sockaddr_in	* addr,
	   const char		* host,
	   const char		* service,
	   const char		* protocol)
{
  memset(addr, 0, sizeof *addr);
  addr->sin_family = AF_INET;

  /*
   *  Set host part of ADDR
   */
  if (host == NULL)
    addr->sin_addr.s_addr = INADDR_ANY;
  else
    {
      /* First check for numerical ip-number */
      addr->sin_addr.s_addr = inet_addr(host);
      if (addr->sin_addr.s_addr == (unsigned long)-1)
	{
	  struct hostent * hp;
	  
	  hp = gethostbyname(host);
	  if (hp == NULL)
	    return 0;
	  memcpy(&addr->sin_addr, hp->h_addr, hp->h_length);
	  addr->sin_family = hp->h_addrtype;
	}
    }

  /*
   *  Set port part of ADDR
   */
  if (service == NULL)
    addr->sin_port = htons(0);
  else
    {
      char		* end;
      long		  portno;

      portno = strtol(service, &end, 10);
      if (portno > 0  &&  portno <= 65535
	  &&  end != service  &&  *end == '\0')
	{
	  addr->sin_port = htons(portno);
	}
      else
	{
	  struct servent	* serv;

	  serv = getservbyname(service, "tcp");
	  if (serv == NULL)
	    return 0;
	  addr->sin_port = serv->s_port;
	}
    }

  return 1;
}

void io_set_nonblocking(int fd)
{
  if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0)
    fatal("io_set_nonblocking: fcntl() failed, %s", strerror(errno));
}

void io_set_close_on_exec(int fd)
{
  if (fcntl(fd, F_SETFD, 1) < 0)
    fatal("Can't set close-on-exec flag for fd %d: %s\n",
	  fd, strerror(errno));
}

/* ALL file descripters handled by the backend should use non-blocking mode,
 * and have the close-on-exec flag set. */

void io_init_fd(int fd)
{
  io_set_nonblocking(fd);
  io_set_close_on_exec(fd);
}

/* Some code is taken from bellman's tcputils. */
struct connect_fd *io_connect(struct io_backend *b,
			      struct sockaddr_in *remote,
			      struct sockaddr_in *local,
			      struct fd_callback *f)
{
  struct connect_fd *fd;
  int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  
  if (s<0)
    return NULL;

  debug("io.c: connecting using fd %d\n", s);
  
  io_init_fd(s);

  if (local  &&  bind(s, (struct sockaddr *)local, sizeof *local) < 0)
    {
      int saved_errno = errno;
      close(s);
      errno = saved_errno;
      return NULL;
    }

  if ( (connect(s, (struct sockaddr *)remote, sizeof *remote) < 0)
       && (errno != EINPROGRESS) )       
    {
      int saved_errno = errno;
      close(s);
      errno = saved_errno;
      return NULL;
    }
  
  NEW(fd);
  fd->fd = s;
  fd->callback = f;

  fd->next = b->connect;
  b->connect = fd;

  b->nconnect++;
  
  return fd;
}

struct listen_fd *io_listen(struct io_backend *b,
			    struct sockaddr_in *local,
			    struct fd_callback *callback)
{
  struct listen_fd *fd;
  int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  
  if (s<0)
    return NULL;

  debug("io.c: listening on fd %d\n", s);
  
  io_init_fd(s);

  {
    int yes = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char*)&yes, sizeof yes);
  }

  if (bind(s, (struct sockaddr *)local, sizeof *local) < 0)
    {
      close(s);
      return NULL;
    }

  if (listen(s, 256) < 0) 
    {
      close(s);
      return NULL;
    }

  NEW(fd);

  fd->fd = s;
  fd->callback = callback;

  fd->next = b->listen;
  b->listen = fd;
  b->nlisten++;
  
  return fd;
}

struct abstract_write *io_read_write(struct io_backend *b,
				     int fd,
				     struct read_handler *read_callback,
				     UINT32 block_size,
				     struct close_callback *close_callback)
{
  struct io_fd *f;
  struct write_buffer *buffer = write_buffer_alloc(block_size);

  debug("io.c: Preparing fd %d for reading and writing\n", fd);
  
  io_init_fd(fd);
  
  NEW(f);
  f->fd = fd;
  
  f->close_reason = -1; /* Invalid reason */
  f->close_now = 0;

  /* Reading */
  f->handler = read_callback;
  f->on_hold = 0;

  /* Writing */
  f->buffer = buffer;
  f->close_callback = close_callback;

  f->next = b->io;
  b->io = f;
  b->nio++;

  return &buffer->super;
}

struct io_fd *io_read(struct io_backend *b,
		      int fd,
		      struct read_handler *read_callback,
		      struct close_callback *close_callback)
{
  struct io_fd *f;

  debug("io.c: Preparing fd %d for reading\n", fd);
  
  io_init_fd(fd);

  NEW(f);
  f->fd = fd;
  
  f->close_reason = -1; /* Invalid reason */
  f->close_now = 0;

  /* Reading */
  f->handler = read_callback;
  f->on_hold = 0;

  /* Writing */
  f->buffer = NULL;

  f->close_callback = close_callback;

  f->next = b->io;
  b->io = f;
  b->nio++;

  return f;
}

struct io_fd *io_write(struct io_backend *b,
		       int fd,
		       UINT32 block_size,
		       struct close_callback *close_callback)
{
  struct io_fd *f;
  struct write_buffer *buffer = write_buffer_alloc(block_size);

  debug("io.c: Preparing fd %d for writing\n", fd);
  
  io_init_fd(fd);
  
  NEW(f);
  f->fd = fd;
  
  f->close_reason = -1; /* Invalid reason */
  f->close_now = 0;

  /* Reading */
  f->handler = NULL;

  /* Writing */
  f->buffer = buffer;
  f->close_callback = close_callback;

  f->next = b->io;
  b->io = f;
  b->nio++;

  return f;
}
