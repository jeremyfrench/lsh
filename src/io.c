/* io.c
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "io.h"
#include "werror.h"
#include "write_buffer.h"
#include "xalloc.h"

#include <assert.h>
#include <string.h>

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_POLL
# if HAVE_POLL_H
#  include <poll.h>
# elif HAVE_SYS_POLL_H
#  include <sys/poll.h>
# endif
#else
# include "jpoll.h"
#endif

#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <signal.h>

#define CLASS_DEFINE
#include "io.h.x"
#undef CLASS_DEFINE

#include "io.c.x"

/* If there's nothing to do for this amount of time (ms), do
 * spontaneous gc. */

#define IDLE_TIME 100

int io_iter(struct io_backend *b)
{
  unsigned long nfds; /* FIXME: Should be nfds_t if that type is defined */
  struct pollfd *fds;

  /* FIXME: Callouts not implemented */
  /* int timeout; */
  int res;

  nfds = 0;
  
  {
    /* Prepare fd:s. This fase calls the prepare-methods, also closes
     * and unlinks any fd:s that should be closed, and also counts how
     * many fd:s there are. */
    
    struct lsh_fd **fd_p;
    struct lsh_fd *fd;
    
    for(fd_p = &b->files; (fd = *fd_p); )
      {
	if (fd->super.alive && fd->prepare)
	  PREPARE_FD(fd);
	
	if (!fd->super.alive)
	  {
	    if (fd->fd < 0)
	      /* Unlink the file object, but don't close any underlying file. */
	      ;
	    else
	      {
		/* Used by write fd:s to make sure that writing to its
		 * buffer fails. */
		if (fd->really_close)
		  REALLY_CLOSE_FD(fd);
		
		/* FIXME: The value returned from the close callback could be used
		 * to choose an exit code. */
		if (fd->close_callback && fd->close_reason)
		  (void) CLOSE_CALLBACK(fd->close_callback, fd->close_reason);
		
		debug("Closing fd %i.\n", fd->fd);
		
		close(fd->fd);
	      }
	    /* Unlink this fd */
	    *fd_p = fd->next;
	    continue;
	  }
	nfds++;
	fd_p = &fd->next;
      }
	
  }

  if (!nfds)
    /* Nothing more to do.
     *
     * NOTE: There might be some callouts left, but we won't wait for them. */
    return 0;
  
  fds = alloca(sizeof(struct pollfd) * nfds);

  /* Fill out fds-array */
  {
    struct lsh_fd *fd;
    unsigned long i;
    int all_events = 0;
    
    for (fd = b->files, i = 0; fd; fd = fd->next, i++)
      {
	assert(i < nfds);

	fds[i].fd = fd->fd;
	fds[i].events = 0;

	if (fd->want_read)
	  fds[i].events |= POLLIN;

	if (fd->want_write)
	  fds[i].events |= POLLOUT;

	all_events |= fds[i].events;
      }
    assert(i == nfds);

    if (!all_events)
      {
	/* Nothing happens */
	/* NOTE: There might be some callouts left, but we don't wait */
	return 0;
      }
  }

  res = poll(fds, nfds, IDLE_TIME);

  if (!res)
    {
      gc_maybe(&b->super, 0);
      res = poll(fds, nfds, -1);
    }
  else
    gc_maybe(&b->super, 1);
  
  if (!res)
    {
      /* Callouts are not implemented */
      fatal("Unexpected timeout\n");
    }
  if (res < 0)
    switch(errno)
      {
      case EAGAIN:
      case EINTR:
	return 1;
      default:
	fatal("io_iter: poll failed: %z", strerror(errno));
      }
  
  {
    /* Do io. Note that the callback functions may add new fds to the
     * head of the list, or clear the alive flag on any fd. */

    struct lsh_fd *fd;
    unsigned long i;
    
    for(fd = b->files, i=0; fd; fd = fd->next, i++)
      {
	assert(i<nfds);
	
	if (!fd->super.alive)
	  continue;

	if (fds[i].revents & POLLOUT)
	  WRITE_FD(fd);

	if (!fd->super.alive)
	  continue;

	if (fds[i].revents & POLLIN)
	  READ_FD(fd);
      }
    assert(i == nfds);
  }

  return 1;
}

/* CLASS:
   (class
     (name fd_read)
     (super abstract_read)
       (vars
         (fd simple int)))
*/

static int do_read(struct abstract_read **r, UINT32 length, UINT8 *buffer)
{
  CAST(fd_read, closure, *r);

  for (;;)
    {
      int res = read(closure->fd, buffer, length);
      if (!res)
	{
	  debug("Read EOF on fd %i.\n", closure->fd);
	  return A_EOF;
	}
      if (res > 0)
	return res;

      switch(errno)
	{
	case EINTR:
	  continue;  /* FIXME: Is it really worth looping here,
		      * instead of in the select loop? */
	case EWOULDBLOCK:  /* aka EAGAIN */
	  return 0;
	case EPIPE:
	  werror("io.c: read() returned EPIPE! Treating it as EOF.\n");
	  return A_EOF;
	default:
	  werror("io.c: do_read: read() failed (errno %i), %z\n",
		 errno, strerror(errno));
	  debug("  fd = %i, buffer = %xi, length = %i\n",
		closure->fd, buffer, length);
	  return A_FAIL;
	}
    }
}

static void read_callback(struct lsh_fd *fd)
{
  CAST(io_fd, self, fd);
  int res;

  struct fd_read r =
  { { STACK_HEADER, do_read }, fd->fd };

  /* The handler function may install a new handler */
  res = READ_HANDLER(self->handler,
		     &r.super);

  /* NOTE: These flags are not mutually exclusive. All combinations
   * must be handled correctly. */
  
  /* NOTE: (i) If LSH_DIE is set, LSH_CLOSE is ignored. (ii) If the fd
   * is read_only, LSH_CLOSE is the same as LSH_DIE. */

  /* This condition must be taken care of earlier. */
  assert(!(res & LSH_CHANNEL_FINISHED));

  /* Not implemented */
  assert(!(res & LSH_KILL_OTHERS));

  if (res & LSH_HOLD)
    {
      /* This flag should not be combined with anything else */
      assert(res == LSH_HOLD);
      fd->want_read = 0;
    }
  if (res & LSH_DIE)
    {
      if (self->buffer)
	write_buffer_close(self->buffer);

      close_fd(fd,
	       LSH_FAILUREP(res) ? CLOSE_PROTOCOL_FAILURE : 0);
    }
  else if (res & LSH_CLOSE)
    {
      if (self->buffer)
	{
	  write_buffer_close(self->buffer);
	  /* Don't attempt to read any further. */
	  /* FIXME: Is it safe to free the handler here? */
	  self->super.want_read = 0;
	  self->handler = NULL;
	}
      else
	kill_fd(fd);
		  
      fd->close_reason
	= LSH_FAILUREP(res) ? CLOSE_PROTOCOL_FAILURE : CLOSE_EOF;
    }
}

static void write_callback(struct lsh_fd *fd)
{
  CAST(io_fd, self, fd);
  UINT32 size;
  int res;
  
  size = MIN(self->buffer->end - self->buffer->start,
	     self->buffer->block_size);
  assert(size);
  
  res = write(fd->fd,
	      self->buffer->buffer + self->buffer->start,
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
	debug("io.c: Broken pipe.\n");
	close_fd(fd, CLOSE_BROKEN_PIPE);
	break;
      default:
	werror("io.c: write failed, %z\n", strerror(errno));

	close_fd(fd, CLOSE_WRITE_FAILED);
	
	break;
      }
  else
    self->buffer->start += res;
}  

static void listen_callback(struct lsh_fd *fd)
{
  CAST(listen_fd, self, fd);
  struct sockaddr_in peer;
  size_t addr_len = sizeof(peer);
  int res;
  int conn;

  /* FIXME: Do something with the peer address? */

  conn = accept(fd->fd,
		(struct sockaddr *) &peer, &addr_len);
  if (conn < 0)
    {
      werror("io.c: accept() failed, %z", strerror(errno));
      return;
    }
  res = FD_CALLBACK(self->callback, conn);
  if (LSH_ACTIONP(res))
    {
      werror("Strange: Accepted a connection, "
	     "but failed before writing anything.\n");
      close_fd(fd, (LSH_FAILUREP(res)
		    ? CLOSE_PROTOCOL_FAILURE
		    : CLOSE_EOF));
    }
}

static void connect_callback(struct lsh_fd *fd)
{
  CAST(connect_fd, self, fd);
  int res;
  
  res = FD_CALLBACK(self->callback, fd->fd);

  if (LSH_ACTIONP(res))
    {
      werror("Strange: Connected, "
	     "but failed before writing anything.\n");
    }
  else
    {
      /* To avoid actually closing the fd */
      fd->fd = -1;
    }
  kill_fd(fd);
}

/* FIXME: Prehaps this function should return a suitable exit code? */
void io_run(struct io_backend *b)
{
  struct sigaction pipe;
  memset(&pipe, 0, sizeof(pipe));

  pipe.sa_handler = SIG_IGN;
  sigemptyset(&pipe.sa_mask);
  pipe.sa_flags = 0;
  
  if (sigaction(SIGPIPE, &pipe, NULL) < 0)
    fatal("Failed to ignore SIGPIPE.\n");
  
  while(io_iter(b))
    ;
}

void init_backend(struct io_backend *b)
{
  b->files = NULL;
#if 0
  b->callouts = 0;
#endif
}

/* This function is called if a connection this file somehow dependent
 * on disappears. For instance, the connection may have spawned a
 * child process, and this file may be the stdin of that process. */

/* To kill a file, mark it for closing and the backend will do the work. */
static void do_kill_fd(struct resource *r)
{
  CAST_SUBTYPE(lsh_fd, fd, r);

  /* FIXME: It could make sense to you a separate close reason for
   * killed files. For now, using the zero reason will supress calling
   * of any close callbacks. */
  if (r->alive)
    close_fd(fd, 0);
}

/* Initializes a file structure, and adds it to the backend's list. */
static void init_file(struct io_backend *b, struct lsh_fd *f, int fd)
{
  /* assert(fd); */
  f->fd = fd;
  f->close_reason = -1; /* Invalid reason */
  f->close_callback = NULL;

  f->prepare = NULL;

  f->want_read = 0;
  f->read = NULL;

  f->want_write = 0;
  f->write = NULL;

  f->super.alive = 1;
  f->super.kill = do_kill_fd;
  f->really_close = NULL;

  f->next = b->files;
  b->files = f;
}

/* Blocking read from a file descriptor (i.e. don't use the backend).
 * The fd should *not* be in non-blocking mode. */

int blocking_read(int fd, struct read_handler *handler)
{
  struct fd_read r =
  { { STACK_HEADER, do_read }, fd };

  for (;;)
    {
      int res = READ_HANDLER(handler,
			     &r.super);

      assert(!(res & (LSH_HOLD | LSH_KILL_OTHERS)));

      if (res & (LSH_CLOSE | LSH_DIE))
	{
	  close(fd);
	  return res;
	}
      if (res & LSH_FAIL)
	werror("blocking_read: Ignoring error %i\n", res);
    }
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
#if HAVE_INET_ATON
      if (!inet_aton(host, &addr->sin_addr))
#else /* !HAVE_INET_ATON */
	/* TODO: It is wrong to work with ((unsigned long int) -1)
	 * directly, as this breaks Linux/Alpha systems. But
	 * INADDR_NONE isn't portable. The clean solution is to use
	 * inet_aton rather than inet_addr; see the GNU libc
	 * documentation. */
# ifndef INADDR_NONE
# define INADDR_NONE ((unsigned long int) -1)
# endif /* !INADDR_NONE */
      addr->sin_addr.s_addr = inet_addr(host);
      if (addr->sin_addr.s_addr == INADDR_NONE)
#endif  /* !HAVE_INET_ATON */
	{
	  struct hostent * hp;
	  
	  hp = gethostbyname(host);
	  if (hp == NULL)
	    return 0;
	  memcpy(&addr->sin_addr, hp->h_addr, (size_t) (hp->h_length));
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

	  serv = getservbyname(service, protocol);
	  if (serv == NULL)
	    return 0;
	  addr->sin_port = serv->s_port;
	}
    }

  return 1;
}

/* For fd:s in blocking mode. */
int write_raw(int fd, UINT32 length, UINT8 *data)
{
  while(length)
    {
      int written = write(fd, data, length);

      if (written < 0)
	switch(errno)
	  {
	  case EINTR:
	  case EAGAIN:
	    continue;
	  default:
	    return 0;
	  }
      
      length -= written;
      data += written;
    }
  return 1;
}

int write_raw_with_poll(int fd, UINT32 length, UINT8 *data)
{
  while(length)
    {
      struct pollfd pfd;
      int res;
      int written;
      
      pfd.fd = fd;
      pfd.events = POLLOUT;

      res = poll(&pfd, 1, -1);

      if (res < 0)
	switch(errno)
	  {
	  case EINTR:
	  case EAGAIN:
	    continue;
	  default:
	    return 0;
	  }
      
      written = write(fd, data, length);

      if (written < 0)
	switch(errno)
	  {
	  case EINTR:
	  case EAGAIN:
	    continue;
	  default:
	    return 0;
	  }
      
      length -= written;
      data += written;
    }
  return 1;
}

void io_set_nonblocking(int fd)
{
  if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0)
    fatal("io_set_nonblocking: fcntl() failed, %z", strerror(errno));
}

void io_set_close_on_exec(int fd)
{
  if (fcntl(fd, F_SETFD, 1) < 0)
    fatal("Can't set close-on-exec flag for fd %i: %z\n",
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
  int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  
  if (s<0)
    return NULL;

  debug("io.c: connecting using fd %i\n", s);
  
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

  {
    NEW(connect_fd, fd);

    init_file(b, &fd->super, s);

    fd->super.want_write = 1;
    fd->super.write = connect_callback;
    fd->callback = f;
    
    return fd;
  }
}

struct listen_fd *io_listen(struct io_backend *b,
			    struct sockaddr_in *local,
			    struct fd_callback *callback)
{
  int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  
  if (s<0)
    return NULL;

  debug("io.c: listening on fd %i\n", s);
  
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

  {
    NEW(listen_fd, fd);

    init_file(b, &fd->super, s);
    
    fd->super.want_read = 1;
    fd->super.read = listen_callback;
    fd->callback = callback;
    
    return fd;
  }
}

static void really_close(struct lsh_fd *fd)
{
  CAST(io_fd, self, fd);

  assert(self->buffer);

  write_buffer_close(self->buffer);
}

static void prepare_write(struct lsh_fd *fd)
{
  CAST(io_fd, self, fd);

  assert(self->buffer);

  if (! (fd->want_write = write_buffer_pre_write(self->buffer))
      && self->buffer->closed)
    close_fd(fd, CLOSE_EOF);
}
  
struct io_fd *io_read_write(struct io_backend *b,
			    int fd,
			    struct read_handler *handler,
			    UINT32 block_size,
			    struct close_callback *close_callback)
{
  NEW(io_fd, f);
  struct write_buffer *buffer = write_buffer_alloc(block_size);

  debug("io.c: Preparing fd %i for reading and writing\n", fd);
  
  io_init_fd(fd);
  
  init_file(b, &f->super, fd);
  
  /* Reading */
  f->super.read = read_callback;
  f->super.want_read = !!handler;
  f->handler = handler;

  /* Writing */
  f->super.prepare = prepare_write;
  f->super.write = write_callback;
  f->buffer = buffer;

  /* Closing */
  f->super.really_close = really_close;
  f->super.close_callback = close_callback;

  return f;
}

struct io_fd *io_read(struct io_backend *b,
		      int fd,
		      struct read_handler *handler,
		      struct close_callback *close_callback)
{
  NEW(io_fd, f);

  debug("io.c: Preparing fd %i for reading\n", fd);
  
  io_init_fd(fd);

  init_file(b, &f->super, fd);

  /* Reading */
  f->super.want_read = !!handler;
  f->super.read = read_callback;
  f->handler = handler;

  f->super.close_callback = close_callback;

  return f;
}

struct io_fd *io_write(struct io_backend *b,
		       int fd,
		       UINT32 block_size,
		       struct close_callback *close_callback)
{
  NEW(io_fd, f);
  struct write_buffer *buffer = write_buffer_alloc(block_size);

  debug("io.c: Preparing fd %i for writing\n", fd);
  
  io_init_fd(fd);
  
  init_file(b, &f->super, fd);

  /* Writing */
  f->super.prepare = prepare_write;
  f->super.write = write_callback;
  f->buffer = buffer;
  
  f->super.close_callback = close_callback;

  return f;
}

void kill_fd(struct lsh_fd *fd)
{
  fd->super.alive = 0;
}

void close_fd(struct lsh_fd *fd, int reason)
{
  debug("Marking fd %i for closing.\n", fd->fd);
  fd->close_reason = reason;
  kill_fd(fd);
}
