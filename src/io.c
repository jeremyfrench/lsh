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

#ifdef HAVE_POLL
#include <poll.h>
#else
#include "poll.h"
#endif

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

int io_iter(struct io_backend *b)
{
  unsigned long nfds; /* FIXME: Should be nfds_t if that type is defined */
  struct pollfd *fds;

  int timeout;
  int res;

  nfds = 0;
  
  {
    /* Prepare fd:s. This fase calls the prepare-methods, also closes
     * and unlinks any fd:s that should be closed, and also counts how
     * many fd:s there are. */
    
    struct lsh_fd **_fd;
    struct lsh_fd *fd;
    
    for(_fd = &b->files; (fd = *_fd); )
      {
	if (!fd->close_now && fd->prepare)
	  PREPARE_FD(fd);
	
	if (fd->close_now)
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
		
		debug("Closing fd %d.\n", fd->fd);
		
		close(fd->fd);
	      }
	    /* Unlink this fd */
	    *_fd = fd->next;
	    continue;
	  }
	nfds++;
	_fd = &fd->next;
      }
	
  }

  if (!nfds)
    /* Nothing more to do.
     *
     * NOTE: There might be some callouts left, but we won't wait for them. */
    return 0;

  /* FIXME: Callouts not implemented */
  timeout = -1;
  
  fds = alloca(sizeof(struct pollfd) * nfds);

  /* Fill out fds-array */
  {
    struct lsh_fd *fd;
    int i;
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

  res = poll(fds, nfds, timeout);

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
	fatal("io_iter: poll failed: %s", strerror(errno));
      }
  
  {
    /* Do io. Note that the callback functions may add new fds to the
     * head of the list, or set the close_now flag on any fd. */

    struct lsh_fd *fd;
    int i;
    
    for(fd = b->files, i=0; fd; fd = fd->next, i++)
      {
	assert(i<nfds);
	
	if (fd->close_now)
	  continue;

	if (fds[i].revents & POLLOUT)
	  WRITE_FD(fd);

	if (fd->close_now)
	  continue;

	if (fds[i].revents & POLLIN)
	  READ_FD(fd);
      }
    assert(i == nfds);
  }

  return 1;
}

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
	case EPIPE:
	  werror("io.c: read() returned EPIPE! Treating it as EOF.\n");
	  return A_EOF;
	default:
	  werror("io.c: do_read: read() failed (errno %d), %s\n",
		 errno, strerror(errno));
	  debug("  fd = %d, buffer = %p, length = %ud\n",
		closure->fd, buffer, length);
	  return A_FAIL;
	}
    }
}

static void read_callback(struct lsh_fd *fd)
{
  struct io_fd *self = (struct io_fd *) fd;
  int res;

  struct fd_read r =
  { { STACK_HEADER, do_read }, fd->fd };

  MDEBUG(self);
  
  /* The handler function may install a new handler */
  res = READ_HANDLER(self->handler,
		     &r.super);

  /* NOTE: These flags are not mutually exclusive. All combination
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
		  
      fd->close_reason = LSH_FAILUREP(res)
	? CLOSE_PROTOCOL_FAILURE : 0;
      fd->close_now = 1;
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
	fd->close_now = 1;
		  
      fd->close_reason
	= LSH_FAILUREP(res) ? CLOSE_PROTOCOL_FAILURE : CLOSE_EOF;
    }
}

static void write_callback(struct lsh_fd *fd)
{
  struct io_fd *self = (struct io_fd *) fd;
  UINT32 size;
  int res;
  
  MDEBUG(self);

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
    self->buffer->start += res;
}  

static void listen_callback(struct lsh_fd *fd)
{
  struct listen_fd *self = (struct listen_fd *) fd;
  struct sockaddr_in peer;
  size_t addr_len = sizeof(peer);
  int res;
  int conn;

  MDEBUG(self);
  
  /* FIXME: Do something with the peer address? */

  conn = accept(fd->fd,
		(struct sockaddr *) &peer, &addr_len);
  if (conn < 0)
    {
      werror("io.c: accept() failed, %s", strerror(errno));
      return;
    }
  res = FD_CALLBACK(self->callback, conn);
  if (LSH_ACTIONP(res))
    {
      werror("Strange: Accepted a connection, "
	     "but failed before writing anything.\n");
      fd->close_now = 1;
      fd->close_reason = LSH_FAILUREP(res) ? CLOSE_PROTOCOL_FAILURE
	: CLOSE_EOF;
    }
}

static void connect_callback(struct lsh_fd *fd)
{
  struct connect_fd *self = (struct connect_fd *) fd;
  int res;
  
  MDEBUG(self);

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
  fd->close_now = 1;
}

/* FIXME: Prehaps this function should return a suitable exit code? */
void io_run(struct io_backend *b)
{
  struct sigaction pipe;

  pipe.sa_handler = SIG_IGN;
  sigemptyset(&pipe.sa_mask);
  pipe.sa_flags = 0;
  pipe.sa_restorer = NULL;
  
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

  f->close_now = 0;
  f->really_close = NULL;

  f->next = b->files;
  b->files = f;
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
  init_file(b, &fd->super, s);

  fd->super.want_write = 1;
  fd->super.write = connect_callback;
  fd->callback = f;

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

  init_file(b, &fd->super, s);

  fd->super.want_read = 1;
  fd->super.read = listen_callback;
  fd->callback = callback;

  return fd;
}

static void really_close(struct lsh_fd *fd)
{
  struct io_fd *self = (struct io_fd *) fd;

  MDEBUG(self);

  assert(self->buffer);

  write_buffer_close(self->buffer);
}

static void prepare_write(struct lsh_fd *fd)
{
  struct io_fd *self = (struct io_fd *) fd;

  MDEBUG(self);

  assert(self->buffer);

  if (! (fd->want_write = write_buffer_pre_write(self->buffer))
      && self->buffer->closed)
    fd->close_now = 1;
}
  
struct abstract_write *io_read_write(struct io_backend *b,
				     int fd,
				     struct read_handler *handler,
				     UINT32 block_size,
				     struct close_callback *close_callback)
{
  struct io_fd *f;
  struct write_buffer *buffer = write_buffer_alloc(block_size);

  debug("io.c: Preparing fd %d for reading and writing\n", fd);
  
  io_init_fd(fd);
  
  NEW(f);
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

  return &buffer->super;
}

struct io_fd *io_read(struct io_backend *b,
		      int fd,
		      struct read_handler *handler,
		      struct close_callback *close_callback)
{
  struct io_fd *f;

  debug("io.c: Preparing fd %d for reading\n", fd);
  
  io_init_fd(fd);

  NEW(f);

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
  struct io_fd *f;
  struct write_buffer *buffer = write_buffer_alloc(block_size);

  debug("io.c: Preparing fd %d for writing\n", fd);
  
  io_init_fd(fd);
  
  NEW(f);
  init_file(b, &f->super, fd);

  /* Writing */
  f->super.prepare = prepare_write;
  f->super.write = write_callback;
  f->buffer = buffer;
  
  f->super.close_callback = close_callback;

  return f;
}

/* Marks a file for closing, at the end of the current iteration.
 * FIXME: Could be generalized for other fd:s than read-write fds. */

void close_fd(struct lsh_fd *fd, int reason)
{
  debug("Marking fd %d for closing.\n", fd->fd);
  fd->close_reason = reason;
  fd->close_now = 1;
}
