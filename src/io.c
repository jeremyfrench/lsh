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

#include "format.h"
#include "werror.h"
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

/* Workaround for some version of FreeBSD. */
#ifdef POLLRDNORM
# define MY_POLLIN (POLLIN | POLLRDNORM)
#else /* !POLLRDNORM */
# define MY_POLLIN POLLIN
#endif /* !POLLRDNORM */

#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/stat.h>


#define GABA_DEFINE
#include "io.h.x"
#undef GABA_DEFINE

#include "io.c.x"


/* Backend loop */

/* If there's nothing to do for this amount of time (ms), do
 * spontaneous gc. */

#define IDLE_TIME 100

int io_iter(struct io_backend *b)
{
  unsigned long nfds; /* FIXME: Should be nfds_t if that type is defined */
  struct pollfd *fds;
  struct lsh_fd **active_fds;
  
  /* FIXME: Callouts not implemented */
  /* int timeout; */
  int res;

  {
    struct lsh_fd *fd;
    int need_close;
    
    /* Prepare fd:s. This phase calls the prepare-methods, also closes
     * and unlinks any fd:s that should be closed, and also counts how
     * many fd:s there are. */

    for (fd = b->files; fd; fd = fd->next)
      {
	if (fd->super.alive && fd->prepare)
	  FD_PREPARE(fd);
      }
    
    /* Note that calling a close callback might cause other files to
     * be closed as well, so we need a double loop.
     *
     * FIXME: How can we improve this? We could keep a stack of closed
     * files, but that will require backpointers from the fd:s to the
     * backend (so that kill_fd() can find the top of the stack). */

    do
      {
	struct lsh_fd **fd_p;
	need_close = 0;
	nfds = 0;
	
	for(fd_p = &b->files; (fd = *fd_p); )
	  {
	    if (!fd->super.alive)
	      {
		if (fd->fd < 0)
		  /* Unlink the file object, but don't close any
		   * underlying file. */
		  ;
		else
		  {
		    /* Used by write fd:s to make sure that writing to its
		     * buffer fails. */
		    if (fd->write_close)
		      FD_WRITE_CLOSE(fd);
		
		    /* FIXME: The value returned from the close
		     * callback could be used to choose an exit code.
		     * */
		    if (fd->close_callback)
		      {
			CLOSE_CALLBACK(fd->close_callback, fd->close_reason);
			need_close = 1;
		      }
		    trace("io.c: Closing fd %i.\n", fd->fd);
		
		    close(fd->fd);
		  }
		/* Unlink this fd */
		*fd_p = fd->next;
		continue;
	      }

	    /* FIXME: nfds should probably include only fd:s that we are
	     * interested in reading or writing. However, that makes the
	     * mapping from struct pollfd to struct lsh_fd a little more
	     * difficult. */
	    if (fd->want_read || fd->want_write)
	      nfds++;

	    fd_p = &fd->next;
	  }
      } while (need_close);
  }

  if (!nfds)
    /* Nothing more to do.
     *
     * NOTE: There might be some callouts left, but we won't wait for them. */
    return 0;

  fds = alloca(sizeof(struct pollfd) * nfds);
  active_fds = alloca(sizeof(struct lsh_fd *) *nfds);
  
  /* Fill out fds-array */
  {
    struct lsh_fd *fd;
    unsigned long i;
    int all_events = 0;
    
    for (fd = b->files, i = 0; fd; fd = fd->next)
      {
	assert(fd->super.alive);
	
	if (fd->want_read || fd->want_write)
	  {
	    assert(i < nfds);

	    active_fds[i] = fd;

	    fds[i].fd = fd->fd;
	    fds[i].events = 0;
	    
	    if (fd->want_read)
	      fds[i].events |= MY_POLLIN;

	    if (fd->want_write)
	      fds[i].events |= POLLOUT;

	    all_events |= fds[i].events;
	    i++;
	  }
      }
    assert(i == nfds);
    assert(all_events);
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
	fatal("io_iter: poll failed: %z", STRERROR(errno));
      }
  
  {
    /* Do io. Note that the callback functions may add new fds to the
     * head of the list, or clear the alive flag on any fd. But this
     * is less of a problem now, as we use the active_fd array.*/

    /* struct lsh_fd *fd; */
    unsigned long i;
    
    for(i=0; i<nfds; i++)
      {
	struct lsh_fd *fd = active_fds[i];
	assert(i<nfds);

	debug("io.c: poll for fd %i: events = 0x%xi, revents = 0x%xi.\n",
 	      fds[i].fd, fds[i].events, fds[i].revents);
	
	if (!fd->super.alive)
	  continue;

	/* On systems without poll(), we use jpoll.c to emulate some
	 * of poll(), but we lack POLLNVAL, POLLPRI and POLLHUP. */
#ifdef POLLNVAL
	if (fds[i].revents & POLLNVAL)
	  {
	    werror("io.c: poll request on fd %i, for events of type %xi\n"
		   "      return POLLNVAL, revents = %xi\n",
		   fds[i].fd, fds[i].events, fds[i].revents);
	    kill_fd(fd);
	    continue;
	  }
#endif /* POLLNVAL */

#ifdef POLLHUP
	/* FIXME: According to Solaris' man page, POLLHUP is mutually
	 * exclusive with POLLOUT, but orthogonal to POLLIN.
	 *
	 * However, on my system (sparc-linux) POLLHUP is set when we
	 * get EOF on an fd we are reading. This will cause an i/o
	 * exception to be raised rather than the ordinary EOF
	 * handling. */
	if (fds[i].revents & POLLHUP)
	  {
	    if (fd->want_write)
	      /* Will raise an i/o error */
	      FD_WRITE(fd);
	    else if (fd->want_read)
	      /* Ought to behave like EOF, but might raise an i/o
	       * error instead. */
	      FD_READ(fd);
	    else
	      {
		werror("io.c: poll said POLLHUP on an inactive fd.\n");
		close_fd(fd, CLOSE_EOF);
	      }
	    continue;
	  }
#endif /* POLLHUP */

#ifdef POLLPRI
	if (fds[i].revents & POLLPRI)
	  {
	    werror("io.c: Peer is trying to send Out of Band data. Hanging up.\n");

	    /* FIXME: Should we raise any exception here? */

	    close_fd(fd, CLOSE_PROTOCOL_FAILURE); 

	    continue;
	  }
#endif /* POLLPRI */
	if (fds[i].revents & POLLOUT)
	  FD_WRITE(fd);

	if (!fd->super.alive)
	  continue;

	if (fds[i].revents & MY_POLLIN)
	  FD_READ(fd);
      }
    assert(i == nfds);
  }

  return 1;
}


/* FIXME: Perhaps this function should return a suitable exit code? */
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


/* Read-related callbacks */

static void
do_buffered_read(struct io_callback *s,
		 struct lsh_fd *fd)
{
  CAST(io_buffered_read, self, s);
  UINT8 *buffer = alloca(self->buffer_size);
  int res = read(fd->fd, buffer, self->buffer_size);

  if (res < 0)
    switch(errno)
      {
      case EINTR:
	break;
      case EWOULDBLOCK:
	werror("io.c: read_callback: Unexpected EWOULDBLOCK\n");
	break;
      case EPIPE:
	/* Getting EPIPE from read() seems strange, but appearantly
	 * it happens sometimes. */
	werror("Unexpected EPIPE.\n");
      default:
	EXCEPTION_RAISE(fd->e, 
			make_io_exception(EXC_IO_READ, fd,
					  errno, NULL));
	break;
      }
  else if (res > 0)
    {
      UINT32 left = res;
    
      while (fd->super.alive && fd->read && left)
	{
	  UINT32 done;

	  /* FIXME: What to do if want_read is false? */
	  assert(fd->want_read);
	  assert(self->handler);

	  /* NOTE: This call may replace self->handler */
	  done = READ_HANDLER(self->handler, left, buffer);

	  buffer += done;
	  left -= done;

	  if (fd->want_read && !self->handler)
	    {
	      werror("do_buffered_read: Handler disappeared! Ignoring %i bytes\n",
		     left);
	      fd->want_read = 0;
	      return;
	    }
	}

      if (left)
	verbose("read_buffered(): fd died, %i buffered bytes discarded\n",
		left);
    }
  else
    {
      /* We have read EOF. Pass available == 0 to the handler */
      assert(fd->super.alive);
      assert(fd->read);
      assert(fd->want_read);
      assert(self->handler);

      close_fd_nicely(fd, 0);
      READ_HANDLER(self->handler, 0, NULL);
    }
	
}

struct io_callback *
make_buffered_read(UINT32 buffer_size,
		   struct read_handler *handler)
{
  NEW(io_buffered_read, self);

  self->super.f = do_buffered_read;
  self->buffer_size = buffer_size;
  self->handler = handler;

  return &self->super;
}

static void
do_consuming_read(struct io_callback *c,
		  struct lsh_fd *fd)
{
  CAST_SUBTYPE(io_consuming_read, self, c);
  UINT32 wanted = READ_QUERY(self);

  if (!wanted)
    {
      fd->want_read = 0;
    }
  else
    {
      struct lsh_string *s = lsh_string_alloc(wanted);
      int res = read(fd->fd, s->data, wanted);

      if (res < 0)
	switch(errno)
	  {
	  case EINTR:
	    break;
	  case EWOULDBLOCK:
	    werror("io.c: read_consume: Unexpected EWOULDBLOCK\n");
	    break;
	  case EPIPE:
	    /* FIXME: I don't understand why reading should return
	     * EPIPE, but it happens occasionally under linux. Perhaps
	     * we should treat it as EOF instead? */
	    werror("io.c: read_consume: Unexpected EPIPE.\n");
	  default:
	    EXCEPTION_RAISE(fd->e, 
			    make_io_exception(EXC_IO_READ,
					      fd, errno, NULL));
	    break;
	  }
      else if (res > 0)
	{
	  s->length = res;
	  A_WRITE(self->consumer, s);
	}
      else
	{
	  close_fd_nicely(fd, 0);
	  A_WRITE(self->consumer, NULL);
	}
      
    }
}

/* NOTE: Doesn't initialize the query field. That should be done in
 * the subclass's constructor. */
void init_consuming_read(struct io_consuming_read *self,
			 struct abstract_write *consumer)
{
  self->super.f = do_consuming_read;
  self->consumer = consumer;
}


/* Write related callbacks */
static void
do_write_callback(struct io_callback *s UNUSED,
		  struct lsh_fd *fd)
{
  /* CAST(io_write_callback, self, s); */
  UINT32 size;
  int res;
  
  size = MIN(fd->write_buffer->end - fd->write_buffer->start,
	     fd->write_buffer->block_size);
  assert(size);
  
  res = write(fd->fd,
	      fd->write_buffer->buffer + fd->write_buffer->start,
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
	werror("io.c: write failed, %z\n", STRERROR(errno));
	EXCEPTION_RAISE(fd->e,
			make_io_exception(EXC_IO_WRITE, fd, errno, NULL));
	close_fd(fd, CLOSE_WRITE_FAILED);
	
	break;
      }
  else
    write_buffer_consume(fd->write_buffer, res);
}  

static struct io_callback io_write_callback =
{ STATIC_HEADER, do_write_callback };

static void
do_write_prepare(struct lsh_fd *fd)
{
  /* CAST(io_write_callback, self, s); */

  assert(fd->write_buffer);

  if (! (fd->want_write = write_buffer_pre_write(fd->write_buffer))
      && fd->write_buffer->closed)
    close_fd(fd, CLOSE_EOF);
}

static void
do_write_close(struct lsh_fd *fd)
{
  /* CAST(io_write_callback, self, s); */

  assert(fd->write_buffer);

  write_buffer_close(fd->write_buffer);
}

struct listen_value *
make_listen_value(struct lsh_fd *fd,
		  struct address_info *peer)
{
  NEW(listen_value, self);

  self->fd = fd;
  self->peer = peer;

  return self;
}


/* Listen callback */

/* GABA:
   (class
     (name io_listen_callback)
     (super io_callback)
     (vars
       (backend object io_backend)
       (c object command_continuation)
       (e object exception_handler)))
*/

static void
do_listen_callback(struct io_callback *s,
		   struct lsh_fd *fd)
{
  CAST(io_listen_callback, self, s);

#if WITH_IPV6
  struct sockaddr_storage peer;
#else
  struct sockaddr peer;
#endif

  socklen_t addr_len = sizeof(peer);
  int conn;

  conn = accept(fd->fd,
		(struct sockaddr *) &peer, &addr_len);
  if (conn < 0)
    {
      werror("io.c: accept() failed, %z", STRERROR(errno));
      return;
    }
  trace("io.c: accept() on fd %i\n", conn);
  COMMAND_RETURN(self->c,
		 make_listen_value(make_lsh_fd(self->backend,
					       conn, self->e),
				   sockaddr2info(addr_len,
						 (struct sockaddr *) &peer)));
}

struct io_callback *
make_listen_callback(struct io_backend *backend,
		     struct command_continuation *c,
		     struct exception_handler *e)
{
  NEW(io_listen_callback, self);
  self->super.f = do_listen_callback;
  self->backend = backend;
  self->c = c;
  self->e = e;
  
  return &self->super;
}


/* Connect callback */

/* GABA:
   (class
     (name io_connect_callback)
     (super io_callback)
     (vars
       (c object command_continuation)))
*/

static void
do_connect_callback(struct io_callback *s,
		    struct lsh_fd *fd)
{
  CAST(io_connect_callback, self, s);
  int socket_error;
  socklen_t len = sizeof(socket_error);
  
  /* Check if the connection was successful */
  if ((getsockopt(fd->fd, SOL_SOCKET, SO_ERROR,
		  (char *) &socket_error, &len) < 0)
      || socket_error)
    {
      debug("io.c: connect_callback: Connect failed.\n");
      EXCEPTION_RAISE(fd->e,
		      make_io_exception(EXC_IO_CONNECT, fd, 0, "connect() failed."));
      kill_fd(fd);
    }
  else
    {
      fd->write = NULL;
      fd->want_write = 0;
      COMMAND_RETURN(self->c, fd);
    }
}

static struct io_callback *
make_connect_callback(struct command_continuation *c)
{
  NEW(io_connect_callback, self);

  self->super.f = do_connect_callback;
  self->c = c;

  return &self->super;
}


/* This function is called if a connection this file somehow depends
 * on disappears. For instance, the connection may have spawned a
 * child process, and this file may be the stdin of that process. */

/* To kill a file, mark it for closing and the backend will do the work. */
static void do_kill_fd(struct resource *r)
{
  CAST_SUBTYPE(lsh_fd, fd, r);

  /* NOTE: We use the zero close reason for files killed this way.
   * Close callbacks are still called, but they should probably not do
   * anything if reason == 0. */
  if (r->alive)
    close_fd(fd, 0);
}

/* Closes the file on i/o errors, and passes the exception on */

static void
do_exc_io_handler(struct exception_handler *self,
		  const struct exception *x)
{
  if (x->type & EXC_IO)
    {
      CAST_SUBTYPE(io_exception, e, x);

      if (e->fd)
	close_fd(e->fd, 0);
    }
  EXCEPTION_RAISE(self->parent, x);
  return;
}

/* Initializes a file structure, and adds it to the backend's list. */
static void init_file(struct io_backend *b, struct lsh_fd *f, int fd,
		      struct exception_handler *e)
{
  f->fd = fd;

  f->e = make_exception_handler(do_exc_io_handler, e, HANDLER_CONTEXT);
  
  f->close_reason = -1; /* Invalid reason */
  f->close_callback = NULL;

  f->prepare = NULL;

  f->want_read = 0;
  f->read = NULL;

  f->want_write = 0;
  f->write = NULL;
  f->write_close = NULL;
  
  f->super.alive = 1;
  f->super.kill = do_kill_fd;

  f->next = b->files;
  b->files = f;
}


/* Blocking read from a file descriptor (i.e. don't use the backend).
 * The fd should *not* be in non-blocking mode. */

/* FIXME: How to do this when moving from return codes to exceptions? */

/* FIXME: The entire blocking_read mechanism should be replaced by
 * ordinary commands and non-blocking i/o command. Right now, it is
 * used to read key-files, so that change probably has to wait until
 * the parser is rewritten. */


#define BLOCKING_READ_SIZE 4096

int blocking_read(int fd, struct read_handler *handler)
{  
  UINT8 *buffer = alloca(BLOCKING_READ_SIZE);
  
  for (;;)
    {
      int res = read(fd, buffer, BLOCKING_READ_SIZE);
      if (res < 0)
	switch(errno)
	  {
	  case EINTR:
	    break;
	  case EWOULDBLOCK:
	    fatal("blocking_read: Unexpected EWOULDBLOCK! fd in non-blocking mode?\n");
	  default:
	    werror("blocking_read: read() failed (errno = %i): %z\n",
		   errno, strerror(errno));
	    return 0;
	  }
      else if (!res)
	return 1;
      else
	{
	  UINT32 got = res;
	  UINT32 done = 0;

	  while (handler
		 && (done < got))
	    done += READ_HANDLER(handler, got - done, buffer + done);
	}
    }
  /* FIXME: Not reached. Hmm. */
  close(fd);
  return !handler;
}


/* These functions are used by werror() and friends */

/* For fd:s in blocking mode. */
const struct exception *
write_raw(int fd, UINT32 length, const UINT8 *data)
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
	    return make_io_exception(EXC_IO_BLOCKING_WRITE,
				     NULL, errno, NULL);
	  }
      
      length -= written;
      data += written;
    }
  return NULL;
}

const struct exception *
write_raw_with_poll(int fd, UINT32 length, const UINT8 *data)
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
	    return make_io_exception(EXC_IO_BLOCKING_WRITE,
				     NULL, errno, NULL);
	  }
      
      written = write(fd, data, length);

      if (written < 0)
	switch(errno)
	  {
	  case EINTR:
	  case EAGAIN:
	    continue;
	  default:
	    return make_io_exception(EXC_IO_BLOCKING_WRITE,
				     NULL, errno, NULL);
	  }
      
      length -= written;
      data += written;
    }
  return NULL;
}


/* Network utility functions */

/* Converts a string port number or service name to a port number.
 * Returns the port number in _host_ byte order, or 0 if lookup
 * fails. */

int get_portno(const char *service, const char *protocol)
{
  if (service == NULL)
    return 0;
  else
    {
      char *end;
      long portno;

      portno = strtol(service, &end, 10);
      if (portno > 0
	  &&  portno <= 65535
	  &&  end != service
	  &&  *end == '\0')
	  return portno;
      else
	{
	  struct servent * serv;

	  serv = getservbyname(service, protocol);
	  if (!serv)
	    return 0;
	  return ntohs(serv->s_port);
	}
    }
}

#if 0
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
get_inaddr(struct sockaddr	* addr,
	   const char		* host,
	   const char		* service,
	   const char		* protocol)
{
  /* HERE!!! IPv6 */
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

/* FIXME: IPv6 support */
/* FIXME: The host name lookup may block. We would need an asyncronous
 * get_inaddr function. As a work around, we could let the client do
 * all lookups, so that the server need only deal with ip-numbers. And
 * optionally refuse requests with dns names. */

int tcp_addr(struct sockaddr_in *sin,
	     UINT32 length,
	     UINT8 *addr,
	     UINT32 port)
{
  char *c;
  int res;

  if (addr)
    {
      c = alloca(length + 1);
  
      memcpy(c, addr, length);
      c[length] = '\0';
    }
  else
    c = NULL;
  
  res = get_inaddr(sin, c, NULL, "tcp");
  if (!res)
    return 0;

  sin->sin_port = htons(port);
  return 1;
}
#endif

/* If def != 0, use that value as a fallback if the lookup fails. */
struct address_info *
make_address_info_c(const char *host,
		    const char *port,
		    int def)
{
  int portno = get_portno(port, "tcp");
  if (!portno)
    portno = def;

  if (!portno)
    return NULL;

  else
    {
      NEW(address_info, info);
      
      info->port = portno;
      info->ip = host ? ssh_format("%lz", host) : NULL;
      
      return info;
    }
}

struct address_info *
make_address_info(struct lsh_string *host, UINT32 port)
{
  NEW(address_info, info);

  info->port = port; /* htons(port); */
  info->ip = host;
  return info;
}

struct address_info *
sockaddr2info(size_t addr_len UNUSED,
	      struct sockaddr *addr)
{
  NEW(address_info, info);
  
  switch(addr->sa_family)
    {
    case AF_INET:
      {
	struct sockaddr_in *in = (struct sockaddr_in *) addr;
	UINT32 ip = ntohl(in->sin_addr.s_addr);
	info->port = ntohs(in->sin_port);
	info->ip = ssh_format("%di.%di.%di.%di",
			      (ip >> 24) & 0xff,
			      (ip >> 16) & 0xff,
			      (ip >> 8) & 0xff,
			      ip & 0xff);
	return info;
      }
#if WITH_IPV6
    case AF_INET6:
      {
	struct sockaddr_in6 *in = (struct sockaddr_in6 *) addr;
	UINT8 *ip = in->sin6_addr.s6_addr;
	info->port = ntohs(in->sin6_port);
	info->ip = ssh_format("%xi:%xi:%xi:%xi:%xi:%xi:%xi:%xi",
			      (ip[0]  << 8) | ip[1],
			      (ip[2]  << 8) | ip[3],
			      (ip[4]  << 8) | ip[5],
			      (ip[6]  << 8) | ip[7],
			      (ip[8]  << 8) | ip[9],
			      (ip[10] << 8) | ip[11],
			      (ip[12] << 8) | ip[13],
			      (ip[14] << 8) | ip[15]);
	return info;
      }
#endif
    default:
      fatal("io.c: format_addr(): Unsupported address family.\n");
    }
}

#if HAVE_GETADDRINFO
static struct addrinfo *
choose_address(struct addrinfo *list,
	       const int *preference)
{
  int i;
  for (i = 0; preference[i]; i++)
    {
      struct addrinfo *p;
      for (p = list; p; p = p->ai_next)
	if (preference[i] == p->ai_family)
	  return p;
    }
  return NULL;
}
#endif /* HAVE_GETADDRINFO */

/* FIXME: Perhaps this function should be changed to return a list of
 * sockaddr:s? */
struct sockaddr *
address_info2sockaddr(socklen_t *length,
		      struct address_info *a,
		      /* Preferred address families. Zero-terminated array. */
		      const int *preference,
		      int lookup)
{
  char *host;

  if (a->ip)
    {
      host = alloca(a->ip->length + 1);
  
      memcpy(host, a->ip->data, a->ip->length);
      host[a->ip->length] = '\0';
    }
  else
    host = NULL;
  
#if HAVE_GETADDRINFO
  {
    struct addrinfo hints;
    struct addrinfo *list;
    struct addrinfo *chosen;
    struct sockaddr *res;
    const int default_preference
#if WITH_IPV6
      [3] = { AF_INET6, AF_INET }
#else
      [2] = { AF_INET, 0 }
#endif      
      ;
    int err;
    /* FIXME: It seems ugly to have to convert the port number to a
     * string. */
    struct lsh_string *service = ssh_format("%di%c", a->port, 0);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if (!lookup)
      hints.ai_flags |= AI_NUMERICHOST;
    
    err = getaddrinfo(host, service->data, &hints, &list);
    lsh_string_free(service);

    if (err)
      {
	debug("address_info2sockaddr: getaddrinfo failed (err = %d): %s\n",
	      err, gai_strerror(err));
	return NULL;
      }

    chosen = choose_address(list,
			    preference ? preference : default_preference);
    if (!chosen)
      {
	freeaddrinfo(list);
	return NULL;
      }
    
    *length = chosen->ai_addrlen;
    
    res = lsh_space_alloc(*length);
    memcpy(res, chosen->ai_addr, *length);
    freeaddrinfo(list);

    return res;
  }
#else /* !HAVE_GETADDRINFO */

#if WITH_IPV6
#warning IPv6 enabled, but getaddrinfo() was not found. 
#endif

  if (a->ip && memchr(a->ip->data, ':', a->ip->length))
    {
      debug("address_info2sockaddr: Literal IPv6 used. Failing.\n");
      return NULL;
    }
  else
    {
      struct sockaddr_in *addr;
      NEW_SPACE(addr);

      *length = sizeof(*addr);
      addr->sin_port = htons(a->port);
    
      if (!host)
	{
	  /* Use INADDR_ANY (and IPv4 only) */

	  addr->sin_family = AF_INET;
	  addr->sin_addr.s_addr = INADDR_ANY;

	  return (struct sockaddr *) addr;
	}
      else
	{
	  /* First check for numerical ip-number */
#if HAVE_INET_ATON
	  if (!inet_aton(host, &addr->sin_addr))
#else /* !HAVE_INET_ATON */
	    /* NOTE: It is wrong to work with ((unsigned long int) -1)
	     * directly, as this breaks Linux/Alpha systems. But
	     * INADDR_NONE isn't portable. That's what inet_aton is for;
	     * see the GNU libc documentation. */
# ifndef INADDR_NONE
# define INADDR_NONE ((unsigned long int) -1)
# endif /* !INADDR_NONE */
	  addr->sin_addr.s_addr = inet_addr(host);
	  if (addr->sin_addr.s_addr == INADDR_NONE)
#endif  /* !HAVE_INET_ATON */
	    {
	      struct hostent *hp;

	      if (! (lookup 
		     && (hp = gethostbyname(host))
		     && (hp->h_addrtype == AF_INET)))
		{
		  lsh_space_free(addr);
		  return NULL;
		}

	      memcpy(&addr->sin_addr, hp->h_addr, hp->h_length);
	    }
	  return (struct sockaddr *) addr;
	}
    }
#endif /* !HAVE_GETADDRINFO */  
}


void io_set_nonblocking(int fd)
{
  int old = fcntl(fd, F_GETFL);

  if (old < 0)
    fatal("io_set_nonblocking: fcntl(F_GETFL) failed, %z", STRERROR(errno));
  
  if (fcntl(fd, F_SETFL, old | O_NONBLOCK) < 0)
    fatal("io_set_nonblocking: fcntl(F_SETFL) failed, %z", STRERROR(errno));
}

void io_set_close_on_exec(int fd)
{
  /* NOTE: There's only one documented flag bit, so reading the old
   * value should be redundant. */
  
  int old = fcntl(fd, F_GETFD);

  if (old < 0)
    fatal("io_set_nonblocking: fcntl(F_GETFD) failed, %z", STRERROR(errno));
  
  if (fcntl(fd, F_SETFD, old | 1) < 0)
    fatal("Can't set close-on-exec flag for fd %i: %z\n",
	  fd, STRERROR(errno));
}


/* ALL file descripters handled by the backend should use non-blocking mode,
 * and have the close-on-exec flag set. */

void io_init_fd(int fd)
{
  io_set_nonblocking(fd);
  io_set_close_on_exec(fd);
}

struct lsh_fd *
make_lsh_fd(struct io_backend *b,
	    int fd,
	    struct exception_handler *e)
{
  NEW(lsh_fd, f);

  io_init_fd(fd);
  init_file(b, f, fd, e);

  return f;
}

/* Some code is taken from Thomas Bellman's tcputils. */
struct lsh_fd *
io_connect(struct io_backend *b,
	   struct sockaddr *remote,
	   socklen_t remote_length,
	   struct command_continuation *c,
	   struct exception_handler *e)
{
  int s = socket(remote->sa_family, SOCK_STREAM, 0);
  struct lsh_fd *fd;
  
  if (s<0)
    return NULL;

  trace("io.c: Connecting using fd %i\n", s);
  
  io_init_fd(s);

#if 0
  if (local  &&  bind(s, (struct sockaddr *)local, sizeof *local) < 0)
    {
      int saved_errno = errno;
      close(s);
      errno = saved_errno;
      return NULL;
    }
#endif
  
  if ( (connect(s, remote, remote_length) < 0)
       && (errno != EINPROGRESS) )       
    {
      int saved_errno = errno;
      close(s);
      errno = saved_errno;
      return NULL;
    }

  fd = make_lsh_fd(b, s, e);
  
  fd->want_write = 1;
  fd->write = make_connect_callback(c);
    
  return fd;
}

struct lsh_fd *
io_listen(struct io_backend *b,
	  struct sockaddr *local,
	  socklen_t length,
	  struct io_callback *callback,
	  struct exception_handler *e)
{
  int s = socket(local->sa_family, SOCK_STREAM, 0);
  struct lsh_fd *fd;
  
  if (s<0)
    return NULL;

  trace("io.c: Listening on fd %i\n", s);
  
  io_init_fd(s);

  {
    int yes = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char*)&yes, sizeof yes);
  }

  if (bind(s, (struct sockaddr *)local, length) < 0)
    {
      close(s);
      return NULL;
    }

  if (listen(s, 256) < 0) 
    {
      close(s);
      return NULL;
    }

  /* FIXME: What handler to use? */
  fd = make_lsh_fd(b, s, e);

  fd->want_read = 1;
  fd->read = callback;

  return fd;
}


/* AF_LOCAL sockets */

static void
safe_popd(int old_cd, const char *directory)
{
  while (fchdir(old_cd) < 0)
    if (errno != EINTR)
      fatal("io.c: Failed to cd back from %z (errno = %i): %z\n",
	    directory, errno, STRERROR(errno));
      
  close(old_cd);
}

/* Changes the cwd, making sure that it it has reasonable permissions,
 * and that we can change back later. */
static int
safe_pushd(const char *directory,
	   int create)
{
  int old_cd;
  struct stat sbuf;

  if (create)
    {  
      /* First create the directory, in case it doesn't yet exist. */
      if ( (mkdir(directory, 0700) < 0)
	   && (errno != EEXIST) )
	{
	  werror("io.c: Creating directory %z failed "
		 "(errno = %i): %z\n", directory, errno, STRERROR(errno));
	}
    }
    
  /* cd to it, but first save old cwd */

  old_cd = open(".", O_RDONLY);
  if (old_cd < 0)
    {
      werror("io.c: open(\".\") failed.\n");
      return -1;
    }

  /* Test if we are allowed to cd to our current working directory. */
  while (fchdir(old_cd) < 0)
    if (errno != EINTR)
      {
	werror("io.c: fchdir(\".\") failed (errno = %i): %z\n",
	       errno, strerror(errno));
	close(old_cd);
	return -1;
      }

  /* As far as I have been able to determine, all checks for
   * fchdir:ability is performed at the time the directory was opened.
   * Even if the directory is chmod:et to zero, or unlinked, we can
   * probably fchdir to it later. */

  while (chdir(directory) < 0)
    if (errno != EINTR)
      {
	close(old_cd);
	return -1;
      }

  /* Check that it has reasonable permissions */
  if (stat(".", &sbuf) < 0)
    {
      werror("io.c: Failed to stat() \".\" (supposed to be %z).\n"
	     "  (errno = %i): %z\n", directory, errno, STRERROR(errno));

      safe_popd(old_cd, directory);
      return -1;
    }

  if (sbuf.st_uid != getuid())
    {
      werror("io.c: Socket directory %z not owned by user.\n", directory);

      safe_popd(old_cd, directory);
      return -1;
    }
    
  if (sbuf.st_mode & (S_IRWXG | S_IRWXO))
    {
      werror("io.c: Permission bits on %z are too loose.\n", directory);

            safe_popd(old_cd, directory);
      return -1;
    }

  return old_cd;
}


/* Requires DIRECTORY and NAME to be NUL-terminated */
struct lsh_fd *
io_listen_local(struct io_backend *b,
		struct lsh_string *directory,
		struct lsh_string *name,
		struct io_callback *callback,
		struct exception_handler *e)
{
  int old_cd;

  mode_t old_umask;
  struct sockaddr_un *local;
  socklen_t local_length;

  struct lsh_fd *fd;
  
  assert(directory && NUL_TERMINATED(directory));
  assert(name && NUL_TERMINATED(name));

  /* NAME should not be a plain filename, with no directory separators.
   * In particular, it should not be an absolute filename. */
  assert(!memchr(name->data, '/', name->length));

  local_length = OFFSETOF(struct sockaddr_un, sun_path) + name->length;
  local = alloca(local_length);

  local->sun_family = AF_UNIX;
  memcpy(local->sun_path, name->data, name->length);

  /* cd to it, but first save old cwd */

  old_cd = safe_pushd(directory->data, 1);
  if (old_cd < 0)
    return NULL;

  /* Ok, now the current directory should be a decent place for
   * creating a socket. */

  /* Try unlinking any existing file. */
  if ( (unlink(name->data) < 0)
       && (errno != ENOENT))
    {
      werror("io.c: unlink '%S'/'%S' failed (errno = %i): %z\n",
	     directory, name, errno, STRERROR(errno));
      safe_popd(old_cd, directory->data);
      return NULL;
    }

  /* We have to change the umask, as that's the only way to control
   * the permissions that bind() uses. */

  old_umask = umask(0770);

  /* Bind and listen */
  fd = io_listen(b, (struct sockaddr *) local, local_length, callback, e);
  
  /* Ok, now we restore umask and cwd */
  umask(old_umask);

  safe_popd(old_cd, directory->data);

  return fd;
}

/* Requires DIRECTORY and NAME to be NUL-terminated */
struct lsh_fd *
io_connect_local(struct io_backend *b,
		 struct lsh_string *directory,
		 struct lsh_string *name,
		 struct command_continuation *c,
		 struct exception_handler *e)
{
  int old_cd;

  struct sockaddr_un *addr;
  socklen_t addr_length;

  struct lsh_fd *fd;
  
  assert(directory && NUL_TERMINATED(directory));
  assert(name && NUL_TERMINATED(name));

  /* NAME should not be a plain filename, with no directory separators.
   * In particular, it should not be an absolute filename. */
  assert(!memchr(name->data, '/', name->length));

  addr_length = OFFSETOF(struct sockaddr_un, sun_path) + name->length;
  addr = alloca(addr_length);

  addr->sun_family = AF_UNIX;
  memcpy(addr->sun_path, name->data, name->length);

  /* cd to it, but first save old cwd */

  old_cd = safe_pushd(directory->data, 0);
  if (old_cd < 0)
    return NULL;
  
  fd = io_connect(b, (struct sockaddr *) addr, addr_length, c, e);

  safe_popd(old_cd, directory->data);

  return fd;
}

/* Constructors */

struct lsh_fd *
io_read_write(struct lsh_fd *fd,
	      struct io_callback *read,
	      UINT32 block_size,
	      struct close_callback *close_callback)
{
  trace("io.c: Preparing fd %i for reading and writing\n",
	fd->fd);
  
  /* Reading */
  fd->read = read;
  fd->want_read = !!read;
  
  /* Writing */
  fd->write_buffer = write_buffer_alloc(block_size);
  fd->write = &io_write_callback;

  fd->prepare = do_write_prepare;
  fd->write_close = do_write_close;
  
  /* Closing */
  fd->close_callback = close_callback;

  return fd;
}

struct lsh_fd *
io_read(struct lsh_fd *fd,
	struct io_callback *read,
	struct close_callback *close_callback)
{
  trace("io.c: Preparing fd %i for reading\n", fd->fd);
  
  /* Reading */
  fd->want_read = !!read;
  fd->read = read;
  
  fd->close_callback = close_callback;

  return fd;
}

struct lsh_fd *
io_write(struct lsh_fd *fd,
	 UINT32 block_size,
	 struct close_callback *close_callback)
{
  trace("io.c: Preparing fd %i for writing\n", fd->fd);
  
  /* Writing */
  fd->write_buffer = write_buffer_alloc(block_size);
  fd->write = &io_write_callback;

  fd->prepare = do_write_prepare;
  fd->write_close = do_write_close;

  fd->close_callback = close_callback;

  return fd;
}

struct lsh_fd *
io_write_file(struct io_backend *backend,
	      const char *fname, int flags, int mode,
	      UINT32 block_size,
	      struct close_callback *c,
	      struct exception_handler *e)
{
  int fd = open(fname, flags, mode);
  if (fd < 0)
    return NULL;

  return io_write(make_lsh_fd(backend, fd, e), block_size, c);
}

struct lsh_fd *
io_read_file(struct io_backend *backend,
	     const char *fname, 
	     struct exception_handler *e)
{
  int fd = open(fname, O_RDONLY);
  if (fd < 0)
    return NULL;

  return make_lsh_fd(backend, fd, e);
}

void kill_fd(struct lsh_fd *fd)
{
  fd->super.alive = 0;
}

void close_fd(struct lsh_fd *fd, int reason)
{
  trace("io.c: Marking fd %i for closing.\n", fd->fd);
  fd->close_reason = reason;
  kill_fd(fd);
}

void close_fd_nicely(struct lsh_fd *fd, int reason)
{
  /* Don't attempt to read any further. */
  /* FIXME: Is it safe to free the handler here? */

  fd->want_read = 0;
  fd->read = NULL;
  
  if (fd->write_close)
    /* Mark the write_buffer as closed */
    FD_WRITE_CLOSE(fd);
  else
    /* There's no data buffered for write. */
    kill_fd(fd);

  fd->close_reason = reason;
}


/* Responsible for handling the EXC_FINISH_READ exception. It should
 * be a parent to the connection related exception handlers, as for
 * instance the protocol error handler will raise the EXC_FINISH_READ
 * exception. */
/* GABA:
   (class
     (name exc_finish_read_handler)
     (super exception_handler)
     (vars
       (fd object lsh_fd)))
*/

static void
do_exc_finish_read_handler(struct exception_handler *s,
			   const struct exception *e)
{
  CAST(exc_finish_read_handler, self, s);
  switch(e->type)
    {
    case EXC_FINISH_READ:
      /* FIXME: What to do about the reason argument? */
      close_fd_nicely(self->fd, 0);
      break;
    case EXC_FINISH_IO:
      close_fd(self->fd, 0);
      break;
    default:
      EXCEPTION_RAISE(self->super.parent, e);
    }
}

struct exception_handler *
make_exc_finish_read_handler(struct lsh_fd *fd,
			     struct exception_handler *parent,
			     const char *context)
{
  NEW(exc_finish_read_handler, self);

  self->super.parent = parent;
  self->super.raise = do_exc_finish_read_handler;
  self->super.context = context;
  
  self->fd = fd;

  return &self->super;
}

struct exception finish_read_exception =
STATIC_EXCEPTION(EXC_FINISH_READ, "Finish i/o");

struct exception *
make_io_exception(UINT32 type, struct lsh_fd *fd, int error, const char *msg)
{
  NEW(io_exception, self);
  assert(type & EXC_IO);
  
  self->super.type = type;

  if (msg)
    self->super.msg = msg;
  else
    self->super.msg = error ? strerror(error) : "Unknown i/o error";

  self->error = error;
  self->fd = fd;
  
  return &self->super;
}
