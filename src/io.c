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
#include <arpa/inet.h>
#include <signal.h>

#define GABA_DEFINE
#include "io.h.x"
#undef GABA_DEFINE

#include "io.c.x"

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

  nfds = 0;
  
  {
    /* Prepare fd:s. This phase calls the prepare-methods, also closes
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
		if (fd->close_callback)
		  CLOSE_CALLBACK(fd->close_callback, fd->close_reason);
		
		debug("Closing fd %i.\n", fd->fd);
		
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
#if 1
	if (fd->want_read || fd->want_write)
#endif
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
  active_fds = alloca(sizeof(struct lsh_fd *) *nfds);
  
  /* Fill out fds-array */
  {
    struct lsh_fd *fd;
    unsigned long i;
    int all_events = 0;
    
    for (fd = b->files, i = 0; fd; fd = fd->next)
      {
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
#if 0
    if (!all_events)
      {
	/* Nothing happens */
	/* NOTE: There might be some callouts left, but we don't wait */
	return 0;
      }
#endif
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

	if (fds[i].revents & POLLNVAL)
	  {
	    werror("io.c: poll request on fd %i, for events of type %xi\n"
		   "      return POLLNVAL, revents = %xi\n",
		   fds[i].fd, fds[i].events, fds[i].revents);
	    kill_fd(fd);
	    continue;
	  }

	/* FIXME: POLLHUP is mutually exclusive with POLLOUT, but
	 * orthogonal to POLLIN. */
	if (fds[i].revents & POLLHUP)
	  {
	    if (fd->want_read)
	      READ_FD(fd);
	    else if (fd->want_write)
	      WRITE_FD(fd);
	    else
	      {
		werror("io.c: poll said POLLHUP on an inactive fd.\n");
		close_fd(fd, CLOSE_EOF);
	      }
	    continue;
	  }

	if (fds[i].revents & POLLPRI)
	  {
	    werror("io.c: Peer is trying to send Out of Band data. Hanging up.\n");

	    /* FIXME: Should we raise any exception here? */

	    close_fd(fd, CLOSE_PROTOCOL_FAILURE); 

	    continue;
	  }

	if (fds[i].revents & POLLOUT)
	  WRITE_FD(fd);

	if (!fd->super.alive)
	  continue;

	if (fds[i].revents & MY_POLLIN)
	  READ_FD(fd);
      }
    assert(i == nfds);
  }

  return 1;
}


static void do_buffered_read(struct io_read_callback *s,
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

struct io_read_callback *
make_buffered_read(UINT32 buffer_size,
		   struct read_handler *handler)
{
  NEW(io_buffered_read, self);

  self->super.read = do_buffered_read;
  self->buffer_size = buffer_size;
  self->handler = handler;

  return &self->super;
}

static void do_consuming_read(struct io_read_callback *c,
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
	    fatal("io.c: read_consume: Unexpected EPIPE.\n");
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
  self->super.read = do_consuming_read;
  self->consumer = consumer;
}
			 

static void write_callback(struct lsh_fd *fd)
{
  CAST(io_fd, self, fd);
  UINT32 size;
  int res;
  
  size = MIN(self->write_buffer->end - self->write_buffer->start,
	     self->write_buffer->block_size);
  assert(size);
  
  res = write(fd->fd,
	      self->write_buffer->buffer + self->write_buffer->start,
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
    write_buffer_consume(self->write_buffer, res);
}  

static void
do_listen_callback(struct io_read_callback *s UNUSED,
		   struct lsh_fd *fd)
{
  CAST(listen_fd, self, fd);
  struct sockaddr_in peer;
  size_t addr_len = sizeof(peer);
  int conn;

  conn = accept(fd->fd,
		(struct sockaddr *) &peer, &addr_len);
  if (conn < 0)
    {
      werror("io.c: accept() failed, %z", STRERROR(errno));
      return;
    }
  FD_LISTEN_CALLBACK(self->callback, conn, 
		     sockaddr2info(addr_len,
				   (struct sockaddr *) &peer));
}

static struct io_read_callback listen_callback =
{ STATIC_HEADER, do_listen_callback };

static void connect_callback(struct lsh_fd *fd)
{
  CAST(connect_fd, self, fd);
  int socket_error;
  size_t len = sizeof(socket_error);
  
  /* Check if the connection was successful */
  if ((getsockopt(fd->fd, SOL_SOCKET, SO_ERROR,
		  (char *) &socket_error, &len) < 0)
      || socket_error)
    {
      debug("io.c: connect_callback: Connect failed.\n");
      EXCEPTION_RAISE(fd->e,
		      make_io_exception(EXC_IO_CONNECT, fd, 0, "connect() failed."));
    }
  else
    {
      FD_CALLBACK(self->callback, fd->fd);

      /* To avoid actually closing the fd */
      fd->fd = -1;
    }
  kill_fd(fd);
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

  f->super.alive = 1;
  f->super.kill = do_kill_fd;
  f->really_close = NULL;

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
  char *buffer = alloca(BLOCKING_READ_SIZE);
  
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
  close(fd);
  return !handler;
}

/* Converts a string port number or service name to a port number.
 * Returns the port number in _host_ byte order, or -1 of the port
 * or service was invalid. */

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
	  if (serv == NULL)
	    return -1;
	  return ntohs(serv->s_port);
	}
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

struct address_info *make_address_info_c(const char *host,
					 const char *port)
{
  int portno = get_portno(port, "tcp");
  if (portno < 0)
    return 0;
  else
    {
      NEW(address_info, info);
      
      info->port = portno;
      info->ip = host ? ssh_format("%lz", host) : NULL;
      
      return info;
    }
}

struct address_info *make_address_info(struct lsh_string *host, UINT32 port)
{
  NEW(address_info, info);

  info->port = port; /* htons(port); */
  info->ip = host;
  return info;
}

struct address_info *sockaddr2info(size_t addr_len UNUSED,
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
#if 0
    case AF_INETv6:
      ...
#endif
    default:
      fatal("io.c: format_addr(): Unsupported address family.\n");
    }
}

int address_info2sockaddr_in(struct sockaddr_in *sin,
			     struct address_info *a)
{

  if (a->ip)
    return tcp_addr(sin,
		    a->ip->length, a->ip->data,
		    a->port);
  else
    return tcp_addr(sin, 0, NULL, a->port);
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

void io_set_nonblocking(int fd)
{
  if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0)
    fatal("io_set_nonblocking: fcntl() failed, %z", STRERROR(errno));
}

void io_set_close_on_exec(int fd)
{
  if (fcntl(fd, F_SETFD, 1) < 0)
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

/* Some code is taken from Thomas Bellman's tcputils. */
struct connect_fd *
io_connect(struct io_backend *b,
	   struct sockaddr_in *remote,
	   struct sockaddr_in *local,
	   struct fd_callback *f,
	   struct exception_handler *e)
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

    init_file(b, &fd->super, s, e);

    fd->super.want_write = 1;
    fd->super.write = connect_callback;
    fd->callback = f;
    
    return fd;
  }
}

struct listen_fd *
io_listen(struct io_backend *b,
	  struct sockaddr_in *local,
	  struct fd_listen_callback *callback,
	  struct exception_handler *e)
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

    /* FIXME: What handler to use? */
    init_file(b, &fd->super, s, e);
    
    fd->super.want_read = 1;
    fd->super.read = &listen_callback;
    fd->callback = callback;
    
    return fd;
  }
}

/* FIXME: Closing the write buffer should perhaps be done earlier,
 * from kill_fd(). */
static void really_close(struct lsh_fd *fd)
{
  CAST(io_fd, self, fd);

  assert(self->write_buffer);

  write_buffer_close(self->write_buffer);
}

static void prepare_write(struct lsh_fd *fd)
{
  CAST(io_fd, self, fd);

  assert(self->write_buffer);

  if (! (fd->want_write = write_buffer_pre_write(self->write_buffer))
      && self->write_buffer->closed)
    close_fd(fd, CLOSE_EOF);
}


/* Constructors */

struct io_fd *make_io_fd(struct io_backend *b,
			 int fd,
			 struct exception_handler *e)
{
  NEW(io_fd, f);

  io_init_fd(fd);
  init_file(b, &f->super, fd, e);

  return f;
}

struct io_fd *io_read_write(struct io_fd *fd,
			    struct io_read_callback *read,
			    UINT32 block_size,
			    struct close_callback *close_callback)
{
  struct write_buffer *buffer = write_buffer_alloc(block_size);

  debug("io.c: Preparing fd %i for reading and writing\n",
	fd->super.fd);
  
  /* Reading */
  fd->super.read = read;
  fd->super.want_read = !!read;
  
  /* Writing */
  fd->super.prepare = prepare_write;
  fd->super.write = write_callback;
  fd->write_buffer = buffer;

  /* Closing */
  fd->super.really_close = really_close;
  fd->super.close_callback = close_callback;

  return fd;
}

struct io_fd *io_read(struct io_fd *fd,
		      struct io_read_callback *read,
		      struct close_callback *close_callback)
{
  debug("io.c: Preparing fd %i for reading\n", fd->super.fd);
  
  /* Reading */
  fd->super.want_read = !!read;
  fd->super.read = read;
  
  fd->super.close_callback = close_callback;

  return fd;
}

struct io_fd *io_write(struct io_fd *fd,
		       UINT32 block_size,
		       struct close_callback *close_callback)
{
  struct write_buffer *buffer = write_buffer_alloc(block_size);

  debug("io.c: Preparing fd %i for writing\n", fd->super.fd);
  
  /* Writing */
  fd->super.prepare = prepare_write;
  fd->super.write = write_callback;
  fd->write_buffer = buffer;

  fd->super.close_callback = close_callback;

  return fd;
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

void close_fd_nicely(struct lsh_fd *fd, int reason)
{
  /* Don't attempt to read any further. */
  /* FIXME: Is it safe to free the handler here? */

  fd->want_read = 0;
  fd->read = NULL;
  
  if (fd->really_close)
    /* Mark the write_buffer as closed */
    REALLY_CLOSE_FD(fd);
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

struct io_fd *
io_write_file(struct io_backend *backend,
	      const char *fname, int flags, int mode,
	      UINT32 block_size,
	      struct close_callback *c,
	      struct exception_handler *e)
{
  int fd = open(fname, flags, mode);
  if (fd < 0)
    return NULL;

  return io_write(make_io_fd(backend, fd, e), block_size, c);
}

struct io_fd *
io_read_file(struct io_backend *backend,
	     const char *fname, 
	     struct exception_handler *e)
{
  int fd = open(fname, O_RDONLY);
  if (fd < 0)
    return NULL;

  return make_io_fd(backend, fd, e);
}
