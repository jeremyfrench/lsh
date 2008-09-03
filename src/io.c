/* io.c
 *
 */

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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <errno.h>
#include <string.h>

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
/* For the popen code */
#include <sys/wait.h>
#include <sys/ioctl.h>

/* Needed for FIONREAD on Solaris */
#if HAVE_SYS_FILIO_H
#include <sys/filio.h>
#endif

#include <arpa/inet.h>

#include "io.h"

#include "format.h"
#include "lsh_string.h"
#include "werror.h"
#include "xalloc.h"

#define GABA_DEFINE
#include "io.h.x"
#undef GABA_DEFINE

#include "io.c.x"

/* Glue to liboop */

#define WITH_LIBOOP_SIGNAL_ADAPTER 1

/* Because of signal handlers, there can be only one oop object. */
static oop_source_sys *global_oop_sys = NULL;
#if WITH_LIBOOP_SIGNAL_ADAPTER
static oop_adapter_signal *global_oop_signal = NULL;
#endif
oop_source *global_oop_source = NULL;
static unsigned global_nfiles = 0;


/* OOP Callbacks */
static void *
lsh_oop_signal_callback(oop_source *s UNUSED, int sig, void *data)
{
  CAST(lsh_signal_handler, self, (struct lsh_object *) data);

  trace("lsh_oop_signal_callback: Signal %i, handler: %t\n",
	sig, self->action);
  
  assert(sig == self->signum);
  
  LSH_CALLBACK(self->action);

  return OOP_CONTINUE;
}

static void
lsh_oop_register_signal(struct lsh_signal_handler *handler)
{
  trace("lsh_oop_register_signal: signal: %i, handler: %t\n",
	handler->signum, handler);
  
  assert(global_oop_source);
  if (handler->super.alive)
    global_oop_source->on_signal(global_oop_source, handler->signum,
		      lsh_oop_signal_callback, handler);
}

static void
lsh_oop_cancel_signal(struct lsh_signal_handler *handler)
{
  trace("lsh_oop_cancel_signal: signal: %i, handler: %t\n",
	handler->signum, handler);

  assert(global_oop_source);
  if (handler->super.alive)
    global_oop_source->cancel_signal(global_oop_source, handler->signum,
			  lsh_oop_signal_callback, handler);
}

static void *
lsh_oop_time_callback(oop_source *source UNUSED,
                      struct timeval time UNUSED, void *data)
{
  CAST(lsh_callout, callout, (struct lsh_object *) data);

  assert(callout->super.alive);

  trace("lsh_oop_time_callback: action: %t\n",
        callout->action);
  
  callout->super.alive = 0;

  LSH_CALLBACK(callout->action);

  return OOP_CONTINUE;
}

static void
lsh_oop_register_callout(struct lsh_callout *callout)
{
  assert(global_oop_source);
  trace("lsh_oop_register_callout: action: %t\n",
        callout->action);

  if (callout->super.alive)
    global_oop_source->on_time(global_oop_source, callout->when, lsh_oop_time_callback, callout);
}

static void
lsh_oop_cancel_callout(struct lsh_callout *callout)
{
  assert(global_oop_source);
  trace("lsh_oop_cancel_callout: action: %t\n",
        callout->action);
  if (callout->super.alive)
    global_oop_source->cancel_time(global_oop_source, callout->when, lsh_oop_time_callback, callout);
}

static void *
lsh_oop_stop_callback(oop_source *source UNUSED,
                      struct timeval time UNUSED, void *data UNUSED)
{
  trace("lsh_oop_stop_callback\n");
  
  if (!global_nfiles)
    /* An arbitrary non-NULL value stops oop_sys_run. */
    return OOP_HALT;
  else
    return OOP_CONTINUE;
}

static void
lsh_oop_stop(void)
{
  assert(global_oop_source);
  trace("lsh_oop_stop\n");
  global_oop_source->on_time(global_oop_source, OOP_TIME_NOW, lsh_oop_stop_callback, NULL);
}

static void
lsh_oop_cancel_stop(void)
{
  assert(global_oop_source);
  trace("lsh_oop_cancel_stop\n");
  global_oop_source->cancel_time(global_oop_source, OOP_TIME_NOW, lsh_oop_stop_callback, NULL);
}

/* Increments the count of active files, and sets the non-blocking and
   close-on-exec if appropriate. With the exception of stdio
   file descriptors, all file descripters handled by the backend should
   have the close-on-exec flag set and use non-blocking mode. */
void
io_register_fd(int fd, const char *label)
{
  trace("io_register_fd: fd = %i: %z\n", fd, label);

  if (fd > STDERR_FILENO)
    {
      io_set_close_on_exec(fd);
      io_set_nonblocking(fd);      
    }
  global_nfiles++;
}

/* Closes an fd registered as above. Stdio file descriptors are
   treated specially. */
void
io_close_fd(int fd)
{  
  if (fd < 0)
    return;

  trace("io_close_fd: fd = %i\n", fd);

  global_oop_source->cancel_fd(global_oop_source, fd, OOP_READ);
  global_oop_source->cancel_fd(global_oop_source, fd, OOP_WRITE);

  if (fd == STDERR_FILENO)
    /* Do nothing */
    ;
  else if (close(fd) < 0)
    werror("Closing fd %i failed: %e.\n", fd, errno);
  
  else if (fd <= STDOUT_FILENO)
    {
      int null = open("/dev/null", O_RDWR);
      if (null < 0)
	fatal("Failed to open /dev/null!\n");
      if (null != fd)
	fatal("Failed to map stdio fd %i to /dev/null.\n", fd);
    }

  assert(global_nfiles);
  if (!--global_nfiles)
    lsh_oop_stop();
}


void
io_init(void)
{
  struct sigaction pipe;
  memset(&pipe, 0, sizeof(pipe));

  pipe.sa_handler = SIG_IGN;
  sigemptyset(&pipe.sa_mask);
  pipe.sa_flags = 0;
  
  if (sigaction(SIGPIPE, &pipe, NULL) < 0)
    fatal("Failed to ignore SIGPIPE.\n");

  assert(!global_oop_sys);
  global_oop_sys = oop_sys_new();
  if (!global_oop_sys)
    fatal("Failed to initialize liboop oop_sys.\n");

#if WITH_LIBOOP_SIGNAL_ADAPTER
  global_oop_signal = oop_signal_new(oop_sys_source(global_oop_sys));
  if (!global_oop_signal)
    fatal("Failed to initialize liboop oop_signal.\n");
  global_oop_source = oop_signal_source(global_oop_signal);
#else
  global_oop_source = oop_sys_source(global_oop_sys);
#endif
}

void
io_run(void)
{
  void *res = oop_sys_run(global_oop_sys);

  /* We need liboop-0.8, OOP_ERROR is not defined in liboop-0.7. */

  if (res == OOP_ERROR)
    werror("oop_sys_run %e\n", errno);

  trace("io_run: Cleaning up\n");

  gc_final();

  /* The final gc may have closed some files, and called lsh_oop_stop.
   * So we must unregister that before deleting the oop source. */
  lsh_oop_cancel_stop();

  /* There mustn't be any outstanding callbacks left. */
  assert(global_nfiles == 0);
  
#if WITH_LIBOOP_SIGNAL_ADAPTER
  oop_signal_delete(global_oop_signal);
  global_oop_signal = NULL;
#endif
  oop_sys_delete(global_oop_sys);
  global_oop_sys = NULL;
  global_oop_source = NULL;
}


/* Calls trigged by a signal handler. */
/* GABA:
   (class
     (name lsh_signal_handler)
     (super resource)
     (vars
       (signum . int)
       (action object lsh_callback)))
*/

/* GABA:
   (class
     (name lsh_callout)
     (super resource)
     (vars
       (when . "struct timeval")
       (action object lsh_callback)))
*/


static void
do_kill_signal_handler(struct resource *s)
{
  CAST(lsh_signal_handler, self, s);

  if (self->super.alive)
    {
      lsh_oop_cancel_signal(self);
      self->super.alive = 0;
    }
}

struct resource *
io_signal_handler(int signum,
		  struct lsh_callback *action)
{
  NEW(lsh_signal_handler, handler);

  init_resource(&handler->super, do_kill_signal_handler);

  handler->signum = signum;
  handler->action = action;

  lsh_oop_register_signal(handler);
  gc_global(&handler->super);
  
  return &handler->super;
}

static void
do_kill_callout(struct resource *s)
{
  CAST(lsh_callout, self, s);

  if (self->super.alive)
    {
      lsh_oop_cancel_callout(self);
      self->super.alive = 0;
    }
}

struct resource *
io_callout(struct lsh_callback *action, unsigned seconds)
{
  NEW(lsh_callout, self);
  init_resource(&self->super, do_kill_callout);

  if (seconds)
    {
      /* NOTE: Using absolute times, like oop does, is a little
       * dangerous if the system time is changed abruptly. */
      if (gettimeofday(&self->when, NULL) < 0)
	fatal("io_callout: gettimeofday failed!\n");
      self->when.tv_sec += seconds;
    }
  else
    self->when = OOP_TIME_NOW;
  
  self->action = action;
      
  lsh_oop_register_callout(self);
  
  gc_global(&self->super);
  return &self->super;
}

static void
kill_io_fd_resource(struct resource *s)
{
  CAST_SUBTYPE(io_fd_resource, self, s);
  if (self->super.alive)
    {
      self->super.alive = 0;

      io_close_fd(self->fd);
      self->fd = -1;
    }
}

void
init_io_connect_state(struct io_connect_state *self,
		      void (*done)(struct io_connect_state *self, int fd),
		      void (*error)(struct io_connect_state *self, int err))
{
  init_resource(&self->super.super, kill_io_fd_resource);
  self->super.fd = -1;
  self->done = done;
  self->error = error;
}

static void *
oop_io_connect(oop_source *source UNUSED,
	       int fd, oop_event event, void *state)
{
  CAST_SUBTYPE(io_connect_state, self, (struct lsh_object *) state);
  int socket_error = 0;
  socklen_t len = sizeof(socket_error);

  assert(self->super.fd == fd);
  assert(event == OOP_WRITE);

  global_oop_source->cancel_fd(global_oop_source, fd, OOP_WRITE);

  /* Check if the connection was successful */
  if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *) &socket_error, &len) < 0
      || socket_error)
    {
      self->error(self, socket_error);
    }
  else
    {
      self->super.fd = -1;
      self->done(self, fd);
    }

  KILL_RESOURCE(&self->super.super);
  return OOP_CONTINUE;
}

int
io_connect(struct io_connect_state *self,
	   socklen_t addr_length,
	   struct sockaddr *addr)
{
  assert(self->super.fd < 0);
  self->super.fd = socket(addr->sa_family, SOCK_STREAM, 0);

  if (self->super.fd < 0)
    return 0;

  io_register_fd(self->super.fd, "connect fd");
  
  if (connect(self->super.fd, addr, addr_length) < 0 && errno != EINPROGRESS)
    {
      int saved_errno = errno;

      KILL_RESOURCE(&self->super.super);
      errno = saved_errno;

      return 0;
    }

  global_oop_source->on_fd(global_oop_source, self->super.fd, OOP_WRITE, oop_io_connect, self);
  gc_global(&self->super.super);
  return 1;
}


/* Listening */
void
init_io_listen_port(struct io_listen_port *self, int fd,
		    void (*accept)(struct io_listen_port *self,
				   int fd,
				   socklen_t addr_len,
				   const struct sockaddr *addr))
{
  init_resource(&self->super.super, kill_io_fd_resource);

  io_register_fd(fd, "listen port");

  self->super.fd = fd;
  self->accept = accept;  
}

static void *
oop_io_accept(oop_source *source UNUSED,
	      int fd, oop_event event, void *state)
{
  CAST_SUBTYPE(io_listen_port, self, (struct lsh_object *) state);

#if WITH_IPV6
  struct sockaddr_storage peer;
#else
  struct sockaddr_in peer;
#endif

  socklen_t peer_length = sizeof(peer);
  int s;
  
  assert(event == OOP_READ);
  assert(self->super.fd == fd);

  s = accept(fd, (struct sockaddr *) &peer, &peer_length);
  if (s < 0)
    werror("accept failed, fd = %i: %e\n", fd, errno);

  else
    self->accept(self, s, peer_length, (struct sockaddr *) &peer);

  return OOP_CONTINUE;
}

int
io_listen(struct io_listen_port *self)
{
  if (listen(self->super.fd, 256) < 0)
    return 0;

  global_oop_source->on_fd(global_oop_source, self->super.fd, OOP_READ,
			   oop_io_accept, self);

  return 1;
}


/* These functions are used by werror and friends */

/* For fd:s in blocking mode. On error, see errno. */
int
write_raw(int fd, uint32_t length, const uint8_t *data)
{
  while (length)
    {
      int written = write(fd, data, length);
      if (written < 0)
	{
	  if (errno == EINTR)
	    continue;
	  else
	    return 0;
	}
      length -= written;
      data += written;
    }
  return 1;
}

struct lsh_string *
io_read_file_raw(int fd, uint32_t guess)
{
  struct lsh_string *buffer = lsh_string_alloc(guess);
  uint32_t pos = 0;
  
  for (;;)
    {
      uint32_t left = lsh_string_length(buffer) - pos;
      int res;

      if (!left)
	{
	  /* Roughly double the size of the buffer */
	  
	  buffer = lsh_string_realloc(buffer, 2*pos + 100);
	  left = lsh_string_length(buffer) - pos;
	}

      res = lsh_string_read(buffer, pos, fd, left);
      
      if (res < 0)
        {
          if (errno == EINTR)
            continue;

	  lsh_string_free(buffer);
          return NULL;
        }
      else if (!res)
        {
          /* EOF */
	  lsh_string_trunc(buffer, pos);
	  return buffer;
        }
      assert( (unsigned) res <= left);
      
      pos += res;
    }
}

int
io_readable_p(int fd)
{
#if HAVE_IOCTL_FIONREAD
  int nbytes = 0;
  if (ioctl(fd, FIONREAD, &nbytes) < 0)
    {
      debug("ioctl FIONREAD failed: %e\n", errno);
      return 0;
    }
  return nbytes != 0;
#else /* ! HAVE_IOCTL_FIONREAD */
  return 0;
#endif /* !HAVE_IOCTL_FIONREAD */
}

/* Network utility functions */

/* Converts a string port number or service name to a port number.
 * Returns the port number in _host_ byte order, or 0 if lookup
 * fails. */

unsigned
get_portno(const char *service, const char *protocol)
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

struct address_info *
make_address_info(struct lsh_string *host, uint32_t port)
{
  NEW(address_info, info);

  info->port = port;
  info->ip = host;
  return info;
}

/* FIXME: Review need for this function. And maybe also the need for
   the address_info type? */
struct address_info *
sockaddr2info(size_t addr_length,
              const struct sockaddr *addr)
{
  NEW(address_info, info);
  
  switch(addr->sa_family)
    {
    case AF_INET:
      assert(addr_length == sizeof(struct sockaddr_in));
      {
        const struct sockaddr_in *in = (const struct sockaddr_in *) addr;
        uint32_t ip = ntohl(in->sin_addr.s_addr);
        
        info->port = ntohs(in->sin_port);
        info->ip = ssh_format("%di.%di.%di.%di",
                              (ip >> 24) & 0xff,
                              (ip >> 16) & 0xff,
                              (ip >> 8) & 0xff,
                              ip & 0xff);
      }
      return info;
      
#if WITH_IPV6
    case AF_INET6:
      assert(addr_length == sizeof(struct sockaddr_in6));
      {
        const struct sockaddr_in6 *in = (const struct sockaddr_in6 *) addr;

        info->port = ntohs(in->sin6_port);
        info->ip = lsh_string_ntop(addr->sa_family, INET6_ADDRSTRLEN,
                                   &in->sin6_addr);

      }
      return info;
#endif /* WITH_IPV6 */

    default:
      fatal("io.c: sockaddr2info: Unsupported address family.\n");
    }
}

/* Creates a sockaddr. Only handles ip-addresses, no dns names. This
   is a simplified version of address_info2sockaddr. */
struct sockaddr *
io_make_sockaddr(socklen_t *lenp, const char *ip, unsigned port)
{
  struct sockaddr *sa;
  int res;

  if (!ip)
    {
      werror("io_make_sockaddr: NULL ip address!\n");
      return NULL;
    }
  if (port >= 0x10000)
    {
      werror("io_make_sockaddr: Invalid port %i.\n", port);
      return NULL;
    }

#if WITH_IPV6
  if (strchr(ip, ':'))
    {
      /* IPv6 */
      struct sockaddr_in6 *sin6;
      NEW_SPACE(sin6);
      
      sin6->sin6_family = AF_INET6;
      sin6->sin6_port = htons(port);
      res = inet_pton(AF_INET6, ip, &sin6->sin6_addr);

      *lenp = sizeof(*sin6);
      sa = (struct sockaddr *) sin6;
    }
  else
#endif
    {
      /* IPv4 */
      struct sockaddr_in *sin;
      NEW_SPACE(sin);
      
      sin->sin_family = AF_INET;
      sin->sin_port = htons(port);
      res = inet_pton(AF_INET, ip, &sin->sin_addr);

      *lenp = sizeof(*sin);
      sa = (struct sockaddr *) sin;
    }
  if (res < 0)
    {
      werror("inet_pton failed for address type %i: %e.\n",
	     sa->sa_family, errno);

      lsh_space_free(sa);
      return NULL;
    }
  else if (!res)
    {
      werror("Invalid address for address type %i.\n",
	     sa->sa_family);
      lsh_space_free(sa);
      return NULL;
    }

  return sa;
}

/* Translating a dns name to an IP address. We don't currently support
   DNS names in tcpip forwarding requests, so all names have to be
   translated by the client. */

struct address_info *
io_lookup_address(const char *ip, const char *service)
{
  struct address_info *addr;
  const char *last_dot;
  
  assert(ip);

  if (strchr(ip, ':'))
    {
      /* Raw IPv6 address */
      unsigned port;

    raw_address:

      port = get_portno(service, "tcp");
      if (port > 0)
	return make_address_info(make_string(ip), port);
      else return 0;
    }

  /* Difference between a dns name and an ip address is that the ip
     address is dotted, and the final component starts with a
     digit. */
  last_dot = strrchr(ip, '.');
  if (last_dot && last_dot[1] >= '0' && last_dot[1] <= '9')
    /* Raw IPv4 address */
    goto raw_address;

  /* So, it looks like a domain name. Look it up. */
#if HAVE_GETADDRINFO
  {
    struct addrinfo hints;
    struct addrinfo *list;
    struct addrinfo *p;
    int err;
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    err = getaddrinfo(ip, service, &hints, &list);
    if (err)
      {
      	werror("io_address_lookup: getaddrinfo failed: %z\n",
	      gai_strerror(err));
	return 0;
      }

    addr = NULL;
    
    /* We pick only one address, and prefer IPv4 */
    for (p = list; p; p = p->ai_next)
      {
	if (p->ai_family == AF_INET)
	  {
	    struct sockaddr_in *sin = (struct sockaddr_in *) p->ai_addr;
	    assert(p->ai_addrlen == sizeof(*sin));
	    
	    addr = make_address_info(lsh_string_ntop(AF_INET, INET_ADDRSTRLEN,
						     &sin->sin_addr),
				     ntohs(sin->sin_port));

	    break;
	  }
      }
#if WITH_IPV6
    if (!addr)
      for (p = list; p; p = p->ai_next)
      {
	if (p->ai_family == AF_INET6)
	  {
	    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) p->ai_addr;
	    assert(p->ai_addrlen == sizeof(*sin6));
	    
	    addr = make_address_info(lsh_string_ntop(AF_INET6, INET6_ADDRSTRLEN,
						     &sin6->sin6_addr),
				     ntohs(sin6->sin6_port));

	    break;
	  }
      }
#endif
    freeaddrinfo(list);
    
    if (!addr)
      {
	werror("No internet address found.\n");
	return NULL;
      }

    return addr;
  }
#else
#error At the moment, getaddrinfo is required
#endif
}

static void
handle_nonblock_error(const char *msg)
{
  /* On BSD, trying to set /dev/null in nonblocking mode fails with
   * errno 19, ENODEV. We have to ignore that.
   *
   * And on FreeBSD 5, the error code is changed to ENOTTY, for the
   * same problem.
   *
   * For now, still display a warning message, to keep track of when
   * and where it occurs.
   */
  if (errno == ENODEV || errno == ENOTTY)
    werror("%z %e\n", msg, errno);
  else
    fatal("%z %e\n", msg, errno);
}

void
io_set_nonblocking(int fd)
{
  int old = fcntl(fd, F_GETFL);

  if (old < 0)
    fatal("io_set_nonblocking: fcntl(F_GETFL) failed: %e\n", errno);
  
  if (fcntl(fd, F_SETFL, old | O_NONBLOCK) < 0)
    handle_nonblock_error("io_set_nonblocking: fcntl(F_SETFL) failed");
}

void
io_set_close_on_exec(int fd)
{
  /* NOTE: There's only one documented flag bit, so reading the old
   * value should be redundant. */
  
  int old = fcntl(fd, F_GETFD);

  if (old < 0)
    fatal("io_set_close_on_exec: fcntl(F_GETFD) failed %e\n", errno);
  
  if (fcntl(fd, F_SETFD, old | 1) < 0)
    fatal("Can't set close-on-exec flag for fd %i %e\n", fd, errno);
}


/* AF_LOCAL sockets */

struct local_info *
make_local_info(const struct lsh_string *directory,
		const struct lsh_string *name)
{
  if (!directory || !name
      || memchr(lsh_string_data(name), '/', lsh_string_length(name)))
    return NULL;

  assert(lsh_get_cstring(directory));
  assert(lsh_get_cstring(name));
  
  {
    NEW(local_info, self);
    self->directory = directory;
    self->name = name;
    return self;
  }
}

void
lsh_popd(int old_cd, const char *directory)
{
  while (fchdir(old_cd) < 0)
    if (errno != EINTR)
      fatal("io.c: Failed to cd back from %z %e\n",
	    directory, errno);
      
  close(old_cd);
}

int
lsh_pushd_fd(int dir)
{
  int old_cd;

  /* cd to it, but first save old cwd */

  old_cd = open(".", O_RDONLY);
  if (old_cd < 0)
    {
      werror("io.c: open(`.') failed.\n");
      return -1;
    }

  io_set_close_on_exec(old_cd);

  /* Test if we are allowed to cd to our current working directory. */
  while (fchdir(old_cd) < 0)
    if (errno != EINTR)
      {
	werror("io.c: fchdir(`.') failed %e\n", errno);
	close(old_cd);
	return -1;
      }

  /* As far as I have been able to determine, all checks for
   * fchdir:ability is performed at the time the directory was opened.
   * Even if the directory is chmod:et to zero, or unlinked, we can
   * probably fchdir back to old_cd later. */

  while (fchdir(dir) < 0)
    if (errno != EINTR)
      {
	close(old_cd);
	return -1;
      }

  return old_cd;
}

/* Changes the cwd, making sure that it it has reasonable permissions,
 * and that we can change back later. */
int
lsh_pushd(const char *directory,
	  /* The fd to the directory is stored in *FD, unless fd is
	   * NULL */
	  int *result,
	  int create, int secret)
{
  int old_cd;
  int fd;
  struct stat sbuf;

  if (create)
    {  
      /* First create the directory, in case it doesn't yet exist. */
      if ( (mkdir(directory, 0700) < 0)
	   && (errno != EEXIST) )
	{
	  werror("io.c: Creating directory %z failed "
		 "%e\n", directory, errno);
	}
    }

  fd = open(directory, O_RDONLY);
  if (fd < 0)
    return -1;

  io_set_close_on_exec(fd);
  
  if (fstat(fd, &sbuf) < 0)
    {
      werror("io.c: Failed to stat `%z'.\n"
	     "  %e\n", directory, errno);
      close(fd);
      return -1;
    }
  
  if (!S_ISDIR(sbuf.st_mode))
    {
      close(fd);
      return -1;
    }

  if (secret)
    {
      /* Check that it has reasonable permissions */
      if (sbuf.st_uid != getuid())
	{
	  werror("io.c: Socket directory %z not owned by user.\n", directory);

	  close(fd);
	  return -1;
	}
    
      if (sbuf.st_mode & (S_IRWXG | S_IRWXO))
	{
	  werror("io.c: Permission bits on %z are too loose.\n", directory);

	  close(fd);
	  return -1;
	}
    }
  
  /* cd to it, but first save old cwd */

  old_cd = open(".", O_RDONLY);
  if (old_cd < 0)
    {
      werror("io.c: open('.') failed.\n");

      close(fd);
      return -1;
    }

  io_set_close_on_exec(old_cd);

  /* Test if we are allowed to cd to our current working directory. */
  while (fchdir(old_cd) < 0)
    if (errno != EINTR)
      {
	werror("io.c: fchdir(\".\") failed %e\n", errno);
	close(fd);
	close(old_cd);
	return -1;
      }

  /* As far as I have been able to determine, all checks for
   * fchdir:ability is performed at the time the directory was opened.
   * Even if the directory is chmod:et to zero, or unlinked, we can
   * probably fchdir back to old_cd later. */

  while (fchdir(fd) < 0)
    if (errno != EINTR)
      {
	close(fd);
	close(old_cd);
	return -1;
      }

  if (result)
    *result = fd;
  else
    close(fd);
  
  return old_cd;
}

int
io_bind_sockaddr(struct sockaddr *addr, socklen_t addr_length)
{
  int yes = 1;
  int fd;

  fd = socket(addr->sa_family, SOCK_STREAM, 0);
  if (fd < 0)
    return -1;

  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char*)&yes, sizeof(yes)) < 0)
    werror("setsockopt failed: %e\n", errno);

  if (bind(fd, addr, addr_length) < 0)
    {
      close(fd);
      return -1;
    }

  return fd;
}

int
io_bind_local(const struct local_info *info)
{
  int old_cd;

  mode_t old_umask;
  struct sockaddr_un *local;
  socklen_t local_length;

  int fd;

  const char *cdir = lsh_get_cstring(info->directory);
  const char *cname = lsh_get_cstring(info->name);
  uint32_t length = lsh_string_length(info->name);
  
  assert(cdir);
  assert(cname);

  /* NAME should not be a plain filename, with no directory separators.
   * In particular, it should not be an absolute filename. */
  assert(!memchr(cname, '/', length));

  local_length = offsetof(struct sockaddr_un, sun_path) + length;
  local = alloca(local_length + 1);

  local->sun_family = AF_UNIX;
  memcpy(local->sun_path, cname, length);
  local->sun_path[length] = 0;
  
  /* cd to it, but first save old cwd */

  old_cd = lsh_pushd(cdir, NULL, 1, 1);
  if (old_cd < 0)
    return -1;

  /* Ok, now the current directory should be a decent place for
   * creating a socket. */

  /* Try unlinking any existing file. */
  if ( (unlink(cname) < 0)
       && (errno != ENOENT))
    {
      werror("io.c: unlink '%S'/'%S' failed %e\n",
	     info->directory, info->name, errno);
      lsh_popd(old_cd, cdir);
      return -1;
    }

  /* We have to change the umask, as that's the only way to control
   * the permissions that bind uses. */

  old_umask = umask(0077);

  fd = io_bind_sockaddr((struct sockaddr *) local, local_length);
  
  /* Ok, now we restore umask and cwd */
  umask(old_umask);

  lsh_popd(old_cd, cdir);

  return fd;
}

/* Uses a blocking connect */
int
io_connect_local(const struct local_info *info)
{
  int old_cd;
  int fd;
  int res;

  struct sockaddr_un *addr;
  socklen_t addr_length;

  const char *cdir = lsh_get_cstring(info->directory);
  const char *cname = lsh_get_cstring(info->name);
  uint32_t length = lsh_string_length(info->name);

  assert(cname);
  assert(cdir);

  /* NAME should be a plain filename, with no directory separators. In
   * particular, it should not be an absolute filename. */
  assert(!memchr(cname, '/', length));

  addr_length = offsetof(struct sockaddr_un, sun_path) + length;
  addr = alloca(addr_length);

  addr->sun_family = AF_UNIX;
  memcpy(addr->sun_path, cname, length);

  /* cd to it, but first save old cwd */

  old_cd = lsh_pushd(cdir, NULL, 0, 1);
  if (old_cd < 0)
    return -1;

  fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0)
    return -1;

  do
    res = connect(fd, (struct sockaddr *) addr, addr_length);
  while (res < 0 && errno == EINTR);

  lsh_popd(old_cd, cdir);

  if (res < 0)
    {
      close(fd);
      return -1;
    }
  return fd;
}


/* Creates a one-way socket connection. Returns 1 on success, 0 on
 * failure. fds[0] is for reading, fds[1] for writing (like for the
 * pipe system call). */
int
lsh_make_pipe(int *fds)
{
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0)
    {
      werror("socketpair failed: %e.\n", errno);
      return 0;
    }
  trace("Created socket pair. Using fd:s %i <-- %i\n", fds[0], fds[1]);

  if (SHUTDOWN_UNIX(fds[0], SHUT_WR) < 0)
    {
      werror("shutdown(%i, SHUT_WR) failed %e\n", fds[0], errno);
      goto fail;
    }
  if (SHUTDOWN_UNIX(fds[1], SHUT_RD) < 0)
    {
      werror("shutdown(%i, SHUT_RD) failed %e\n", fds[0], errno);
    fail:
      {
	int saved_errno = errno;

	close(fds[0]);
	close(fds[1]);

	errno = saved_errno;
	return 0;
      }
    }
  
  return 1;
}

/* Forks a filtering process, and reads the output. Always closes
   the IN fd. */
struct lsh_string *
lsh_popen_read(const char *program, const char **argv, int in,
	       unsigned guess)
{
  /* 0 for read, 1 for write */
  int out[2];
  pid_t pid;
  
  if (!lsh_make_pipe(out))
    {
      close(in);
      return NULL;
    }
  pid = fork();

  if (pid < 0)
    {
      close(in);
      close(out[0]);
      close(out[1]);
      return NULL;
    }
  else if (!pid)
    {
      /* Child */
      if (dup2(in, STDIN_FILENO) < 0)
	{
	  werror("lsh_popen: dup2 for stdin failed %e.\n", errno);
	  _exit(EXIT_FAILURE);
	}
      if (dup2(out[1], STDOUT_FILENO) < 0)
	{
	  werror("lsh_popen: dup2 for stdout failed %e.\n", errno);
	  _exit(EXIT_FAILURE);
	}

      close(in);
      close(out[0]);
      close(out[1]);

      /* The execv prototype uses const in the wrong way */
      execv(program, (char **) argv);

      werror("lsh_popen_read: execv `%z' failed %e.\n", program, errno);

      _exit(EXIT_FAILURE);
    }
  else
    {
      /* Parent process */
      struct lsh_string *s;
      int status;
      
      close(in);
      close(out[1]);

      s = io_read_file_raw(out[0], guess);

      if (waitpid(pid, &status, 0) < 0)
	{
	  werror("lsh_popen_read: waitpid failed: %e\n", errno);
	  lsh_string_free(s);
	  return NULL;
	}

      if (!s)
	return NULL;

      if (WIFEXITED(status))
	{
	  if (!WEXITSTATUS(status))
	    /* Success. */
	    return s;

	  werror("Program `%z' exited with status %i.\n",
		 program, WEXITSTATUS(status));
	}
      else
	werror("Program `%z' terminated by signal %i (%z).\n",
	       program, WTERMSIG(status), STRSIGNAL(WTERMSIG(status)));

      lsh_string_free(s);
      return NULL;
    }
}

/* Forks a filtering process. Writes DATA as the filter's stdin, and
   redirects stdout to OUT. The OUT fd is not closed. */
int
lsh_popen_write(const char *program, const char **argv, int out,
		uint32_t length, const uint8_t *data)
{
  /* 0 for read, 1 for write */
  int fds[2];
  pid_t pid;
  
  if (!lsh_make_pipe(fds))
    return 0;

  pid = fork();

  if (pid < 0)
    {
      close(fds[0]);
      close(fds[1]);
      return 0;
    }

  else if (!pid)
    {
      /* Child */
      if (dup2(fds[0], STDIN_FILENO) < 0)
	{
	  werror("lsh_popen: dup2 for stdin failed %e.\n", errno);
	  _exit(EXIT_FAILURE);
	}
      if (dup2(out, STDOUT_FILENO) < 0)
	{
	  werror("lsh_popen: dup2 for stdout failed %e.\n", errno);
	  _exit(EXIT_FAILURE);
	}

      close(out);
      close(fds[0]);
      close(fds[1]);

      /* The execv prototype uses const in the wrong way */
      execv(program, (char **) argv);

      werror("lsh_popen_write: execv `%z' failed %e.\n", program, errno);

      _exit(EXIT_FAILURE);
    }
  else
    {
      /* Parent process */
      int status;
      int res;
      
      close(fds[0]);

      res = write_raw(fds[1], length, data);
      close(fds[1]);

      if (waitpid(pid, &status, 0) < 0)
	{
	  werror("lsh_popen_write: waitpid failed: %e\n", errno);
	  return 0;
	}

      if (!res)
	return 0;

      if (WIFEXITED(status))
	{
	  if (!WEXITSTATUS(status))
	    /* Success. */
	    return 1;

	  werror("Program `%z' exited with status %i.\n",
		 program, WEXITSTATUS(status));
	}
      else
	werror("Program `%z' terminated by signal %i (%z).\n",
	       program, WTERMSIG(status), STRSIGNAL(WTERMSIG(status)));

      return 0;
    }
}
