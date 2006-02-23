/* lshd-pty-helper.c
 *
 * Helper program for managing pty:s. An unprivileged process
 * communicates with this program via a AF_UNIX socket. Either a named
 * socket, or socket pair(s) provided as stdin and stdout.
 */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>

void
die(const char *format, ...)
#if __GNUC___
     __attribute__((__format__ (__printf__,1, 2)))
     __attribute__((__noreturn__))
#endif
     ;

void
die(const char *format, ...)
{
  va_list args;
  va_start(args, format);
  vfprintf(stderr, format, args);
  va_end(args);

  exit(EXIT_FAILURE);
}

/* A request is a single type byte, and a SCM_CREDENTIALS control
   message. */
struct pty_request
{
  char type;
  pid_t pid;
  uid_t uid;
  gid_t gid;
};

/* The response includes the fd of the master side of the pty pair,
   and the name of the slave tty. It is sent as two messages, one with
   the fd and the length, and another with the tty name. Since the
   protocol is used only locally on a single machine, we send the
   length using whatever the native representation of an unsigned
   is. */

struct pty_response
{
  /* Master pty */
  int fd;
  unsigned tty_length;
  const char *tty_name;  
};

static int
recv_request(int fd, struct pty_request *request)
{
  struct msghdr msg;
  struct cmsghdr *cmsg;
  struct ucred creds;
  struct iovec io;
  int res;

  /* FIXME: Not portable to assume CMSG_SPACE expands to a constant
     expression. */
  char buf[CMSG_SPACE(sizeof(creds))];
  
  io.iov_base = &request->type;
  io.iov_len = sizeof(request->type);
  
  msg.msg_name = NULL;
  msg.msg_namelen = 0;
  msg.msg_iov = &io;
  msg.msg_iovlen = 1;
  msg.msg_control = buf;
  msg.msg_controllen = sizeof(buf);

  do
    res = recvmsg(fd, &msg, 0);
  while (res < 0 && errno == EINTR);

  if (res != 1)
    return 0;

  cmsg = CMSG_FIRSTHDR(&msg);

  if (cmsg->cmsg_level == SOL_SOCKET
      && cmsg->cmsg_type == SCM_CREDENTIALS
      && cmsg->cmsg_len == CMSG_LEN(sizeof(creds)))
    {
      /* No alignment guarantees, so use memcpy. */
      memcpy(&creds, CMSG_DATA(cmsg), sizeof(creds));
      request->pid = creds.pid;
      request->uid = creds.uid;
      request->gid = creds.gid;
      
      return 1;
    }

  return 0;
}

static int
send_response(int fd, const struct pty_response *response)
{
  struct msghdr msg;
  struct cmsghdr *cmsg;
  struct iovec io;
  int res;

  char buf[CMSG_SPACE(sizeof(response->fd))];

  io.iov_base = (void *) &response->tty_length;
  io.iov_len = sizeof(response->tty_length);

  msg.msg_name = NULL;
  msg.msg_namelen = 0;
  msg.msg_iov = &io;
  msg.msg_iovlen = 1;
  msg.msg_control = buf;
  msg.msg_controllen = sizeof(buf);

  cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(sizeof(response->fd));
  
  memcpy(CMSG_DATA(cmsg), &response->fd, sizeof(response->fd));

  do
    res = sendmsg(fd, &msg, 0);
  while (res < 0 && errno == EINTR);

  if (res != sizeof(response->tty_length))
    return 0;

  io.iov_base = (void *) response->tty_name;
  io.iov_len = response->tty_length;

  msg.msg_control = NULL;
  msg.msg_controllen = 0;

  do
    res = sendmsg(fd, &msg, 0);
  while (res < 0 && errno == EINTR);
  
  return (res == response->tty_length);
}

static int
process_request(const struct pty_request *request,
		struct pty_response *response)
{
  return 0;
}

int
main (int argc, char **argv)
{
  struct pty_request request;
  struct pty_response response;

  if (!recv_request(STDIN_FILENO, &request))
    die("Failed to recieve message.\n");

  if (!process_request(&request, &response))
    die("Pty processing failed.\n");
  if (!send_response(STDOUT_FILENO, &response))
    die("Failed to send message.\n");

  return EXIT_SUCCESS;  
}
