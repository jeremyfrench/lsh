/* pty-helper.c
 *
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 2006 Niels Möller
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

/* For CMSG_SPACE and friends on Solaris */
#define _XPG4_2

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

/* Only for debugging */
#include <stdio.h>

/* Linux: SCM_CREDENTIALS, struct ucred. BSD: SCM_CREDS, struct cmsgcred.  */
#include <sys/types.h>
#include <sys/socket.h>

/* Solaris ucred support, SCM_UCRED, ucred_t. */
#if HAVE_UCRED_H
#include <ucred.h>
#endif

/* At least Solaris 5.8 lacks CMSG_LEN and CMSG_SPACE. */
#ifndef CMSG_LEN
/* The safest way seems to be to extract the offset of the data */
# define CMSG_LEN(l) ((size_t) CMSG_DATA((struct cmsghdr *) 0) + (l))
#endif

#ifndef CMSG_SPACE
# if defined(__sparc) && defined(__sun__)
#  define CMSG_HDR_ALIGN(x) (((x) + 7) & ~7)
# else
#  define CMSG_HDR_ALIGN(x) (((x) + 3) & ~3)
# endif
# define CMSG_SPACE(l) CMSG_HDR_ALIGN(CMSG_LEN(l))
#endif

#include "pty-helper.h"

/* Returns 0 on success, errno value on error */
int
pty_send_message(int socket, const struct pty_message *message)
{
  struct msghdr hdr;
  struct cmsghdr *cmsg;
  struct iovec io;
  size_t creds_size;
  int controllen;
  int res;

  io.iov_base = (void *) &message->header;
  io.iov_len = sizeof(message->header);

#if defined (SCM_CREDENTIALS)
  creds_size = sizeof(struct ucred);
#elif defined (SCM_CREDS)
  creds_size = sizeof (struct cmsgcred);
#else
  creds_size = 0;
#endif

  hdr.msg_name = NULL;
  hdr.msg_namelen = 0;
  hdr.msg_iov = &io;
  hdr.msg_iovlen = 1;
  hdr.msg_controllen = CMSG_SPACE(creds_size) + CMSG_SPACE(sizeof(message->fd));
  hdr.msg_control = alloca(hdr.msg_controllen);

  cmsg = NULL;
  controllen = 0;

  if (message->has_creds)
    {
#if defined (SCM_CREDENTIALS)
      /* Linux style credentials */
      struct ucred *creds;

      cmsg = cmsg ? CMSG_NXTHDR(&hdr, cmsg) : CMSG_FIRSTHDR(&hdr);

      cmsg->cmsg_level = SOL_SOCKET;
      cmsg->cmsg_type = SCM_CREDENTIALS;
      cmsg->cmsg_len = CMSG_LEN(sizeof(*creds));

      creds = (struct ucred *) CMSG_DATA(cmsg);
      creds->pid = message->creds.pid;
      creds->uid = message->creds.uid;
      creds->gid = message->creds.gid;
	
      controllen += CMSG_SPACE(sizeof(*creds));
#elif defined (SCM_CREDS)
      /* BSD style credentials */
      cmsg = cmsg ? CMSG_NXTHDR(&hdr, cmsg) : CMSG_FIRSTHDR(&hdr);

      cmsg->cmsg_level = SOL_SOCKET;
      cmsg->cmsg_type = SCM_CREDS;
      cmsg->cmsg_len = CMSG_LEN(sizeof(struct cmsgcred));

      /* Data filled in by the kernel */
      controllen += CMSG_SPACE(sizeof(struct cmsgcred));      
#endif
    }

  if (message->fd != -1)
    {
      cmsg = cmsg ? CMSG_NXTHDR(&hdr, cmsg) : CMSG_FIRSTHDR(&hdr);

      cmsg->cmsg_level = SOL_SOCKET;
      cmsg->cmsg_type = SCM_RIGHTS;
      cmsg->cmsg_len = CMSG_LEN(sizeof(message->fd));

      memcpy(CMSG_DATA(cmsg), &message->fd, sizeof(message->fd));
      controllen += CMSG_SPACE(sizeof(message->fd));
    }
  hdr.msg_controllen = controllen;

  do
    res = sendmsg(socket, &hdr, 0);
  while (res < 0 && errno == EINTR);

  if (res < 0)
    return errno;

  if (res != sizeof(message->header))
    return EIO;

  if (message->header.length)
    {
      io.iov_base = message->data;
      io.iov_len = message->header.length;

      hdr.msg_control = NULL;
      hdr.msg_controllen = 0;

      do
	res = sendmsg(socket, &hdr, 0);
      while (res < 0 && errno == EINTR);

      if (res < 0)
	return errno;

      if (res != message->header.length)
	return EIO;
    }

  return 0;
}

#define PTY_MESSAGE_MAX_LENGTH 1000

/* Returns 0 on success, errno value on error, -1 on EOF */
int
pty_recv_message(int socket, struct pty_message *message)
{
  struct msghdr hdr;
  struct cmsghdr *cmsg;
  struct iovec io;
  size_t creds_size;
  int res;

#if defined (SCM_CREDENTIALS)
  creds_size = sizeof(struct ucred);
#elif defined (SCM_CREDS)
  creds_size = sizeof(struct cmsgcred);
#elif defined (SCM_UCRED)
  creds_size = ucred_size();
#else
  creds_size = 0;
#endif

  message->has_creds = 0;
  message->fd = -1;
  message->data = NULL;

  io.iov_base = &message->header;
  io.iov_len = sizeof(message->header);

  hdr.msg_name = NULL;
  hdr.msg_namelen = 0;
  hdr.msg_iov = &io;
  hdr.msg_iovlen = 1;
  hdr.msg_controllen = CMSG_SPACE(creds_size) + CMSG_SPACE(sizeof(message->fd));
  hdr.msg_control = alloca(hdr.msg_controllen);

  do
    res = recvmsg(socket, &hdr, 0);
  while (res < 0 && errno == EINTR);

  if (res < 0)
    return errno;

  if (res == 0)
    return -1;

  /* Process any ancillary data before examining the regular data */
  for (cmsg = CMSG_FIRSTHDR(&hdr); cmsg; cmsg = CMSG_NXTHDR(&hdr, cmsg))
    {
      if (cmsg->cmsg_level != SOL_SOCKET)
	continue;
      switch (cmsg->cmsg_type)
	{
#if defined (SCM_CREDENTIALS)
	case SCM_CREDENTIALS:
	  {
	    struct ucred *creds;
	    if (cmsg->cmsg_len != CMSG_LEN(sizeof(*creds)))
	      continue;

	    if (message->has_creds)
	      /* Shouldn't be multiple credentials, but if there are,
		 ignore all but the first. */
	      continue;

	    creds = (struct ucred *) CMSG_DATA(cmsg);
	    message->creds.pid = creds->pid;
	    message->creds.uid = creds->uid;
	    message->creds.gid = creds->gid;
	    
	    message->has_creds = 1;

	    break;
	  }
#elif defined (SCM_CREDS)
	case SCM_CREDS:
	  {
	    struct cmsgcred *creds;
	    if (cmsg->cmsg_len != CMSG_LEN(sizeof(*creds)))
	      continue;

	    if (message->has_creds)
	      /* Shouldn't be multiple credentials, but if there are,
		 ignore all but the first. */
	      continue;

	    creds = (struct cmsgcred *) CMSG_DATA(cmsg);
	    message->creds.pid = creds->cmcred_pid;
	    message->creds.uid = creds->cmcred_uid;
	    message->creds.gid = creds->cmcred_gid;
	    
	    message->has_creds = 1;
	    
	    break;
	  }
#elif defined (SCM_UCRED)
	case SCM_UCRED:
	  {
	    ucred_t *creds;

	    if (message->has_creds)
	      /* Shouldn't be multiple credentials, but if there are,
		 ignore all but the first. */
	      continue;

	    creds = (ucred_t *) CMSG_DATA(cmsg);
	    message->creds.pid = ucred_getpid(creds);
	    message->creds.uid = ucred_geteuid(creds);
	    message->creds.gid = ucred_getegid(creds);

	    message->has_creds = 1;

	    break;
	  }
#endif
	case SCM_RIGHTS:
	  {
	    int *fd = (int *) CMSG_DATA(cmsg);
	    int i = 0;

	    /* Is there any simple and portable way to get the number
	       of fd:s? */
	    
	    if (message->fd == -1 && CMSG_LEN(message->fd) <= cmsg->cmsg_len)
	      {
		message->fd = fd[i++];
		fprintf(stderr, "Got fd %d\n", message->fd);
	      }
	    /* We want only one fd; if we receive any more, close
	       them */
	    for (; CMSG_LEN( (i+1) * sizeof(message->fd)) <= cmsg->cmsg_len; i++)
	      {
		fprintf(stderr, "Got unwanted fd %d, closing\n", fd[i]);
		
		close(fd[i]);
	      }
	  }
	default:
	  /* Ignore */
	  ;
	}
    }
  if (res != sizeof(message->header))
    {
      if (message->fd != -1)
	{
	  close(message->fd);
	  message->fd = -1;
	}
      return EIO;
    }

  if (message->header.length)
    {
      if (message->header.length > PTY_MESSAGE_MAX_LENGTH
	  || !(message->data = malloc(message->header.length)))
	{
	  if (message->fd != -1)
	    {
	      close(message->fd);
	      message->fd = -1;
	    }
	  return ENOMEM;
	}

      io.iov_base = message->data;
      io.iov_len = message->header.length;

      hdr.msg_control = NULL;
      hdr.msg_controllen = 0;

      do
	res = recvmsg(socket, &hdr, 0);
      while (res < 0 && errno == EINTR);

      if (res != message->header.length)
	{
	  int err = (res < 0) ? errno : EIO;

	  /* Clean up */

	  if (message->fd != -1)
	    {
	      close(message->fd);
	      message->fd = -1;
	    }
	  free(message->data);
	  message->data = NULL;

	  return err;
	}
    }
  return 0;
}
