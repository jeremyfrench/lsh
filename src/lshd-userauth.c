/* lshd-userauth.c
 *
 * Main program for the ssh-userauth service.
 *
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 2005 Niels Möller
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

#include "nettle/macros.h"

#include "lsh_string.h"
#include "format.h"
#include "ssh.h"
#include "werror.h"

#define HEADER_SIZE 8

/* We use blocking i/o through out. */
static struct lsh_string *
read_packet(void)
{
  uint8_t header[HEADER_SIZE];
  uint32_t seqno;
  uint32_t length;
  struct lsh_string *packet;
  uint32_t done;

  for (done = 0; done < HEADER_SIZE; )
    {
      int res;
      do
	res = read(STDIN_FILENO, header + done, HEADER_SIZE - done);
      while (res < 0 && errno == EINTR);
      if (res <= 0)
	{
	  if (res == 0)
	    werror("read_packet: End of file after %i header octets.\n",
		   done);
	  else
	    werror("read_packet: read failed after %i header octets: %e\n",
		   done, errno);

	  return NULL;
	}
      done += res;
    }
  
  seqno = READ_UINT32(header);
  length = READ_UINT32(header + 4);

  if (length > SSH_MAX_PACKET)
    {
      werror("lshd-userauth: Too large packet.\n");
      return NULL;
    }
  packet = lsh_string_alloc(length);

  for (done = 0; done < length; )
    {
      int res;
      do
	res = lsh_string_read(packet, done, STDIN_FILENO, length - done);
      while (res < 0 && errno == EINTR);
      if (res <= 0)
	{
	  if (res == 0)
	    werror("read_packet: End of file after %i data octets.\n",
		   done);
	  else
	    werror("read_packet: read failed after %i data octets: %e\n",
		   done, errno);
	  
	  lsh_string_free(packet);
	  return NULL;
	}
      done += res;
    }
  return packet;
}

static int
write_packet(struct lsh_string *packet)
{
  uint32_t done;
  const uint8_t *data;
  uint32_t length;
  
  packet = ssh_format("%i%fS", lsh_string_sequence_number(packet), packet);

  length = lsh_string_length(packet);
  data = lsh_string_data(packet);

  for (done = 0; done < length; )
    {
      int res;
      do
	res = write(STDOUT_FILENO, data + done, length - done);
      while (res < 0 && errno == EINTR);

      assert (res != 0);
      if (res < 0)
	{
	  werror("write_packet: write failed: %e\n", errno);
	  lsh_string_free(packet);
	  return 0;
	}
      done += res;      
    }
  lsh_string_free(packet);
  return 1;  
}

int main(int argc, char **argv)
{
  werror("Started userauth service.\n");
  for (;;)
    {
      struct lsh_string *packet = read_packet();
      if (!packet)
	exit(EXIT_FAILURE);

      werror("Received packet.\n");
      
      if (!write_packet(ssh_format("%c%i%c",
				   SSH_MSG_USERAUTH_FAILURE, 0, 0)))
	exit(EXIT_FAILURE);
    }
}
