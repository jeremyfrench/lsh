/* service_read.c
 *
 * oop-based reader for the local communication.
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005 Niels Möller
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

#include <errno.h>

#include <nettle/macros.h>

#include "ssh_read.h"

#include "lsh_string.h"
#include "ssh.h"
#include "werror.h"
#include "xalloc.h"

struct lsh_string *
service_process_header(struct ssh_read_state *self)
{
  uint32_t seqno;
  uint32_t length;
  struct lsh_string *packet;
  const uint8_t *header;

  header = lsh_string_data(self->header);

  seqno = READ_UINT32(header);
  length = READ_UINT32(header + 4);

  if (length > SSH_MAX_PACKET)
    {
      werror("service_process_header: Receiving too large packet.\n"
	     "  %i octets\n", length);

      self->io_error(self, EINVAL);
      return NULL;
    }

  packet = lsh_string_alloc(length);

  /* The sequence number is unused */
  lsh_string_set_sequence_number(packet, seqno);
  self->pos = 0;
  return packet;
}
