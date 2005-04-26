/* service.h
 *
 * Interface for the local ssh service protocol.
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

#ifndef LSH_SERVICE_H_INCLUDED
#define LSH_SERVICE_H_INCLUDED

#include "lsh.h"

struct service_read_state;

/* FIXME: 1. Reuse status codes with the transport layer. 2. It would
   be desirable to get the push indication together with the last read
   packet. To get that to work, the reader must be able to decrypt the
   next packet header. To do this, the handling of SSH_MSG_NEWKEYS
   must be moved down to the reader layer, which does make some
   sense. */

enum service_read_status
{
  /* Read error, errno value stored in *error. */
  SERVICE_READ_IO_ERROR = -1,
  /* Protocol error, SSH_DISCONNECT reson code stored in *error and
     error message in *msg. */
  SERVICE_READ_PROTOCOL_ERROR = -2,
  /* End of file reached. */
  SERVICE_READ_EOF = 0,
  /* Packet/line read successfully. */
  SERVICE_READ_COMPLETE = 1,
  /* There's more data available for the next read. */
  SERVICE_READ_PENDING = 2,
  /* No more data available now, so read data should be delivered
     immediately. */
  SERVICE_READ_PUSH = 3,
};

struct service_read_state *
make_service_read_state(void);

enum service_read_status
service_read_packet(struct service_read_state *self, int fd,
		    const char **msg,
		    uint32_t *seqno,
		    uint32_t *length, const uint8_t **packet);

#endif /* LSH_SERVICE_H_INCLUDED */
