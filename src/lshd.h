/* lshd.h
 *
 * Types used by the main server program.
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

#ifndef LSHD_H_INCLUDED
#define LSHD_H_INCLUDED

#include "abstract_io.h"
#include "keyexchange.h"
#include "publickey_crypto.h"
#include "resource.h"
#include "transport.h"
#include "ssh_read.h"
#include "ssh_write.h"

struct lshd_connection;

enum service_state
{
  /* Before key exchange, a service request is not acceptable. */
  SERVICE_DISABLED = 0,
  /* After key exchange, we accept a single service request. */
  SERVICE_ENABLED = 1,
  /* After the service is started, no more requests are allowed. */
  SERVICE_STARTED = 2
};

#define GABA_DECLARE
# include "lshd.h.x"
#undef GABA_DECLARE


/* GABA:
   (class
     (name lshd_service_read_state)
     (super ssh_read_state)
     (vars
       (connection object lshd_connection)))
*/

struct lshd_service_read_state *
make_lshd_service_read_state(struct lshd_connection *connection);


/* Information shared by several connections */
/* GABA:
   (class
     (name configuration)
     (super transport_context)
     (vars
       (keys object alist)
       ; For now, a list { name, program, name, program, NULL }       
       (services . "const char **")))
*/

/* GABA:
   (class
     (name lshd_connection)
     (super transport_connection)
     (vars
       (service_state . "enum service_state")
       
       ; Communication with service on top of the transport layer.
       ; This is a bidirectional pipe
       (service_fd . int)
       (service_reader object service_read_state)
       (service_read_active . int)
       (service_writer object ssh_write_state)
       (service_write_active . int)))
*/


#endif /* LSHD_H_INCLUDED */
