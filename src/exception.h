/* exception.h
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

#ifndef LSH_EXCEPTION_H_INCLUDED
#define LSH_EXCEPTION_H_INCLUDED

#include "lsh.h"

#include "exception.h.x"

/* GABA:
   (class
     (name exception)
     (vars
       (type . UINT32)
       (msg . "const char *")))
*/

/* GABA:
   (class
     (name exception_handler)
     (vars
       (raise method void "const struct exception *")
       (parent object exception_handler)))
*/

#define EXCEPTION_RAISE(h, e)  ((h)->raise((h), (e)))

#define STATIC_EXCEPTION(type, name) \
{ STATIC_HEADER, (type), (name) }

/* Exception types. */

/* Used in places where no real exception is defined yet.
 * Never handled. */
#define EXC_DUMMY 0

/* Protocol errors */
#define EXC_PROTOCOL 0x1000

/* IO related errors */
#define EXC_IO 0x2000
#define EXC_CONNECT 0x2001
#define EXC_RESOLVE 0x2002
#define EXC_IO_BLOCKING_WRITE 0x2003

/* Not really errors */
/* EOF was read */
#define EXC_IO_EOF 0x2003

/* Authorization errors */
#define EXC_AUTH 0x4000
#define EXC_USERAUTH 0x4001

/* Services */
#define EXC_SERVICE 0x8000
#define EXC_GLOBAL_REQUEST 0x8001
#define EXC_CHANNEL_REQUEST 0x8002

/* Use subtypes for the different error codes? */
#define EXC_CHANNEL_OPEN 0x8003

/* Closing down things */
#define EXC_FINISH 0x10000
/* Close a channel */
#define EXC_FINISH_CHANNEL 0x10001
/* Stop reading on some fd */
#define EXC_FINISH_READ 0x10002


extern struct exception_handler default_exception_handler;
extern struct exception dummy_exception;

/* ;;GABA:
   (class
     (name exception_frame)
     (super exception_handler)
     (vars
       (parent object exception_handler)))
*/

struct exception *
make_simple_exception(UINT32 type, int name);

/* A protocol exception, that normally terminates the connection */
/* GABA:
   (class
     (name protocol_exception)
     (super exception)
     (vars
       ;; A reason code that can be passed in a SSH_MSG_DISCONNECT message.
       ;; Zero means terminate the connection without sending such a message.
       (reason . UINT32)))
*/


/* If msg is NULL, it is derived from the reason value */
struct exception *
make_protocol_exception(UINT32 reason, const char *msg);

#define STATIC_PROTOCOL_EXCEPTION(reason, msg) \
{ { STATIC_HEADER, EXC_PROTOCOL, (msg) }, (reason) }

#endif /* LSH_EXCEPTION_H_INCLUDED */
