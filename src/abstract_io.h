/* abstract_io.h
 *
 * This is the layer separating protocol processing from actual io.
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

#ifndef LSH_ABSTRACT_IO_H_INCLUDED
#define LSH_ABSTRACT_IO_H_INCLUDED

#include "exception.h"

#define GABA_DECLARE
#include "abstract_io.h.x"
#undef GABA_DECLARE

/* A read-function returning n means:
 *
 * n > 0: n bytes were read successfully.
 * n = 0: No more data available, without blocking.
 * n = -1: Read failed.
 * n = -2: EOF.
 */
#define A_FAIL -1
#define A_EOF -2

/* GABA:
   (class
     (name abstract_read)
     (vars
       ;; FIXME: Should we allow that the read method is called with
       ;; length = 0? I think so.
       (read indirect-method int
             "UINT32 length" "UINT8 *buffer")))
*/

#define A_READ(f, length, buffer) (f)->read(&(f), (length), (buffer))


/* May store a new handler into *h. */

/* GABA:
   (class
     (name read_handler)
     (vars
       (handler indirect-method void "struct abstract_read *read")))
                                     ;; "struct exception_handler *io")))
*/

#define READ_HANDLER(h, read) ((h)->handler(&(h), (read)))

#if 0
/* Return values */
/* Everything's fine */
#define READ_OK 0
/* Can't process any more data right now; please hold */
#define READ_HOLD 1
/* Close nicely, after fluching the write buffer */
#define READ_CLOSE 2
/* Close immediately */
#define READ_DIE 3
#endif

/* GABA:
   (class
     (name abstract_write)
     (vars
       (write method void "struct lsh_string *packet" "struct exception_handler *e")))
*/

#define A_WRITE(f, packet, e) ((f)->write((f), (packet), (e)))

/* A handler that passes packets on to another handler */
/* GABA:
   (class
     (name abstract_write_pipe)
     (super abstract_write)
     (vars
       (next object abstract_write)))
*/

#endif /*LSH_ABSTRACT_IO_H_INCLUDED */
