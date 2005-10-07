/* exception.h
 *
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998, 2002 Niels Möller
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

enum exception_type
{
  EXC_IO_ERROR = 1,	/* Subtype is errno */
  EXC_RESOLVE,
  EXC_GLOBAL_REQUEST,
  EXC_CHANNEL_REQUEST,
  EXC_CHANNEL_OPEN
};

#define GABA_DECLARE
#include "exception.h.x"
#undef GABA_DECLARE

/* GABA:
   (class
     (name exception)
     (vars
       (type . int)
       (subtype . int)
       (msg . "const char *")))
*/

#define STATIC_EXCEPTION(type, subtype, msg) \
{ STATIC_HEADER, (type), (subtype), (msg) }

/* GABA:
   (class
     (name exception_handler)
     (vars
       (raise method void "const struct exception *")

       ; Provide some context for debugging unhandled exceptions
       (context . "const char *")))
*/

#define HANDLER_CONTEXT   (__FILE__ ":" STRING_LINE)

#if DEBUG_TRACE
void exception_raise(struct exception_handler *e,
		     const struct exception *h,
		     const char *context);
#  define EXCEPTION_RAISE(h, e) exception_raise((h), (e), HANDLER_CONTEXT)
#else /* !DEBUG_TRACE */
#  define EXCEPTION_RAISE(h, e)  ((h)->raise((h), (e)))
#endif /* !DEBUG_TRACE */

#define DEFINE_EXCEPTION_HANDLER(name)				\
static void							\
do_##name(struct exception_handler *e,				\
	  const struct exception *x);				\
								\
struct exception_handler name =					\
{ STATIC_HEADER, do_##name, __FILE__ ":" STRING_LINE};	\
								\
static void							\
do_##name


extern struct exception_handler ignore_exception_handler;

#if 0
/* ;; GABA:
   (class
     (name report_exception_info)
     (vars
       (mask . uint32_t)
       (value . uint32_t)
       (prefix . "const char *")))
*/

struct report_exception_info *
make_report_exception_info(uint32_t mask, uint32_t value,
			   const char *prefix);

#define STATIC_REPORT_EXCEPTION_INFO(m, v, p) \
{ STATIC_HEADER, m, v, p }

struct exception_handler *
make_report_exception_handler(const struct report_exception_info *info,
			      struct exception_handler *parent,
			      const char *context);
#endif

struct exception *
make_exception(int type, int subtype, const char *msg);

#if 0
/* Create a simple exception handler, with no internal state */
struct exception_handler *
make_exception_handler(void (*raise)(struct exception_handler *s,
				     const struct exception *x),
		       struct exception_handler *parent,
		       const char *context);

/* A protocol exception, that normally terminates the connection */
/* ;;GABA:
   (class
     (name protocol_exception)
     (super exception)
     (vars
       ; A reason code that can be passed in a SSH_MSG_DISCONNECT message.
       ; Zero means terminate the connection without sending such a message.
       (reason . uint32_t)))
*/


/* If msg is NULL, it is derived from the reason value */
struct exception *
make_protocol_exception(uint32_t reason, const char *msg);

#define STATIC_PROTOCOL_EXCEPTION(reason, msg) \
{ { STATIC_HEADER, EXC_PROTOCOL, (msg) }, (reason) }

/* Always a static message */
#define PROTOCOL_ERROR(e, msg)			\
{						\
  static const struct protocol_exception _exc	\
    = { { STATIC_HEADER, EXC_PROTOCOL, (msg) },	\
        SSH_DISCONNECT_PROTOCOL_ERROR };	\
  EXCEPTION_RAISE((e), &_exc.super);		\
}

/* Always a static message */
#define PROTOCOL_ERROR_DISCONNECT(e, reason, msg)			\
{						\
  static const struct protocol_exception _exc	\
    = { { STATIC_HEADER, EXC_PROTOCOL, (msg) },	\
        (reason) };	\
  EXCEPTION_RAISE((e), &_exc.super);		\
}
#endif

#endif /* LSH_EXCEPTION_H_INCLUDED */
