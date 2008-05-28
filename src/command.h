/* command.h
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

#ifndef LSH_COMMAND_H_INCLUDED
#define LSH_COMMAND_H_INCLUDED

#include <stdarg.h>

#include "lsh.h"

#include "exception.h"
#include "list.h"

#define GABA_DECLARE
#include "command.h.x"
#undef GABA_DECLARE

/* Continuation based command execution. A command can take one object
 * as argument, and returns one object. */

/* GABA:
   (class
     (name command_continuation)
     (vars
       (c method void "struct lsh_object *result")))
*/

#define COMMAND_RETURN(r, v) ((r)->c((r), (struct lsh_object *) (v)))

/* GABA:
   (class
     (name command)
     (vars
       (call method void "struct lsh_object *arg"
                         "struct command_continuation *c"
			 "struct exception_handler *e")))
*/

#define COMMAND_CALL(f, a, c, e) \
  ((void)&(f), ((f)->call((f), (struct lsh_object *) (a), (c), (e))))

/* NOTE: Except when inheriting command, use DEFINE_COMMAND instead. */
#define STATIC_COMMAND(f) { STATIC_HEADER, f }

#define DEFINE_COMMAND(cname)			\
static void					\
do_##cname(struct command *,			\
	   struct lsh_object *,			\
           struct command_continuation *,	\
           struct exception_handler *);		\
						\
struct command cname =				\
STATIC_COMMAND(do_##cname);			\
						\
static void					\
do_##cname

/* A command taking 2 arguments */
/* GABA:
   (class
     (name command_2)
     (super command)
     (vars
       (invoke pointer
         (function void "struct lsh_object *a1"
			"struct lsh_object *a2"
			"struct command_continuation *c"
			"struct exception_handler *e"))))
*/

void
do_command_2(struct command *s,
	     struct lsh_object *a1,
	     struct command_continuation *c,
	     struct exception_handler *e);

struct command *
make_command_2_invoke(struct command_2 *f,
		      struct lsh_object *a1);

#define DEFINE_COMMAND2(cname)				\
static void						\
do_##cname(struct lsh_object *,				\
	   struct lsh_object *,				\
	   struct command_continuation *,		\
	   struct exception_handler *);			\
							\
struct command_2 cname =				\
{ { STATIC_HEADER, do_command_2 }, do_##cname };	\
							\
static void						\
do_##cname

/* A command taking 3 arguments */
/* GABA:
   (class
     (name command_3)
     (super command)
     (vars
       (invoke pointer
         (function void "struct lsh_object *a1"
			"struct lsh_object *a2"
			"struct lsh_object *a3"
			"struct command_continuation *c"
			"struct exception_handler *e"))))
*/

void
do_command_3(struct command *s,
	     struct lsh_object *a1,
	     struct command_continuation *c,
	     struct exception_handler *e);

struct command *
make_command_3_invoke(struct command_3 *f,
		      struct lsh_object *a1);

struct command *
make_command_3_invoke_2(struct command_3 *f,
			struct lsh_object *a1,
			struct lsh_object *a2);

#define DEFINE_COMMAND3(cname)				\
static void						\
do_##cname(struct lsh_object *,				\
	   struct lsh_object *,				\
	   struct lsh_object *,				\
	   struct command_continuation *,		\
	   struct exception_handler *);			\
							\
struct command_3 cname =				\
{ { STATIC_HEADER, do_command_3 }, do_##cname };	\
							\
static void						\
do_##cname


/* A command taking 4 arguments */
/* GABA:
   (class
     (name command_4)
     (super command)
     (vars
       (invoke pointer
         (function void "struct lsh_object *a1"
			"struct lsh_object *a2"
			"struct lsh_object *a3"
			"struct lsh_object *a4"
			"struct command_continuation *c"
			"struct exception_handler *e"))))
*/

void
do_command_4(struct command *s,
	     struct lsh_object *a1,
	     struct command_continuation *c,
	     struct exception_handler *e);

struct command *
make_command_4_invoke(struct command_4 *f,
		      struct lsh_object *a1);

struct command *
make_command_4_invoke_2(struct command_4 *f,
			struct lsh_object *a1,
			struct lsh_object *a2);

struct command *
make_command_4_invoke_3(struct command_4 *f,
			struct lsh_object *a1,
			struct lsh_object *a2,
			struct lsh_object *a3);

#define DEFINE_COMMAND4(cname)				\
static void						\
do_##cname(struct lsh_object *,				\
	   struct lsh_object *,				\
	   struct lsh_object *,				\
	   struct lsh_object *,				\
	   struct command_continuation *,		\
	   struct exception_handler *);			\
							\
struct command_4 cname =				\
{ { STATIC_HEADER, do_command_4 }, do_##cname };	\
							\
static void						\
do_##cname


extern struct command_continuation discard_continuation;

/* GABA:
   (class
     (name command_frame)
     (super command_continuation)
     (vars
       (up object command_continuation)
       (e object exception_handler)))
*/

/* Used when the execution context must be saved for later use.
 *
 * Primarily used in channel.c.
 */
/* GABA:
   (class
     (name command_context)
     (vars
       (c object command_continuation)
       (e object exception_handler)))
*/

struct command_context *
make_command_context(struct command_continuation *c,
		     struct exception_handler *e);


#if DEBUG_TRACE
struct command *make_trace(const char *name, struct command *real);
struct lsh_object *collect_trace(const char *name, struct lsh_object *real);

#define MAKE_TRACE collect_trace
#else /* !DEBUG_TRACE */
#define MAKE_TRACE(name, real) (real)
#endif /* !DEBUG_TRACE */

#endif /* LSH_COMMAND_H_INCLUDED */ 
