/* command.h
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

#ifndef LSH_COMMAND_H_INCLUDED
#define LSH_COMMAND_H_INCLUDED

#include "lsh.h"

#include "list.h"
#include "io.h"

#include <stdarg.h>

#define GABA_DECLARE
#include "command.h.x"
#undef GABA_DECLARE

/* Continuation based command execution. A command can take one object
 * as argument, and returns one object. */

/* GABA:
   (class
     (name command_continuation)
     (vars
       (c method int "struct lsh_object *result")))
*/

/* GABA:
   (class
     (name command)
     (vars
       (call method int "struct lsh_object *arg"
                        "struct command_continuation *c")))
*/

/* GABA:
   (class
     (name command_simple)
     (super command)
     (vars
       ;; Like call, but returns the value immediately rather than
       ;; using a continuation function
       (call_simple method "struct lsh_object *" "struct lsh_object *")))
*/

#define COMMAND_CALL(f, a, c) ((f)->call((f), (a), (c)))
#define COMMAND_RETURN(r, v) ((r)->c((r), (struct lsh_object *) (v))) 
#define COMMAND_SIMPLE(f, a) ((f)->call_simple((f), (a)))

int do_call_simple_command(struct command *s,
			   struct lsh_object *arg,
			   struct command_continuation *c);

#define STATIC_COMMAND_SIMPLE(f) \
{ { STATIC_HEADER, do_call_simple_command }, f}

struct lsh_object *
do_collect_1(struct command_simple *s, struct lsh_object *a);

#define STATIC_COLLECT_1(next) \
{ { { STATIC_HEADER, do_call_simple_command }, do_collect_1}, \
  make_collect_state_1, next }

#if 0
#define STATIC_COLLECT_1_FINAL(f) \
{ { { STATIC_HEADER, do_call_simple_command }, do_collect_1}, \
  f, NULL }
#endif

#define STATIC_COLLECT_2(next) \
{ STATIC_HEADER, make_collect_state_2, next }

#define STATIC_COLLECT_2_FINAL(f) \
{ STATIC_HEADER, f, NULL }

#define STATIC_COLLECT_3(next) \
{ STATIC_HEADER, make_collect_state_3, next }

#define STATIC_COLLECT_3_FINAL(f) \
{ STATIC_HEADER, f, NULL }

/* GABA:
   (class
     (name command_frame)
     (super command_continuation)
     (vars
       (up object command_continuation)))
*/

/* Commands that need to collect some arguments before actually doing
 * anything. */

/* The collect_info_n classes keeps track about what to do whith the
 * next argument. As long as we collect arguments without doing
 * anything, the f field in collect_info_n will point to the
 * constructor make_collect_state_n. */
/* GABA:
   (class
     (name collect_info_4)
     (vars
       (f method "struct lsh_object *"
                 "struct lsh_object *" "struct lsh_object *"
		 "struct lsh_object *" "struct lsh_object *")
       ;; No next field
       ))
*/

/* GABA:
   (class
     (name collect_info_3)
     (vars
       (f method  "struct lsh_object *"
                  "struct lsh_object *" "struct lsh_object *"
		  "struct lsh_object *")
       (next object collect_info_4)))
*/

/* GABA:
   (class
     (name collect_info_2)
     (vars
       (f method  "struct lsh_object *"
                  "struct lsh_object *" "struct lsh_object *")
       (next object collect_info_3)))
*/

/* GABA:
   (class
     (name collect_info_1)
     (super command_simple)
     (vars
       (f method  "struct lsh_object *"
                  "struct lsh_object *")
       (next object collect_info_2)))
*/

struct lsh_object *
make_collect_state_1(struct collect_info_1 *info,
		     struct lsh_object *a);

struct lsh_object *
make_collect_state_2(struct collect_info_2 *info,
		     struct lsh_object *a,
		     struct lsh_object *b);

struct lsh_object *
make_collect_state_3(struct collect_info_3 *info,
		     struct lsh_object *a,
		     struct lsh_object *b,
		     struct lsh_object *c);

extern struct command_simple command_unimplemented;
#define COMMAND_UNIMPLEMENTED (&command_unimplemented.super.super)

struct command_continuation *
make_apply(struct command *f, struct command_continuation *c);  
struct lsh_object *gaba_apply(struct lsh_object *f,
			      struct lsh_object *x);

#define GABA_APPLY gaba_apply

extern struct command_simple command_I;
#define GABA_VALUE_I (&command_I.super.super)
#define GABA_APPLY_I_1(x) (x)

extern struct command_simple command_K;
struct command *make_command_K_1(struct lsh_object *x);

#define GABA_VALUE_K (&command_K.super.super)
#define GABA_APPLY_K_1(x) ((struct lsh_object *) make_command_K_1(x))

/* The macros are used by automatically generated evaluation code */
extern struct collect_info_1 command_S;
struct command *make_command_S_2(struct command *f,
				 struct command *g);

#define GABA_VALUE_S (&command_S.super.super)
#define GABA_APPLY_S_1(f) (make_collect_state_1(&collect_info_S_2, (f)))
#define GABA_APPLY_S_2(f, g) (make_collect_S_2(NULL, (f), (g)))

#if 0
extern struct command_simple command_B;

struct command *make_listen_command(struct io_backend *backend,
				    struct lsh_string *interface,
				    UINT32 port);
#endif

#if 0
/* (lambda (x) (f (g x))) */
struct command *command_compose(struct command *f, struct command *g);

/* (lambda (x) (and (f1 x) (f2 x) ...)) */
struct command *command_andl(struct object_list *args);

/* (lambda (x) (or (f1 x) (f2 x) ...)) */
struct command *command_orl(struct object_list *args);
#endif

#endif /* LSH_COMMAND_H_INCLUDED */ 
