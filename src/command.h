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

/* GABA:
   (class
     (name command_frame)
     (super command_continuation)
     (vars
       (up object command_continuation)))
*/

struct command_continuation *
make_apply(struct command *f, struct command_continuation *c);  
struct lsh_object *gaba_apply(struct lsh_object *f,
			      struct lsh_object *x);

/* The macros are used by automatically generated evaluation code */
extern struct command_simple command_S;
struct command *make_command_S_2(struct command *f,
				 struct command *g);

struct command *make_command_S_1(struct command *f);

struct lsh_object *gaba_apply_S_1(struct lsh_object *f);
struct lsh_object *gaba_apply_S_2(struct lsh_object *f,
				  struct lsh_object *g);

#define GABA_VALUE_S (&command_S.super.super)
#define GABA_APPLY_S_1 gaba_apply_S_1
#define GABA_APPLY_S_2 gaba_apply_S_2

extern struct command_simple command_K;
struct command *make_command_K_1(struct lsh_object *x);

#define GABA_VALUE_K (&command_K.super.super)
#define GABA_APPLY_K_1(x) ((struct lsh_object *) make_command_K_1(x))

#define GABA_APPLY gaba_apply

extern struct command_simple command_I;
#define GABA_VALUE_I (&command_I.super.super)
#define GABA_APPLY_I_1(x) (x)

#if 0
extern struct command command_B;
#endif

struct command *make_listen_command(struct io_backend *backend,
				    struct lsh_string *interface,
				    UINT32 port);

#if 0
/* (lambda (x) (f (g x))) */
struct command *command_compose(struct command *f, struct command *g);

/* (lambda (x) (and (f1 x) (f2 x) ...)) */
struct command *command_andl(struct object_list *args);

/* (lambda (x) (or (f1 x) (f2 x) ...)) */
struct command *command_orl(struct object_list *args);
#endif

#endif /* LSH_COMMAND_H_INCLUDED */ 
