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

#define COMMAND_CALL(f, a, c) \
  ((f)->call((f), (struct lsh_object *) (a), (c)))
#define COMMAND_RETURN(r, v) \
  ((r) ? ((r)->c((r), (struct lsh_object *) (v))) : LSH_OK | LSH_GOON)
#define COMMAND_SIMPLE(f, a) \
  ((f)->call_simple((f), (struct lsh_object *)(a)))

int do_call_simple_command(struct command *s,
			   struct lsh_object *arg,
			   struct command_continuation *c);

#define STATIC_COMMAND_SIMPLE(f) \
{ { STATIC_HEADER, do_call_simple_command }, f}

#define STATIC_COMMAND(f) { STATIC_HEADER, f }

struct command *make_parallell_progn(struct object_list *body);
extern struct command_simple progn_command;

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
do_collect_1(struct command_simple *s, struct lsh_object *a);

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

extern struct command_simple command_unimplemented;
#define COMMAND_UNIMPLEMENTED (&command_unimplemented.super.super)

struct command command_die_on_null;

/* The GABA_* macros are used by automatically generated evaluation code */

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

extern struct collect_info_1 command_S;
/* extern struct collect_info_2 collect_info_S_2; */

struct command *make_command_S_2(struct command *f,
				 struct command *g);

#define GABA_VALUE_S (&command_S.super.super.super)
#define GABA_APPLY_S_1(f) (make_collect_state_1(&command_S, (f)))
#define GABA_APPLY_S_2(f, g) (collect_S_2(NULL, (f), (g)))

extern struct collect_info_1 command_Sp;
extern struct collect_info_2 collect_info_Sp_2;
/* extern struct collect_info_3 collect_info_Sp_3; */

struct command *make_command_Sp_3(struct command *c,
				  struct command *f,
				  struct command *g);

struct lsh_object *collect_S_2(struct collect_info_2 *info,
			       struct lsh_object *f,
			       struct lsh_object *g);
struct lsh_object *collect_Sp_3(struct collect_info_3 *info,
				struct lsh_object *c,
				struct lsh_object *f,
				struct lsh_object *g);

#define GABA_VALUE_Sp (&command_Sp.super.super)
#define GABA_APPLY_Sp_1(c) (make_collect_state_1(&command_Sp, (c)))
#define GABA_APPLY_Sp_2(c, f) \
  (make_collect_state_2(&collect_info_Sp_2, (c), (f)))
#define GABA_APPLY_Sp_3(c, f, g) (collect_Sp_3(NULL, (c), (f), (g)))

extern struct collect_info_1 command_B;
/* extern struct collect_info_2 collect_info_B_2; */

struct command *make_command_B_2(struct command *f,
				 struct command *g);
struct lsh_object *collect_B_2(struct collect_info_2 *info,
			       struct lsh_object *f,
			       struct lsh_object *g);

#define GABA_VALUE_B (&command_B.super.super)
#define GABA_APPLY_B_1(f) (make_collect_state_1(&command_B, (f)))
#define GABA_APPLY_B_2(f, g) (collect_B_2(NULL, (f), (g)))

extern struct collect_info_1 command_Bp;
extern struct collect_info_2 collect_info_Bp_2;
extern struct collect_info_3 collect_info_Bp_3;

struct command *make_command_Bp_3(struct command *c,
				  struct command *f,
				  struct command *g);
struct lsh_object *collect_Bp_3(struct collect_info_3 *info,
				struct lsh_object *c,
				struct lsh_object *f,
				struct lsh_object *g);

#define GABA_VALUE_Bp (&command_Bp.super.super)
#define GABA_APPLY_Bp_1(c) (make_collect_state_1(&command_Bp, (c)))
#define GABA_APPLY_Bp_2(c, f) \
  (make_collect_state_2(&collect_info_Bp_2, (c), (f)))
#define GABA_APPLY_Bp_3(c, f, g) (collect_Bp_3(NULL, (c), (f), (g)))

extern struct collect_info_1 command_C;
/* extern struct collect_info_2 collect_info_C_2; */

struct command *
make_command_C_2(struct command *f,
		 struct lsh_object *y);
struct lsh_object *
collect_C_2(struct collect_info_2 *info,
	    struct lsh_object *f,
	    struct lsh_object *y);

#define GABA_VALUE_C (&command_C.super.super.super)
#define GABA_APPLY_C_1(f) (make_collect_state_1(&command_C, (f)))
#define GABA_APPLY_C_2(f, y) (collect_C_2(NULL, (f), (y)))

extern struct collect_info_1 command_Cp;
extern struct collect_info_2 collect_info_Cp_2;
/* extern struct collect_info_3 collect_info_Cp_3; */

struct command *
make_command_Cp_3(struct command *c,
		  struct command *f,
		  struct lsh_object *y);
struct lsh_object *
collect_Cp_3(struct collect_info_3 *info,
	     struct lsh_object *c,
	     struct lsh_object *f,
	     struct lsh_object *y);

#define GABA_VALUE_Cp (&command_Cp.super.super)
#define GABA_APPLY_Cp_1(c) (make_collect_state_1(&command_Cp, (c)))
#define GABA_APPLY_Cp_2(c, f) \
  (make_collect_state_2(&collect_info_Cp_2, (c), (f)))
#define GABA_APPLY_Cp_3(c, f, y) (collect_Cp_3(NULL, (c), (f), (y)))
     

#endif /* LSH_COMMAND_H_INCLUDED */ 
