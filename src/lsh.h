/* lsh.h
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

#ifndef LSH_H_INCLUDED
#define LSH_H_INCLUDED

#include "lsh_types.h"

#include <stdlib.h>

/* Generic object */

#define LSH_ALLOC_HEAP 0
#define LSH_ALLOC_STATIC 1
#define LSH_ALLOC_STACK 2

struct lsh_class;

struct lsh_object
{
  /* Objects are chained together, for the sweep phase of the gc. */
  struct lsh_object *next; 
  struct lsh_class *isa;
  
  char alloc_method;
  char marked;
  char dead;
};

/* NOTE: Static objects have a NULL isa-pointer, and can therefore not
 * contain any references to non-static objects. This could be fixed,
 * by using an argument to the STATIC_HEADER macro, but then one must
 * use some class for lsh_class objects... */

#define STATIC_HEADER { NULL, NULL, LSH_ALLOC_STATIC, 0, 0 }
#define STACK_HEADER  { NULL, NULL, LSH_ALLOC_STACK, 0, 0 }

struct lsh_class
{
  struct lsh_object super;
  struct lsh_class *super_class;
  char *name;  /* For debugging */

  size_t size;
  
  void (*mark_instance)(struct lsh_object *instance,
			void (*mark)(struct lsh_object *o));
  void (*free_instance)(struct lsh_object *instance);

  /* Particular classes may add their own methods here */
};

#define MARK_INSTANCE(c, i, f) ((c)->mark_instance((i), (f)))
#define FREE_INSTANCE(c, i) ((c)->free_instance((i)))

#define CLASS(c) (c##_class)

#ifdef DEBUG_ALLOC

struct lsh_string_header
{
  int magic; /* For a sentinel value */
};

#else   /* !DEBUG_ALLOC */

struct lsh_string_header {};

#endif  /* !DEBUG_ALLOC */

struct lsh_string
{
  struct lsh_string_header header;
  
  UINT32 sequence_number;
  /* NOTE: The allocated size may be larger than the string length. */
  UINT32 length; 
  UINT8 data[1];
};

/* A closed function with no arguments */
struct callback;
typedef int (*callback_f)(struct callback *closure);
struct callback
{
  struct lsh_object header;
  
  int (*f)(struct callback *closure);
};

#define CALLBACK(c) ((c)->f(c))

/* Return values.
 *
 * Every handler should return one or more of these values, or-ed together.
 * Zero means everything is ok.
 */

/* Success/fail indication. LSH_FAIL should always be combined with
 * LSH_DIE or LSH_CLOSE. */
#define LSH_OK 0
#define LSH_FAIL 1

#define LSH_FAILUREP(x) ((x) & 1)

/* Everything is ok */
#define LSH_GOON 0

/* Close the associated connection, after flushing buffers. May be
 * combined with LSH_FAIL. */
#define LSH_CLOSE 2

/* Close connection immediately. This is usually combined with
 * LSH_FAIL, but not always. For instance, when forking, the parent
 * process will return this flag in order to have its copy of the
 * filedescriptor closed. */
#define LSH_DIE  4

/* Close all other filedescriptors immediately. Mainly used when forking.
 * Can be combined with LSH_FAIL or LSH_DIE or both. */
#define LSH_KILL_OTHERS 8

/* Not used by the main loop, but is returned by authentication
 * handlers to indicate that the client's authentication was rejected.
 * This can result either in a fatal protocol failure, or in a request
 * to the client to try again. */
#define LSH_AUTH_FAILED 0x10

/* Returned by a read handler when it is (temporarily) not able to
 * read more data. Used for flow control. */
#define LSH_HOLD 0x20

/* Returned by channel callback functions when the channel is closed. */
#define LSH_CHANNEL_FINISHED 0x40

/* Indicates that the connection should be closed once all active
 * channels are closed. */
#define LSH_CHANNEL_PENDING_CLOSE 0x80

/* Returned by channel related functions if the channel should be
 * closed immediately */
#define LSH_CHANNEL_CLOSE 0x100

/* Indicates that a channel is ready to receive remote data */
#define LSH_CHANNEL_READY_REC 0x200

/* Indicates that a channel is ready to send data to the remote end. */
#define LSH_CHANNEL_READY_SEND 0x400

/* Syntax error (used in the sexp parser) */
#define LSH_SYNTAX 0x1000

/* Used to indicate that an sexp have been parsed successfully */
#define LSH_PARSED_OBJECT 0x2000

/* Non-zero if no messages can be sent over the connection. Used when
 * processing error codes from in the middle of the processing a
 * messages. If this is true, processing should stop, and most likely
 * return LSH_FAIL (ored together with the intermediate error code). */
#define LSH_CLOSEDP(x) (x & (LSH_FAIL | LSH_CLOSE | LSH_DIE) )

/* If non-zero, return to main-loop is preferred */
#define LSH_ACTIONP(x) ((x) & (LSH_FAIL | LSH_CLOSE | LSH_DIE | LSH_KILL_OTHERS) )

#endif /* LSH_H_INCLUDED */
