/* lsh_types.h
 *
 *
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef LSH_TYPES_H_INCLUDED
#define LSH_TYPES_H_INCLUDED

#if 0
/* FIXME: This should probably be set in config.h by autoconf */

/* The crypt function requires _XOPEN_SOURCE, while the initgroups
 * function requires _BSD_SOURCE. strsignal() is a GNU extension. */
#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif
/* This needs to be defined before any system header (which may include
 * <features.h>) is included. */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#endif

/* This will include config.h for us. */
#include "crypto_types.h"

#include <stdlib.h>

#ifdef __GNUC__
#define NORETURN __attribute__ ((noreturn))
#define PRINTF_STYLE(f, a) __attribute__ ((format(printf, f, a)))
#define UNUSED __attribute__ ((unused))
#else
#define NORETURN
#define PRINTF_STYLE(f, a)
#define UNUSED
#endif

/* Some macros */

/* Reads a 32-bit integer, in network byte order */
#define READ_UINT32(p)				\
((((UINT32) (p)[0]) << 24)			\
 | (((UINT32) (p)[1]) << 16)			\
 | (((UINT32) (p)[2]) << 8)			\
 | ((UINT32) (p)[3]))

#define WRITE_UINT32(p, i)			\
do {						\
  (p)[0] = ((i) >> 24) & 0xff;			\
  (p)[1] = ((i) >> 16) & 0xff;			\
  (p)[2] = ((i) >> 8) & 0xff;			\
  (p)[3] = (i) & 0xff;				\
} while(0)

/* Useful macros. */
#define MIN(a, b) (((a)>(b)) ? (b) : (a))
#define MAX(a, b) (((a)>(b)) ? (b) : (a))
#define SQR(x) ((x)*(x))
     
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

/* Close all other filedescriptors immediately. MAinly used when forking.
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

/* Indicates that a channel is ready to receive remote data */
#define LSH_CHANNEL_READY_REC 0x100

/* Indicates that a channel is ready to send data to the remote end. */
#define LSH_CHANNEL_READY_SEND 0x200

/* Non-zero if no messages can be sent over the connection. Used when
 * processing error codes from in the middle of the processing a
 * messages. If this is true, processing should stop, and most likely
 * return LSH_FAIL (ored together with the intermediate error code). */
#define LSH_CLOSEDP(x) (x & (LSH_FAIL | LSH_CLOSE | LSH_DIE) )

/* If non-zero, return to main-loop is preferred */
#define LSH_ACTIONP(x) ((x) & (LSH_FAIL | LSH_CLOSE | LSH_DIE | LSH_KILL_OTHERS) )

#endif /* LSH_TYPES_H_INCLUDED */
