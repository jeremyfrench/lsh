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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* FIXME: This should probably be set in config.h by autoconf */

/* The crypt function requires _XOPEN_SOURCE, while the initgroups
 * function requires _BSD_SOURCE */
#define _GNU_SOURCE

#if SIZEOF_SHORT >= 4
#define UINT32 unsigned short
#elif SIZEOF_INT >= 4
#define UINT32 unsigned int
#elif SIZEOF_LONG >= 4
#define UINT32 unsigned long
#else
#error Ledsen error
#endif

#if SIZEOF_SHORT >= 2
#define UINT16 unsigned short
#elif SIZEOF_INT >= 2
#define UINT16 unsigned int
#else
#error Ledsen error
#endif

#define UINT8 unsigned char

#ifdef __GNUC__
#define NORETURN __attribute__ ((noreturn))
#define PRINTF_STYLE(f, a) __attribute__ ((format(printf, f, a)))
#else
#define NORETURN
#define PRINTF_STYLE(f, a)
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

#define MIN(a, b) (((a)>(b)) ? (b) : (a))
#define MAX(a, b) (((a)>(b)) ? (b) : (a))

/* Generic object */

#ifdef DEBUG_ALLOC

struct lsh_object
{
  int size;  /* Zero for objects that are not allocated on the heap. */
};

struct lsh_string_header
{
  int magic;
};

#define STATIC_HEADER { 0 },

#else   /* !DEBUG_ALLOC */
struct lsh_object {};
struct lsh_string_header {};

#define STATIC_HEADER

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
 * Every handler should return one or more of these values, ored together.
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

/* Non-zero if no messages can be sent over the connection. Used when
 * processing error codes from in the middle of the processing a
 * messages. If this is true, processing should stop, and most likely
 * return LSH_FAIL (ored together with the intermediate error code). */
#define LSH_CLOSEDP(x) (x & (LSH_FAIL | LSH_CLOSE | LSH_DIE) )

/* If non-zero, return to main-loop is preferred */
#define LSH_ACTIONP(x) (x)

/* Are return codes really needed here? */
#if 0
#define LSH_EXIT(x) ((x) << 3)
#define LSH_GET_EXIT(x) ((x) >> 3)
#endif

#endif /* LSH_TYPES_H_INCLUDED */
