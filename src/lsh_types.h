/* lsh_types.h
 *
 */

#ifndef LSH_TYPES_H_INCLUDED
#define LSH_TYPES_H_INCLUDED

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


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

/* Generic packet */
struct lsh_string
{
  UINT32 sequence_number; 
  UINT32 length;
  UINT8 data[1];
};

/* A closed function with no arguments */
struct callback;
typedef int (*callback_f)(struct callback *closure);
struct callback
{
  callback_f f;
};

#define CALLBACK(c) ((c)->f(c))

#endif /* LSH_TYPES_H_INCLUDED */
