/* lsh_types.h
 *
 */

#ifndef LSH_TYPS_H_INCLUDED
#define LSH_TYPS_H_INCLUDED

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#if SIZEOF_SHORT >= 4
#define UINT32 unsigned short
#elif SIZEOF_INT >= 4
#define UINT32 unsigned int
#elif SIZEOF_LONG >= 4
#define UINT32 unsigned long
#endif

#define UINT8 unsigned char

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

#endif /* LSH_TYPS_H_INCLUDED */
