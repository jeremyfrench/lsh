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

#endif /* LSH_TYPS_H_INCLUDED */
