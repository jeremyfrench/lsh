/* crypto_common.h
 *
 */

#ifndef LSH_CRYPTO_COMMON_H_INCLUDED
#define LSH_CRYPTO_COMMON_H_INCLUDED

/* FIXME: Perhaps cryptographic algoritms should be encapsulated into
 * objects, to avoid passing a lot of extra state parameters? */

typedef void (*transform_function)(void *state,
				   UINT32 size, UINT8 *src, UINT8 *dst);

#endif /* LSH_CRYPTO_COMMON_H_INCLUDED */
