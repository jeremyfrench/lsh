/* format.h
 *
 * Create a packet from a format string and arguments.
 */

#ifndef LSH_FORMAT_H_INCLUDED
#define LSH_FORMAT_H_INCLUDED

#include <stdarg.h>

#include "atoms.h"
#include "bignum.h"

/* Format strings can contain the following %-specifications:
 *
 * %%  Insert a %-sign
 *
 * %c  Insert an 8-bit character
 *
 * %i  Insert an 32-bit integer, in network byte order
 *
 * %s  Insert a string, given by a length and a pointer.
 *
 * %S  Insert a string, given as a struct lsh_string pointer.
 *
 * %z  Insert a string, using a null-terminated argument.
 *
 * %r  Reserves space in the string, and stores a pointer to this space
 * into the given UINT8 ** argument.
 *
 * %a  Insert a string containing one atom.
 *
 * %A  Insert a string containing a list of atoms. The corresponding
 *     argument sublist should be a int* pointing to a list of atoms,
 *     terminated with -1.
 *
 * %X  Insert a string containing a list of atoms. The corresponding
 *     argument sublist should be terminated with a zero. (Not used)
 *
 * %n  Insert a string containing a bignum.
 *
 * There are two valid modifiers:
 *
 * "l" (as in literal). It is applicable to the s, a, A, n and r
 * specifiers, and outputs strings *without* a length field.
 *
 * "f" (as in free). Frees the input sting after it has been copied.
 * Applicable to %S only. */

UINT32 ssh_vformat_length(char *format, va_list args);
void ssh_vformat(char *format, UINT8 *buffer, va_list args);
struct lsh_string *ssh_format(char *format, ...);

#endif /* LSH_FORMAT_H_INCLUDED */
