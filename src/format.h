/* format.h
 *
 * Create a packet from a format string and arguments.
 */

#ifndef LSH_FORMAT_H_INCLUDED
#define LSH_FORMAT_H_INCLUDED

#include <stdarg.h>

#include "atoms.h"
#include "bignum.h"
#include "transport.h"

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
 * %a  Insert a string containing one atom.
 *
 * %A  Insert a string containing a list of atoms. The corresponding
 *     argument sublist should be terminated with a zero.
 *
 * %n  Insert a string containing a bignum.
 *
 * There is one valid modifier, "l" (as in literal). It is applicable
 * to the s, a, A and n specifiers, and outputs strings *without* a
 * length field.
 */

UINT32 ssh_vformat_length(char *format, va_list args);
void ssh_vformat(char *format, UINT8 *buffer, va_list args);
struct lsh_string *ssh_format(char *format, ...);

#endif /* LSH_FORMAT_H_INCLUDED */
