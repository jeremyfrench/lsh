/* atoms.h
 *
 */

#ifndef LSH_ATOMS_H_INCLUDED
#define LSH_ATOMS_H_INCLUDED

#include "lsh_types.h"
#include "atoms_defines.h"

UINT32 get_atom_length(int atom);
UINT8 *get_atom_name(int atom);
UINT32 lookup_atom(UINT8 *name, UINT32 length);

#endif /* LSH_ATOMS_H_INCLUDED */
