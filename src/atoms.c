/* atoms.c
 *
 */

#include "atoms.h"

#include "atoms_gperf.c"

struct atom_rassoc
{
  UINT8 *name;
  UINT32 length;
};

struct atom_rassoc atom_table[] =
#include "atoms_table.c"
;

UINT32 get_atom_length(int atom)
{ return atom_table[atom].length; }

UINT8 *get_atom_name(int atom)
{ return atom_table[atom].name; }
  
UINT32 lookup_atom(UINT8 *name, UINT32 length)
{
  struct atom_assoc *pair = gperf_atom(name, length);

  return pair ? pair->id : 0;
}


