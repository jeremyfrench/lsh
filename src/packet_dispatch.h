/* packet_dispatch.h
 *
 * Pass packets on to one of several handlers.
 */

#ifndef LSH_PACKET_DISPATH_H_INCLUDED
#define LSH_PACKET_DISPATH_H_INCLUDED

#include "abstract_io.h"

struct dispatch_assoc
{
  int msg;
  struct abstract_write *f;
};

struct packet_dispatch
{
  struct abstract_write super;
  struct abstract_write *other;
  unsigned table_size;
  /* Should be sorted by message number */
  struct dispatch_assoc *dispatch_table;
};

struct abstract_write *
make_packet_dispatch(unsigned size,
		     struct dispatch_assoc *table,
		     struct abstract_write *other);

#endif /* LSH_PACKET_DISPATH_H_INCLUDED */
