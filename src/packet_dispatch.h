/* packet_dispatch.h
 *
 * Pass packets on to one of several handlers.
 */

#ifndef LSH_PACKET_DISPATH_H_INCLUDED
#define LSH_PACKET_DISPATH_H_INCLUDED

struct dispatch_assoc
{
  int msg;
  struct packet_processor *f;
};

struct dispatch_processor
{
  struct packet_processor p;
  struct packet_processor *default;
  unsigned table_size;
  /* Should be sorted by message number */
  struct dispatch_assoc *dispatch_table;
};

struct packet_processor *
make_dispatch_processor(unsigned size,
			struct dispatch_assoc *table,
			struct packet_processor *default);

#endif /* LSH_PACKET_DISPATH_H_INCLUDED */
