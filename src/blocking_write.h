/* blocking_write.h
 *
 */

#ifndef LSH_BLOCKING_WRITE_H_INCLUDED
#define LSH_BLOCKING_WRITE_H_INCLUDED

#warning blocking_write is not used

struct packet_blocking_write
{
  struct abstract_write super;
  int fd;
};

struct abstract_write *make_blocking_write_procesor(int fd);

#endif /* LSH_BLOCKING_WRITE_H_INCLUDED */
