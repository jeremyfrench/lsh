/* blocking_write.h
 *
 */

#ifndef LSH_BLOCKING_WRITE_H_INCLUDED
#define LSH_BLOCKING_WRITE_H_INCLUDED

struct blocking_write_processor
{
  struct abstract_write w;
  int fd;
};

struct abstract_write *make_blocking_write_procesor(int fd);

#endif /* LSH_BLOCKING_WRITE_H_INCLUDED */
