/* read_data.h
 *
 * A read handler for application data.
 */

#ifndef LSH_READ_DATA_H_INCLUDED
#define LSH_READ_DATA_H_INCLUDED

#include "abstract_read.h"

struct read_data
{
  struct read_handler super; /* Super type */

  UINT32 block_size;

  /* Where to send the data */
  struct abstract_write *handler;

  struct callback *close_callback;
};

#endif /* LSH_READ_DATA_H_INCLUDED */


 
