/* blocking_write.h
 *
 */

#ifndef LSH_BLOCKING_WRITE_H_INCLUDED
#define LSH_BLOCKING_WRITE_H_INCLUDED

#include "abstract_io.h"

#define CLASS_DECLARE
#include "blocking_write.h.x"
#undef CLASS_DECLARE

/* CLASS:
   (class
     (name blocking_write)
     (super abstract_write)
     (vars
       (fd . int)))
*/

struct abstract_write *make_blocking_write(int fd);

#endif /* LSH_BLOCKING_WRITE_H_INCLUDED */
