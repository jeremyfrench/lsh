/* read_data.h
 *
 * A read handler for application data.
 *
 * $Id$ */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998 Niels Möller
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef LSH_READ_DATA_H_INCLUDED
#define LSH_READ_DATA_H_INCLUDED

#include "abstract_io.h"

struct read_data
{
  struct read_handler super; /* Super type */

  UINT32 block_size;

  /* Where to send the data */
  struct abstract_write *handler;

  struct callback *close_callback;
};

#endif /* LSH_READ_DATA_H_INCLUDED */


 
