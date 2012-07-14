/* client_escape.h
 *
 * Escape char handling.
 *
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998, 1999, 2000, 2001 Niels Möller
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02111-1301  USA
 */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <string.h>

#include "client.h"

#include "format.h"
#include "lsh_string.h"
#include "werror.h"
#include "xalloc.h"

#include "client_escape.c.x"

/* GABA:
   (class
     (name escape_help)
     (super escape_callback)
     (vars
       (info object escape_info)))
*/

static void
do_escape_help(struct lsh_callback *s)
{
  CAST(escape_help, self, s);
  unsigned i;

  werror("The escape character is `%pc'\n",
	 self->info->escape);

  werror("Available commands:\n\n");
  
  for (i = 0; i < 0x20; i++)
    {
      struct escape_callback *c = self->info->dispatch[i];

      if (c)
	werror("`^%c': %z\n", i + 64, c->help);
    }    
  for (; i < 0x100; i++)
    {
      struct escape_callback *c = self->info->dispatch[i];

      if (c)
	werror("`%pc': %z\n", i, c->help);
    }
}    

static struct escape_callback *
make_escape_help(struct escape_info *info)
{
  NEW(escape_help, self);
  self->super.super.f = do_escape_help;
  self->super.help = "Display this help.";
  self->info = info;

  return &self->super;
}

struct escape_info *
make_escape_info(uint8_t escape)
{
  NEW(escape_info, self);
  unsigned i;

  self->escape = escape;
  
  for (i = 0; i<0x100; i++)
    self->dispatch[i] = NULL;

  self->dispatch['?'] = make_escape_help(self);
  
  return self;
}

/* Returns 1 for the quote action. */ 
static int
escape_dispatch(const struct escape_info *info,
		uint8_t c)
{
  struct escape_callback *f;

  if (c == info->escape)
    return 1;
  
  f = info->dispatch[c];
  if (f)
    LSH_CALLBACK(&f->super);
  else
    werror("<escape> `%pc' not defined.\n", c);
  
  return 0;
}

static inline int
newlinep(uint8_t c)
{
  return (c == '\n') || (c == '\r');
}

/* Scans data for the first escape sequence, and invokes the
   appropriate handler. The amount of input processed is stored in
   *done, and the amount of data to be copied through is stored in
   *copy. */
enum escape_state
client_escape_process(const struct escape_info *info, enum escape_state state,
		      uint32_t length, const uint8_t *data,
		      uint32_t *copy, uint32_t *done)
{
  assert(length > 0);

  switch (state)
    {
    default:
      fatal("Internal error in escape processing.\n");

    case ESCAPE_GOT_ESCAPE:
      *done = 1;
      *copy = escape_dispatch(info, data[0]);

      return ESCAPE_GOT_NONE;
      
    case ESCAPE_GOT_NEWLINE:
      if (data[0] == info->escape)
	{
	  if (length == 1)
	    {
	      *done = 1;
              *copy = 0;
	      return ESCAPE_GOT_ESCAPE;
	    }
	  else
	    {
	      *done = 2;
	      *copy = escape_dispatch(info, data[1]);

	      return ESCAPE_GOT_NONE;
	    }
	}
      /* Fall through */
    case ESCAPE_GOT_NONE:
      {
	uint32_t i;

	for (i = 0; i < length;)
	  {
	    if (newlinep(data[i++]))
	      {
		if (i == length)
		  {
		    *copy = *done = i;
		    return ESCAPE_GOT_NEWLINE;
		  }
		if (data[i] == info->escape)
		  {
		    i++;
		    if (i == length)
		      {
			*copy = i - 1;
			*done = i;
			return ESCAPE_GOT_ESCAPE;
		      }
		    *copy = i - 1 + escape_dispatch(info, data[i]);
		    *done = i + 1;
		    return ESCAPE_GOT_NONE;
		  }
	      }
	  }
	
	*copy = *done = length;
	return ESCAPE_GOT_NONE;
      }
    }
}
