/* connection.c
 *
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998, 2005 Niels Möller
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>

#include "connection.h"

#include "alist.h"
#include "command.h"
#include "werror.h"
#include "xalloc.h"

#define GABA_DEFINE
#include "connection.h.x"
#undef GABA_DEFINE

#define INITIAL_CHANNELS 32
/* Arbitrary limit */
#define MAX_CHANNELS (1L<<17)

void
init_ssh_connection(struct ssh_connection *connection,
		    void (*kill)(struct resource *),
		    void (*write)(struct ssh_connection *, struct lsh_string *),
		    void (*disconnect)(struct ssh_connection *, uint32_t, const char *))
{
  init_resource(&connection->super, kill);

  connection->write = write;
  connection->disconnect = disconnect;
  
  connection->resources = make_resource_list();

  connection->channels = lsh_space_alloc(sizeof(struct ssh_channel *)
				      * INITIAL_CHANNELS);
  connection->in_use = lsh_space_alloc(INITIAL_CHANNELS);
  
  connection->allocated_channels = INITIAL_CHANNELS;
  connection->used_channels = 0;
  connection->next_channel = 0;
  connection->channel_count = 0;
  
  connection->max_channels = MAX_CHANNELS;

  connection->pending_close = 0;

  connection->global_requests = make_alist(0, -1);
  connection->channel_types = make_alist(0, -1);
  connection->open_fallback = NULL;
  
  object_queue_init(&connection->forwarded_ports);
  connection->x11_display = NULL;
  
  object_queue_init(&connection->active_global_requests);
  object_queue_init(&connection->pending_global_requests);
}

#if 0
void
kill_ssh_connection(struct ssh_connection *connection)
{
  KILL_RESOURCE_LIST(self->resources);
  for (i = 0; i<connection->used_channels; i++)
    {
      /* Loop over all channels, no matter if the status is reserved or in use */
      struct ssh_channel *channel = connection->channels[i];

      if (channel)
	KILL_RESOURCE(&channel->super);
    }
}
#endif

/* Returns -1 if allocation fails */
/* NOTE: This function returns locally chosen channel numbers, which
 * are always small integers. So there's no problem fitting them in
 * a signed int. */
int
ssh_connection_alloc_channel(struct ssh_connection *connection)
{
  uint32_t i;
  
  for (i = connection->next_channel; i < connection->used_channels; i++)
    {
      if (connection->in_use[i] == CHANNEL_FREE)
	{
	  assert(!connection->channels[i]);
	  connection->in_use[i] = CHANNEL_RESERVED;
	  connection->next_channel = i+1;

	  goto success;
	}
    }
  if (i == connection->max_channels)
    return -1;

  if (i == connection->allocated_channels) 
    {
      uint32_t new_size = connection->allocated_channels * 2;

      connection->channels
	= lsh_space_realloc(connection->channels,
			    sizeof(struct ssh_channel *) * new_size);

      connection->in_use = lsh_space_realloc(connection->in_use, new_size);
      connection->allocated_channels = new_size;
    }

  connection->next_channel = connection->used_channels = i+1;

  connection->in_use[i] = CHANNEL_RESERVED;
  connection->channels[i] = NULL;
  
 success:
  connection->channel_count++;
  verbose("Allocated local channel number %i\n", i);

  return i;
}

void
ssh_connection_dealloc_channel(struct ssh_connection *connection, uint32_t i)
{
  assert(i < connection->used_channels);
  assert(connection->channel_count);
  
  verbose("Deallocating local channel %i\n", i);
  connection->channels[i] = NULL;
  connection->in_use[i] = CHANNEL_FREE;

  connection->channel_count--;
  
  if ( (unsigned) i < connection->next_channel)
    connection->next_channel = i;
}

void
ssh_connection_use_channel(struct ssh_connection *connection,
			   uint32_t local_channel_number)
{
  assert(connection->channels[local_channel_number]);
  assert(connection->in_use[local_channel_number] == CHANNEL_RESERVED);
  
  connection->in_use[local_channel_number] = CHANNEL_IN_USE;
  trace("ssh_connection_use_channel: local_channel_number: %i.\n",
	local_channel_number);
}


void
ssh_connection_pending_close(struct ssh_connection *connection)
{
  trace("ssh_connection_pending_close\n");

  /* This method should be called before the last channel is cleaned
     up, so that the cleanup code can check the flag and do the right
     thing. */
  assert(connection->channel_count);
  connection->pending_close = 1;
}

/* (remember connection resource) */
DEFINE_COMMAND2(connection_remember)
     (struct lsh_object *a1,
      struct lsh_object *a2,
      struct command_continuation *c,
      struct exception_handler *e UNUSED)
{
  CAST_SUBTYPE(ssh_connection, connection, a1);
  CAST_SUBTYPE(resource, resource, a2);
  
  if (resource)
    remember_resource(connection->resources, resource);

  COMMAND_RETURN(c, resource);
}
