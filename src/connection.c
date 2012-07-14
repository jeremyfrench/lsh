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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02111-1301, USA.
 */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>

#include "connection.h"

#include "alist.h"
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

  connection->channels
    = lsh_space_alloc(sizeof(*connection->channels) * INITIAL_CHANNELS);
  connection->alloc_state
    = lsh_space_alloc(sizeof(*connection->alloc_state) * INITIAL_CHANNELS);
  
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
  
  object_queue_init(&connection->pending_global_requests);
}

/* Returns -1 if allocation fails */
/* NOTE: This function returns locally chosen channel numbers, which
 * are always small integers. So there's no problem fitting them in
 * a signed int. */
int
ssh_connection_alloc_channel(struct ssh_connection *connection,
			     enum channel_alloc_state type)
{
  uint32_t i;

  assert(type == CHANNEL_ALLOC_SENT_OPEN
	 || type == CHANNEL_ALLOC_RECEIVED_OPEN);

  for (i = connection->next_channel; i < connection->used_channels; i++)
    {
      if (connection->alloc_state[i] == CHANNEL_FREE)
	{
	  assert(!connection->channels[i]);
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
			    sizeof(*connection->channels) * new_size);

      connection->alloc_state
	= lsh_space_realloc(connection->alloc_state,
			    sizeof(*connection->alloc_state) * new_size);
      connection->allocated_channels = new_size;
    }

  connection->next_channel = connection->used_channels = i+1;

  connection->channels[i] = NULL;
  
 success:
  connection->alloc_state[i] = type;
  connection->channel_count++;
  verbose("Allocated local channel number %i\n", i);

  return i;
}

void
ssh_connection_dealloc_channel(struct ssh_connection *connection, uint32_t i)
{
  assert(i < connection->used_channels);
  assert(connection->channel_count);
  assert(connection->alloc_state[i] != CHANNEL_FREE);

  verbose("Deallocating local channel %i\n", i);
  connection->channels[i] = NULL;
  connection->alloc_state[i] = CHANNEL_FREE;

  connection->channel_count--;
  
  if (i < connection->next_channel)
    connection->next_channel = i;
}

void
ssh_connection_activate_channel(struct ssh_connection *connection,
				uint32_t local_channel_number)
{
  assert(local_channel_number < connection->used_channels);
  assert(connection->alloc_state[local_channel_number] != CHANNEL_FREE);
  assert(connection->channels[local_channel_number]);

  trace("ssh_connection_activate_channel: local_channel_number: %i.\n",
	local_channel_number);

  connection->alloc_state[local_channel_number] = CHANNEL_ALLOC_ACTIVE;  
}

struct ssh_channel *
ssh_connection_lookup_channel(struct ssh_connection *connection,
			      uint32_t local_channel_number,
			      enum channel_alloc_state flag)
{
  assert(flag != 0);
  if (local_channel_number < connection->used_channels
      && (connection->alloc_state[local_channel_number] == flag))
    {
      struct ssh_channel *channel
	= connection->channels[local_channel_number];
      assert(channel);

      return channel;
    }
  return NULL;
}

void
ssh_connection_pending_close(struct ssh_connection *connection)
{
  trace("ssh_connection_pending_close\n");

  connection->pending_close = 1;

  if (!connection->channel_count)
    KILL_RESOURCE(&connection->super);
}

/* Iterates over the active channels. */
void
ssh_connection_foreach(struct ssh_connection *connection,
		       void (*f)(struct ssh_channel *))
{
  unsigned i;
  for (i = 0; i < connection->used_channels; i++)
    {
      if (connection->alloc_state[i] == CHANNEL_ALLOC_ACTIVE)
	{
	  struct ssh_channel *channel = connection->channels[i];
	  assert(channel);
	  f(channel);
	}
    }
}
