/* channel.h
 *
 * Information about one ssh channel.
 */

#ifndef LSH_CHANNEL_H_INCLUDED
#define LSH_CHANNEL_H_INCLUDED

#include "lsh_types.h"

/* Channels are indexed by local channel number in some array. This
 * index is not stored in the channel struct. When sending messages on
 * the channel, it is identified by the *remote* sides index number,
 * and this number must be stored. */

#define CHANNEL_DATA 0
#define CHANNEL_STDERR_DATA 1

#define CHANNEL_EOF 0
#define CHANNEL_CLOSE 1

struct ssh_channel
{
  UINT32 channel_number;  /* Remote channel number */

  UINT32 rec_window_size;
  UINT32 rec_max_packet;

  UINT32 send_window_size;
  UINT32 send_max_packet;

  /* Type is CHANNEL_DATA or CHANNEL_STDERR_DATA */
  int (*recieve)(struct ssh_channel *self, int type, struct lsh_string *data);

  /* Type is CHANNEL_EOF or CHANNEL_CLOSE */
  int (*close)(struct ssh_channel *self, int type);
};

#endif /* LSH_CHANNEL_H_INCLUDED */
