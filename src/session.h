/* session.h
 *
 * Manage the ssh-connection service.
 */

#ifndef LSH_SESSION_H_INCLUDED
#define LSH_SESSION_H_INCLUDED

#include "connection.h"
#include "channel.h"

struct ssh_session
{
#if 0
  /* FIXME: This is relevant only for the server side. It's probably
   * better to store this in the connection struct */
  uid_t user;  /* Authenticated user */
#endif
  /* Channels are indexed by local number */
  struct channel **channels;

  /* Allocation of local channel numbers is managed using the same *
   * method as is traditionally used for allocation of unix file
   * descriptors. */

  UINT32 allocated_channels;
  UINT32 next_channel;
  UINT32 used_channels;
  UINT32 max_channels; /* Max number of channels allowed */
};

/* SSH_MSG_GLOBAL_REQUEST */
struct global_request
{
  struct lsh_object *header;

  int (*handler)(struct global_request *closure,
		 int want_reply,
		 struct simple_buffer *args);
};

#define GLOBAL_REQUEST(c, w, a) ((c)->handler((c), (w), (a)))

/* SSH_MSG_CHANNEL_OPEN */
struct channel_open {
  struct lsh_object *header;

  int (*handler)(struct channel_request *closure,
		 UINT32 channel_number, /* Remote channel number */
		 UINT32 rec_window_size,
		 UINT32 rec_max_packet,
		 struct simple_buffer *args);
};

#define CHANNEL_OPEN(c, n, w, m, a) \
((c)->handler((c), (n), (w), (m), (a)))

#endif /* LSH_SESSION_H_INCLUDED */
