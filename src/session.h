/* session.h
 *
 * Manage the ssh-connection service.
 */

#ifndef LSH_SESSION_H_INCLUDED
#define LSH_SESSION_H_INCLUDED

#include "connection.h"

struct ssh_session
{
  /* FIXME: This is relevant only for the server side */
  uid_t user;  /* Authenticated user */

  /* Channels are indexed by local number */
  struct channel **channels;

  /* Allocation of local channel numbers is managed using the same *
   * method as is traditionally used for allocation of unix file
   * descriptors. */

  UINT32 allocated channels;
  UINT32 next_channel;
  UINT32 max_channel; /* One more than the highest number in use */
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
struct channel_request {
  struct lsh_object *header;

  int (*handler)(struct global_request *closure,
		 UINT32 channel_number, /* Remote channel number */
		 UINT32 rec_window_size,
		 UINT32 rec_max_packet,
		 struct simple_buffer *args);
};

#define CHANNEL_OPEN(c, n, w, m, a) \
((c)->handler((c), (n), (w), (m), (a)))
     
struct connection_service
{
  struct ssh_service super;

  /* Supported global requests */
  struct alist *global_requests;
  struct alist *channel_requests;
};

#endif /* LSH_SESSION_H_INCLUDED */
