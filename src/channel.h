/* channel.h
 *
 * Information about one ssh channel.
 */

#ifndef LSH_CHANNEL_H_INCLUDED
#define LSH_CHANNEL_H_INCLUDED

#include "alist.h"
#include "connection.h"
#include "parse.h"

/* Channels are indexed by local channel number in some array. This
 * index is not stored in the channel struct. When sending messages on
 * the channel, it is identified by the *remote* sides index number,
 * and this number must be stored. */

#define CHANNEL_DATA 0
#define CHANNEL_STDERR_DATA 1

#if 0
#define CHANNEL_ACTION_EOF 0
#define CHANNEL_ACTION_CLOSE 1
#define CHANNEL_ACTION_OPEN_SUCCESS 2
#define CHANNEL_ACTION_OPEN_FAILURE 3
#endif

struct ssh_channel
{
  UINT32 channel_number;  /* Remote channel number */

  UINT32 rec_window_size;
  UINT32 rec_max_packet;

  UINT32 send_window_size;
  UINT32 send_max_packet;

  struct alist *request_types;

#if 0
  int recieved_close;
  int sent_close;
  int recieved_eof;
  int sent_eof;
#endif

  /* FIXME: What about return values from these functions? A channel
   * may fail to process it's data. Is there some way to propagate a
   * channel broken message to the other end? */

  /* Type is CHANNEL_DATA or CHANNEL_STDERR_DATA */
  int (*recieve)(struct ssh_channel *self, struct abstract_write *write,
		 int type, struct lsh_string *data);

  int (*close)(struct ssh_channel *self, struct abstract_write *write);
  int (*eof)(struct ssh_channel *self, struct abstract_write *write);

  /* Reply from SSH_MSG_CHANNEL_OPEN_REQUEST */
  int (*confirm)(struct ssh_channel *self, struct abstract_write *write);
  int (*fail)(struct ssh_channel *self, struct abstract_write *write);
};

#define CHANNEL_RECIEVE(s, w, t, d) \
((s)->recieve((s), (w), (t), (d)))

#define CHANNEL_CLOSE(s, w) \
((s)->close((s), (w)))

#define CHANNEL_EOF(s, w) \
((s)->eof((s), (w)))

#define CHANNEL_CONFIRM(s, w) \
((s)->confirm((s), (w)))

#define CHANNEL_FAIL(s, w) \
((s)->fail((s), (w)))

/* FIXME: Perhaps, this information is better kept in the connection
 * object? */
struct channel_table
{
  struct lsh_object header;
#if 0
  /* FIXME: This is relevant only for the server side. It's probably
   * better to store this in the connection struct */
  uid_t user;  /* Authenticated user */
#endif
  /* Channels are indexed by local number */
  struct ssh_channel **channels;

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
struct channel_open
{
  struct lsh_object *header;

  int (*handler)(struct channel_open *closure,
		 UINT32 channel_number, /* Remote channel number */
		 UINT32 rec_window_size,
		 UINT32 rec_max_packet,
		 struct simple_buffer *args);
};

#define CHANNEL_OPEN(c, n, w, m, a) \
((c)->handler((c), (n), (w), (m), (a)))

/* SSH_MSH_CHANNEL_REQUEST */
struct channel_request
{
  struct lsh_object *header;

  int (*handler)(struct channel_request *closure,
		 struct ssh_channel *channel,
		 int want_reply,
		 struct simple_buffer *args);
};

#define CHANNEL_REQUEST(s, c, w, a) \
((s)->handler((s), (c), (w), (a)))

struct connection_startup
{
  struct lsh_object header;

  int (*start)(struct connection_startup *closure,
	       struct channel_table *table,
	       struct abstract_write *write);
};

#define CONNECTION_START(c, s, w) ((c)->start((c), (s), (w)))

struct channel_table *make_channel_table(void);
int alloc_channel(struct channel_table *table);
void dealloc_channel(struct channel_table *table, int i);
int register_channel(struct channel_table *table, struct ssh_channel *channel);
struct ssh_channel *lookup_channel(struct channel_table *table, UINT32 i);

struct lsh_string *format_global_failure(void);
struct lsh_string *format_open_failure(UINT32 channel, UINT32 reason,
				       char *msg, char *language);
struct lsh_string *format_channel_failure(UINT32 channel);

struct ssh_service *make_connection_service(struct alist *global_requests,
					    struct alist *channel_types);

#endif /* LSH_CHANNEL_H_INCLUDED */
