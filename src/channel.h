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

#define CHANNEL_SENT_CLOSE 1
#define CHANNEL_RECIEVED_CLOSE 2
#define CHANNEL_SENT_EOF 4
#define CHANNEL_RECIEVED_EOF 8

struct ssh_channel
{
  /* struct read_handler super; */
  
  UINT32 channel_number;  /* Remote channel number */

  UINT32 max_window;      /* We try to keep the rec_window_size
			   * between max_window / 2 and max_window. */
  UINT32 rec_window_size;
  UINT32 rec_max_packet;

  UINT32 send_window_size;
  UINT32 send_max_packet;

  /* FIXME: Perhaps this should be moved to the channel_table,
   * and a pointer to that table be stored here instead? */
  struct abstract_write *write;
  
  struct alist *request_types;

  int flags;
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
  int (*recieve)(struct ssh_channel *self, 
		 int type, struct lsh_string *data);

  /* Called when we are allowed to send data on the channel. */
  int (*send)(struct ssh_channel *self);

#if 0
  int (*close)(struct ssh_channel *self);
  int (*eof)(struct ssh_channel *self);
#endif
  
  /* Reply from SSH_MSG_CHANNEL_OPEN_REQUEST */
  int (*open_confirm)(struct ssh_channel *self);
  int (*open_failure)(struct ssh_channel *self);

  /* Reply from SSH_MSG_CHANNEL_REQUEST */
  int (*channel_success)(struct ssh_channel *self);
  int (*channel_failure)(struct ssh_channel *self);
};

#define CHANNEL_RECIEVE(s, t, d) \
((s)->recieve((s), (t), (d)))

#define CHANNEL_SEND(s) ((s)->send((s)))
     
#define CHANNEL_CLOSE(s) \
((s)->close((s)))

#define CHANNEL_EOF(s) \
((s)->eof((s)))

#define CHANNEL_OPEN_CONFIRM(s) \
((s)->open_confirm((s)))

#define CHANNEL_OPEN_FAILURE(s) \
((s)->open_failure((s)))

#define CHANNEL_SUCCESS(s) \
((s)->channel_success((s)))

#define CHANNEL_FAILURE(s) \
((s)->channel_failure((s)))
     
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

  struct ssh_channel * (*handler)(struct channel_open *closure,
				  struct simple_buffer *args,
				  UINT32 *error,
				  char **error_msg,
				  struct lsh_string **data);
};

#define CHANNEL_OPEN(c, a, e, m, d) \
((c)->handler((c), (a), (e), (m), (d)))

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

void init_channel(struct ssh_channel *channel);

struct channel_table *make_channel_table(void);
int alloc_channel(struct channel_table *table);
void dealloc_channel(struct channel_table *table, int i);
int register_channel(struct channel_table *table, struct ssh_channel *channel);
struct ssh_channel *lookup_channel(struct channel_table *table, UINT32 i);

struct abstract_write *make_channel_write(struct ssh_channel *channel);
struct abstract_write *make_channel_write_extended(struct ssh_channel *channel,
						   UINT32 type);

struct read_handler *make_channel_read_data(struct ssh_channel *channel);
struct read_handler *make_channel_read_stderr(struct ssh_channel *channel);

struct lsh_string *format_global_failure(void);

struct lsh_string *format_open_failure(UINT32 channel, UINT32 reason,
				       char *msg, char *language);
struct lsh_string *format_open_confirmation(struct ssh_channel *channel,
					    UINT32 channel_number,
					    char *format, ...);

struct lsh_string *format_channel_success(UINT32 channel);
struct lsh_string *format_channel_failure(UINT32 channel);

struct lsh_string *prepare_window_adjust(struct ssh_channel *channel,
					 UINT32 add);

struct lsh_string *prepare_channel_open(struct channel_table *table,
					int type, struct ssh_channel *channel,
					char *format, ...);

struct lsh_string *format_channel_request(int type, struct ssh_channel *channel,
					  int want_reply, char *format, ...);

struct lsh_string *format_channel_close(struct ssh_channel *channel);
struct lsh_string *format_channel_eof(struct ssh_channel *channel);

int channel_close(struct ssh_channel *channel);
int channel_eof(struct ssh_channel *channel);

struct lsh_string *channel_transmit_data(struct ssh_channel *channel,
					 struct lsh_string *data);

struct lsh_string *channel_transmit_extended(struct ssh_channel *channel,
					     UINT32 type,
					     struct lsh_string *data);

struct ssh_service *make_connection_service(struct alist *global_requests,
					    struct alist *channel_types,
					    struct connection_startup *start);


#endif /* LSH_CHANNEL_H_INCLUDED */
