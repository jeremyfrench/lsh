/* session.h
 *
 */

#ifndef LSH_SESSION_H_INCLUDED
#define LSH_SESSION_H_INCLUDED

struct session
{
  /* Sent and recieved version strings */
  struct lsh_string *client_version;
  struct lsh_string *server_version;

  struct lsh_string *session_id;
  struct abstract_write write;   /* Socket connected to the other end */
};

#endif /* LSH_SESSION_H_INCLUDED */
