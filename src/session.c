/* session.c
 *
 */

#include "session.h"

struct session *ssh_session_alloc()
{
  struct ssh_session *session = xalloc(sizeof(struct ssh_session));

  memset(session, 0, sizeof(struct ssh_Session));

  session->max_packet = 0x8000;

  return session;
}
