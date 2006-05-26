#ifndef LSH_PTY_HELPER_H_INCLUDED
#define LSH_PTY_HELPER_H_INCLUDED

/* For pid_t */
#include <unistd.h>

enum pty_request_type
{
  /* Creates a pty object reference, without doing anything with it. */
  PTY_REQUEST_CREATE,

  /* Creates a new pty pair. */
  PTY_REQUEST_MASTER,

  /* Updates utmp and wtmp for a login. */
  PTY_REQUEST_LOGIN,

  /* Updates utmp and wtmp for logout. */
  PTY_REQUEST_LOGOUT,

  /* Deletes the object, with no further processing. */
  PTY_REQUEST_DESTROY
};

struct pty_message
{
  /* Ordinary data */
  struct {
    int type;
    int ref;
    unsigned length;
  } header;

  char *data;
  
  /* Transferred credentials */
  int has_creds;

  /* Same fields as linux' struct ucred */
  struct {
    pid_t pid;
    uid_t uid;
    gid_t gid;
  } creds;

  /* Transferred fd (-1 if none) */
  int fd;
};

int
pty_send_message(int socket, const struct pty_message *message);

int
pty_recv_message(int socket, struct pty_message *message);

#endif /* LSH_PTY_HELPER_H_INCLUDED */
