/* client_pty.c
 *
 * $Id$ */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998, 1999, Niels Möller, Balazs Scheidler
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "client_pty.h"

/* GABA:
   (class
     (name pty_request)
     (super channel_request_command)
     (vars
       (term string)
       (width . UINT32)
       (height . UINT32)
       (width_p . UINT32)
       (height_p . UINT32)
       (modes string)))
*/

static struct lsh_string *
do_format_pty_request(struct channel_request_command *s,
		      struct ssh_channel *channel,
		      int want_reply)
{
  CAST(pty_request, req, s);

  verbose("lsh: Requesting a remote pty.\n");
  return format_channel_request(ATOM_PTY_REQ, channel, req->super.want_reply, 
				"%S%i%i%i%i%S",
				req->term,
				req->width, req->height,
				req->width_p, req->height_p,
				req->modes);
}

struct command *make_pty_request(int tty)
{
  NEW(pty_request, req);
  struct termios ios;
  char *term = getenv("TERM");

  if (!tty_getwinsize(fd, &req->width, &req->height,
		      &req->width_p, &req->height_p))
    req->width = req->height = req->width_p = req->height_p = 0;
      
  if (tty_getattr(fd, &ios))
    req->modes = tty_encode_term_mode(&req->ios);
  else
    {
      KILL(req);
      return NULL;
    }
  
  req->super.format = do_format_pty_request;
  req->super.super.call = do_channel_request_command;
  
  req->tty = fd;
  req->term = term ? format_cstring(term) : ssh_format("");

  return &req->super;
}

/* GABA:
   (class
     (name raw_mode_command)
     (super command)
     (vars
       (fd . int)))
*/

static int do_raw_mode(struct command *s,
		       struct lsh_object *x,
		       struct command_continuation *c)
{
  CAST(raw_mode_command, self, s);

  verbose("lsh: pty request %z.\n", x ? "successful" : "failed");
  
  if (x)
    {
      
#if 0
struct lsh_string *
format_pty_req(struct ssh_channel *channel, int want_reply, 
	       UINT8 *term, UINT32 width, UINT32 height, UINT32 width_p, 
	       UINT32 height_p, struct lsh_string *term_modes)
{
  return format_channel_request(ATOM_PTY_REQ, channel, want_reply, 
				"%s%i%i%i%i%S",
				strlen(term),
				term,
				width, height,
				width_p, height_p,
				term_modes);
}
#endif

