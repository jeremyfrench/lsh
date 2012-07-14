/* lsh_process.h
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02111-1301  USA
 */

#ifndef LSH_PROCESS_H_INCLUDED
#define LSH_PROCESS_H_INCLUDED

/* For pid_t */
#include <unistd.h>

#include "resource.h"

#define GABA_DECLARE
# include "lsh_process.h.x"
#undef GABA_DECLARE

/* GABA:
   (class
     (name lsh_process)
     (super resource)
     (vars
       (signal method int int)))
*/

#define SIGNAL_PROCESS(p, s) ((p)->signal((p), (s)))

struct env_value
{
  const char *name;
  const char *value;
};

#define SPAWN_INFO_FIRST_ARG 1

struct spawn_info
{
  /* Is it a login session? */
  int login ;
  
  /* {in|out|err}[0] is for reading,
   * {in|out|err}[1] for writing. */

  /* Negative values for the child fd:s means that the slave tty should
   * be used. */
  int in[2]; int out[2]; int err[2];
  struct pty_info *pty;

  /* These are the arguments to the shell, the first real argument is
   * at SPAWN_INFO_FIRST_ARG, the slots before that are used by
   * spawn_process. Must be terminated by a NULL. Can be a NULL
   * pointer if there are nu arguments. */
  const char **argv;

  /* Dangerous variables must not be set, in order for things like
     restricted shells to work securely. */
  unsigned env_length;
  const struct env_value *env;
};

/* On success, closes the childs stdio fd:s. On error, closes all the
   stdio fd:s. */
struct lsh_process *
spawn_shell(struct spawn_info *info, int helper_fd, struct exit_callback *c);

#endif /* LSH_PROCESS_H_INCLUDED */
