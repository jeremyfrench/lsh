/* reaper.h
 *
 * Handle child processes.
 *
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998 Niels Möller
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

#ifndef LSH_REAPER_H_INCLUDED
#define LSH_REAPER_H_INCLUDED

#include "io.h"

#define GABA_DECLARE
#include "reaper.h.x"
#undef GABA_DECLARE

/* GABA:
   (class
     (name exit_callback)
     (vars
       (exit method void "int signaled" "int core" "int value")))
*/

#define EXIT_CALLBACK(e, s, c, v) ((e)->exit((e), (s), (c), (v)))

/* Uses global state */
void
reaper_init(void);

void
reaper_handle(pid_t pid, struct exit_callback *callback);

#endif /* LSH_REAPER_H_INCLUDED */
