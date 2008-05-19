/* interact.h
 *
 * Interact with the user.
 *
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1999, 2008 Niels Möller
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef LSH_INTERACT_H_INCLUDED
#define LSH_INTERACT_H_INCLUDED

#include "lsh.h"

/* Forward declaration */
struct winsize; /* In sys/ioctl.h */
struct termios;

#define GABA_DECLARE
#include "interact.h.x"
#undef GABA_DECLARE


/* Methods needed to communicate with the user's terminal. */

/* GABA:
   (class
     (name window_change_callback)
     (vars
       (f method void "const struct winsize *dims")))
*/

/* GABA:
   (class
     (name interact_dialog)
     (vars
       (instruction string)
       (nprompt . unsigned)
       (prompt space (string) nprompt)
       (response space (string) nprompt)
       (echo space int nprompt)))
*/

struct interact_dialog *
make_interact_dialog(unsigned nprompt);

int
interact_is_tty(void);

void
interact_set_askpass(const char *askpass);

int
interact_yes_or_no(const struct lsh_string *prompt, int def, int free);

struct lsh_string *
interact_read_password(const struct lsh_string *prompt);

int
interact_dialog(const struct interact_dialog *dialog);

int
interact_set_mode(int raw);

int
interact_get_window_size(struct winsize *dims);

struct resource *
interact_on_window_change(struct window_change_callback *c);

const struct termios *
interact_get_terminal_mode(void);

int
unix_interact_init(int prepare_raw_mode);

#endif /* LSH_INTERACT_H_INCLUDED */
