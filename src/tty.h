/* tty.h
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

#ifndef LSH_TTY_H_INCLUDED
#define LSH_TTY_H_INCLUDED

#include <termios.h>

int tty_getattr(int fd, struct termios *ios);
int tty_setattr(int fd, struct termios *ios);

/* Sets the controlling tty of the callign process, and also attempts to make
 * the process a process group leader. */
int tty_setctty(int fd);

int tty_makeraw(int fd);
int tty_getwinsize(int fd, int *w, int *h, int *wp, int *hp);
int tty_setwinsize(int fd, int w, int h, int wp, int hp);

#endif
