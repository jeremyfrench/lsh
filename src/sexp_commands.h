/* sexp_commands.h
 *
 * Reading and writing of s-expressions.
 *
 * $Id$ */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1999 Niels Möller
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

#ifndef SEXP_COMMANDS_H_INCLUDED
#define SEXP_COMMANDS_H_INCLUDED

#include "abstract_io.h"
#include "command.h"
#include "sexp.h"

struct command_simple *
make_write_sexp_command(int format);

struct command *
make_write_sexp_to(int format, struct abstract_write *dest);

struct command *
make_read_sexp_command(int format, int goon);

#endif /* SEXP_COMMANDS_H_INCLUDED */
