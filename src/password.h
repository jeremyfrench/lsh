/* password.h
 *
 * System dependant password related functions.
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#warning password.h is obsolete

#ifndef LSH_PASSWORD_H_INCLUDED
#define LSH_PASSWORD_H_INCLUDED

#include "lsh.h"

#include "alist.h"

#include <sys/types.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif

struct lsh_string *
read_password(int max_length, struct lsh_string *prompt, int free);

#endif /* LSH_PASSWORD_H_INCLUDED */
