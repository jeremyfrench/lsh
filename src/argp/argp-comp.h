/* argp-comp.h
 *
 * Portability stuff for compiling argp outside of glibc.
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

#ifndef LSH_ARGP_COMP_H_INCLUDED
#define LSH_ARGP_COMP_H_INCLUDED

#include "lsh_types.h"

/* Missing declarations. */
extern char *program_invocation_name;
extern char *program_invocation_short_name;

void
_argp_unlock_xxx (void);

#ifndef __THROW
#define __THROW
#endif

#if !HAVE_MEMPCPY
#include "mempcpy.h"
#endif

#if !HAVE_STRNDUP
#include "strndup.h"
#endif

#include <string.h>

#ifndef __mempcpy
#define __mempcpy mempcpy
#endif

/* For some reason, I can't get this to interact correctly with the header files on my glibc system.
 * So instead, I edited the code in argp-help.c that tried to use __strndup. */

#if 0
#ifndef __strndup
#define __strndup strndup
#endif
#endif

#endif /* LSH_ARGP_COMP_H_INCLUDED */
