/* randomness.c
 *
 *
 *
 * $Id$ */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998, 1999, 2000, Niels Möller
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

#include "randomness.h"

#include "werror.h"

#include "crypto.h"
#include "exception.h"
#include "xalloc.h"

#include "nettle/arcfour.h"

#include <errno.h>

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <string.h>

#define GABA_DEFINE
#include "randomness.h.x"
#undef GABA_DEFINE

#if 0

#include "randomness.c.x"

#endif
