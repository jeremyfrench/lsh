/* seed_file.h */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 2008 Niels Möller
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

#include "nettle/yarrow.h"

#include "lsh.h"

int
seed_file_lock(int fd, int wait);

int
seed_file_unlock(int fd);

int
seed_file_check_permissions(int fd, const struct lsh_string *filename);

int
seed_file_write(int fd, struct yarrow256_ctx *ctx);

