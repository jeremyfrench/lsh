/* password.h
 *
 * System dependant password related functions.
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef LSH_PASSWORD_H_INCLUDED
#define LSH_PASSWORD_H_INCLUDED

#include "lsh_types.h"

#include <sys/types.h>
#include <unistd.h>

struct lsh_string *
read_password(int max_length, char *format, ...) PRINTF_STYLE(1,2);

struct unix_user
{
  struct lsh_object header;
  
  uid_t uid;
  struct lsh_string *passwd; /* Crypted passwd */
  struct lsh_string *home;
};

struct unix_user *lookup_user(lsh_string *name);
int verify_passwd(struct unix_user *user, lsh_string *password);


#endif /* LSH_PASSWORD_H_INCLUDED */
