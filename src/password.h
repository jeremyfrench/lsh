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

#ifndef LSH_PASSWORD_H_INCLUDED
#define LSH_PASSWORD_H_INCLUDED

#include "lsh.h"

#include "alist.h"

#include <sys/types.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#define GABA_DECLARE
#include "password.h.x"
#undef GABA_DECLARE

struct lsh_string *
read_password(int max_length, struct lsh_string *prompt, int free);

/* GABA:
   (class
     (name unix_user)
     (vars
       (uid simple uid_t)
       (gid simple gid_t)
       
       ; These strings include a terminating NUL-character, for
       ; compatibility with library and system calls.
       (name string)
       (passwd string)  ; Crypted passwd
       (home string)
       (shell string)))
       
*/

struct unix_user *lookup_user(struct lsh_string *name, int free);
int verify_password(struct unix_user *user,
		    struct lsh_string *password, int free);

struct userauth *make_password_userauth(void);

/* GABA:
   (class
     (name unix_service)
     (vars
       (login method (object ssh_service) "struct unix_user *user")))
*/

#define LOGIN(s, u) ((s)->login((s), (u)))

struct userauth *make_unix_userauth(struct alist *services);

int change_uid(struct unix_user *user);
int change_dir(struct unix_user *user);

#if 0
struct login_method
{
  struct lsh_object header;

  struct ssh_service * (*login)(struct login_method *closure,
				struct unix_user *user,
				struct ssh_service *service);
};

#define LOGIN(m, u, s) ((m)->login((m), (u), (s)))

struct userauth *make_unix_userauth(struct login_method *login,
				    struct alist *services);
struct login_method *make_unix_login(void);
#endif

#endif /* LSH_PASSWORD_H_INCLUDED */
