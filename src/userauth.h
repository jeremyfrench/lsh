/* userauth.h
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef LSH_USERAUTH_H_INCLUDED
#define LSH_USERAUTH_H_INCLUDED

#include "list.h"
#include "parse.h"
#include "service.h"

#define GABA_DECLARE
#include "userauth.h.x"
#undef GABA_DECLARE

/* Returns 0 if the request is somehow invalid. Otherwise, returns 1,
 * and sets SERVICE non-NULL iff access is granted. */

/* FIXME: Something more general is needed for authentication methods
 * which send additional messages. */

/* GABA:
   (class
     (name userauth)
     (vars
       (authenticate method int
		     ; The name is consumed by this function
		     "struct lsh_string *username"
		     "int requested_service"
		     "struct simple_buffer *args"
		     "struct ssh_service **service")))
*/

#define AUTHENTICATE(s, u, r, a, g) \
((s)->authenticate((s), (u), (r), (a), (g)))

struct lsh_string *format_userauth_failure(struct int_list *methods,
					   int partial);
struct lsh_string *format_userauth_success(void);

/* Server functions */     
struct ssh_service *make_userauth_service(struct int_list *advertised_methods,
					  struct alist *methods);

/* Client functions */
struct ssh_service *make_client_userauth(struct lsh_string *username,
					 int service_name,
					 struct ssh_service *service);

#endif /* LSH_USERAUTH_H_INCLUDED */
