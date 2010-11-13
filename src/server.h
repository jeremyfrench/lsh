/* server.h
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

#ifndef LSH_SERVER_H_INCLUDED
#define LSH_SERVER_H_INCLUDED

#include "arglist.h"
#include "queue.h"
#include "server_config.h"
#include "werror.h"

#define GABA_DECLARE
#include "server.h.x"
#undef GABA_DECLARE


/* GABA:
   (class
     (name server_config)
     (super werror_config)
     (vars
       (parser . "const struct config_parser *")
       (default_file . "const char *")
       (env_variable . "const char *")
       
       (config_file . "const char *")
       (use_example . int)))
*/

void
init_server_config(struct server_config *self,
		   const struct config_parser *parser,
		   const char *default_file,			
		   const char *env_variable);

struct server_config *
make_server_config(const struct config_parser *parser,
		   const char *default_file,			
		   const char *env_variable);

extern const struct argp server_argp;


/* GABA:
   (class
     (name service_entry)
     (vars
       ; Storage for the strings, or NULL if they need not be deallocated.
       (storage space "const char")
       (name_length . size_t)
       (name . "const char *")
       (args indirect-special "struct arglist" #f arglist_clear)))
*/

struct service_entry *
make_service_entry(const uint8_t *name, const uint8_t *storage);

/* GABA:
   (class
     (name service_config)
     (vars
       (services struct object_queue)
       (libexec_dir . "const char *")
       (override_config_file . int)))
*/

struct service_config *
make_service_config(void);

const struct service_entry *
service_config_lookup(const struct service_config *self,
		      size_t length, const char *name);

void
service_config_argp(struct service_config *self,
		    struct argp_state *state,
		    const char *opt, const char *name);

int
service_config_option(struct service_config *self,
		      const char *opt, uint32_t length, const uint8_t *data);

#endif /* LSH_SERVER_H_INCLUDED */

