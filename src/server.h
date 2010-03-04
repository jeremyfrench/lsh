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
#include "server_config.h"
#include "werror.h"

#define GABA_DECLARE
#include "server.h.x"
#undef GABA_DECLARE

const char *
server_lookup_module(const char **modules,
		     uint32_t length, const uint8_t *name);

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
     (name service_config)
     (vars
       ; Pointers into the original command line
       (name . "const char *")
       (args indirect-special "struct arglist" #f arglist_clear)))
*/

struct service_config *
make_service_config(void);

extern const struct argp service_argp;

#endif /* LSH_SERVER_H_INCLUDED */

