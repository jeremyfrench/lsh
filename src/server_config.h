/* server_config.h
 *
 * Parsing of server configuration files. */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 2005 Niels M�ller
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

#ifndef SERVER_CONFIG_H_INCLUDED
#define SERVER_CONFIG_H_INCLUDED

#include <stdio.h>

#include "lsh.h"

/* Both interface and implementation tries to follow that of argp. */

union config_value;
struct config_parser;
struct config_parser_state;

/* FIXME: Using errno seems to be more hassle than it's worth.
   Returning a simple success/fail indication should be sufficient. */
/* Returns errno value. EINVAL is used for invalid or unsupported options */
typedef int (*config_parser_handler_t)(int key, uint32_t value, const uint8_t *data,
				       struct config_parser_state *state);

enum config_type
{
  CONFIG_TYPE_NONE,
  /* CONFIG_TYPE_NOARG, */
  CONFIG_TYPE_BOOL,
  CONFIG_TYPE_UNSIGNED,
  CONFIG_TYPE_STRING
};

enum
{
  CONFIG_PARSE_KEY_INIT = 0x100000,
  CONFIG_PARSE_KEY_END,
};

struct config_option
{
  int key;
  const char *name;
  enum config_type type;
  const char *doc;
  const char *example;
};

struct config_parser
{
  /* Array terminated by CONFIG_TYPE_NONE */
  const struct config_option *options;

  config_parser_handler_t handler;

  /* If non-NULL, a NULL-terminated array of child parsers */
  const struct config_parser **children;
};

struct config_parser_state
{  
  void *input;
  void **child_inputs;
};

int
server_config_parse_string(const struct config_parser *parser,
			   const char *file,
			   uint32_t length, const uint8_t *data,
			   void *input);

int
server_config_parse_example(const struct config_parser *parser,
			    void *input);

void
server_config_print_example(const struct config_parser *parser,
			    FILE *f);

#endif /* LSH_PARSE_CONFIG_H_INCLUDED */
