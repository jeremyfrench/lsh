/* server_config.h
 *
 * Parsing of server configuration files. */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 2005 Niels Möller
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02111-1301  USA
 */

#ifndef LSH_SERVER_CONFIG_H_INCLUDED
#define LSH_SERVER_CONFIG_H_INCLUDED

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
  /* VALUE is 0 or 1 */
  CONFIG_TYPE_BOOL,
  /* VALUE holds an unsigned number */
  CONFIG_TYPE_NUMBER,
  /* Length stored in VALUE, DATA points to the constants. Currently
     not allocated, but a pointer into the input data. FIXME: To
     support quoting with escape handling, we'd need to allocate the
     string. */
  CONFIG_TYPE_STRING,
  /* Length stored in VALUE, DATA points at a newly allocated
     catenation of NUL-terminated strings. Similar to argz, but with
     an explicit length to specify the end of the list. */
  CONFIG_TYPE_LIST
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

#endif /* LSH_SERVER_CONFIG_H_INCLUDED */
