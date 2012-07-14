/* parse_config.c
 *
 * Parsing of configuration files. */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 2002 Niels Möller
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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <string.h>

#include "parse_config.h"

#include "format.h"
#include "lsh_string.h"
#include "parse.h"
#include "tokenize_config.h"
#include "werror.h"
#include "xalloc.h"

#ifndef DEBUG_PARSE_CONFIG
#define DEBUG_PARSE_CONFIG 0
#endif

#if DEBUG_PARSE_CONFIG
# define DEBUG(x) werror x
#else
# define DEBUG(x)
#endif

#define BUFFER (&(self->buffer))

#include "parse_macros.h"

#include "parse_config.c.x"

/* GABA:
   (class
     (name config_setting)
     (vars
       (next object config_setting)
       (type . "enum config_type")
       (value string)))
*/

/* GABA:
   (class
     (name config_host)
     (vars
       (next object config_host)
       (name string)
       (settings object config_setting)))
*/

/* GABA:
   (class
     (name config_group)
     (vars
       (next object config_group)
       (name string)
       ; Group settings
       (settings object config_setting)
       (hosts object config_host)))
*/



#define PARSE_ERROR(msg) config_tokenizer_error(self, (msg))

static int
parse_setting(struct config_tokenizer *self, struct config_setting **settings)
{
  struct lsh_string *s;
  enum config_type type;

  if (self->type != TOK_STRING)
    { PARSE_ERROR("syntax error"); return 0; }
  
  if (config_tokenizer_looking_at(self, "address"))
    type = CONFIG_ADDRESS;
  else if (config_tokenizer_looking_at(self, "user"))
    type = CONFIG_USER;
  else
    {
      werror("Unknown keyword `%s'\n", self->token_length, self->token);
      config_tokenizer_next(self);
      
      if (self->type == TOK_STRING)
	config_tokenizer_next(self);

      return 1;
    }
  config_tokenizer_next(self);

  s = config_tokenizer_get_string(self);
  if (!s)
    return 0;
  
  {
    /* Push new object on the list */
    NEW(config_setting, n);
    n->next = *settings;
    *settings = n;
  
    n->type = type;
    n->value = s;
  }
  return 1;
}


static struct config_setting *
parse_host_settings(struct config_tokenizer *self)
{
  struct config_setting *settings = NULL;

  while (self->type == TOK_STRING)
    {
      if (!parse_setting(self, &settings))
	return NULL;
    }
  return settings;
}


static int
parse_hosts(struct config_tokenizer *self, struct config_host **hosts)
{
  while (self->type == TOK_STRING)
    {
      {
	/* Push new object on the list */
	NEW(config_host, n);
	n->next = *hosts;
	*hosts = n;
	
	n->name = config_tokenizer_get_string(self);
	assert(n->name);
	if (self->type == TOK_BEGIN_GROUP)
	  {
	    config_tokenizer_next(self);
	    n->settings = parse_host_settings(self);
	    if (!config_tokenizer_skip_token(self, TOK_END_GROUP))
	      return 0;
	  }
      }
    }
  return 1;
}

static struct config_group *
parse_groups(struct config_tokenizer *self)
{
  struct config_group *groups = NULL;
  while (self->type != TOK_EOF)
    {
      {
	/* Push new object on the list */
	NEW(config_group, n);
	n->next = groups;
	groups = n;
      }
      /* Name is optional */
      if (self->type == TOK_STRING)
	groups->name = config_tokenizer_get_string(self);
      else
	groups->name = NULL;	
      groups->settings = NULL;
      groups->hosts = NULL;
      
      if (!config_tokenizer_skip_token(self, TOK_BEGIN_GROUP))
	return NULL;

      while (self->type != TOK_END_GROUP)
	{
	  if (config_tokenizer_looking_at(self, "hosts"))
	    {
	      config_tokenizer_next(self);
	      if (!config_tokenizer_skip_token(self, TOK_BEGIN_GROUP))
		return NULL;

	      if (!parse_hosts(self, &groups->hosts))
		return NULL;
	      if (!config_tokenizer_skip_token(self, TOK_END_GROUP))
		return NULL;
	    }
	  else
	    {
	      if (!parse_setting(self, &groups->settings))
		return NULL;
	    }
	}
      if (!config_tokenizer_skip_token(self, TOK_END_GROUP))
	return NULL;
    }
  return groups;
}

struct config_group *
config_parse_string(const char *file, uint32_t length, const uint8_t *data)
{
  struct config_tokenizer t;
  config_tokenizer_init(&t, file, length, data);
  config_tokenizer_next(&t);

  return parse_groups(&t);
}

int
config_lookup_host(const struct config_group *groups,
		   const char *host,
		   struct config_match *match)
{
  unsigned length = strlen(host);
  int found = 0;
  
  for (; groups; groups = groups->next)
    {
      const struct config_host *hosts;
      for (hosts = groups->hosts; hosts; hosts = hosts->next)
	if (lsh_string_eq_l(hosts->name, length, host))
	  {
	    if (found)
	      {
		werror("Ambigous host name `%z' in configuration.\n");
		return 1;
	      }
	    else
	      {
		found = 1;
		match->group = groups->settings;
		match->host = hosts->settings;
	      }
	  }
    }
  return found;
}

const struct lsh_string *
config_get_setting(enum config_type type,
		   const struct config_match *match)
{
  const struct config_setting *p;

  for (p = match->host; p; p = p->next)
    if (p->type == type)
      return p->value;

  for (p = match->group; p; p = p->next)
    if (p->type == type)
      return p->value;

  return NULL;
}
