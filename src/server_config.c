/* server_config.c
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
 *
 */

/*
 * Partly based on Miles Bader's argp, Copyright Free Software
 * Foundation.
 */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <errno.h>
#include <string.h>

#include "server_config.h"

#include "tokenize_config.h"
#include "werror.h"
#include "xalloc.h"

struct group
{
  const struct config_parser *parser;

  struct group *parent;
  unsigned parent_index;
  
  struct config_parser_state state;
};

/* FIXME: Use a hash table for option names? */
struct parser_state
{
  struct group *groups;
  struct group *egroup;

  size_t num_child_inputs;
  void **child_inputs;

  void *storage;
};

struct parser_sizes
{
  size_t num_groups;
  size_t num_child_inputs;
};

static void
init_sizes (struct parser_sizes *szs)
{
  szs->num_groups = 0;
  szs->num_child_inputs = 0;
}

static void
calc_sizes (const struct config_parser *parser, struct parser_sizes *szs)
{
  const struct config_parser **children = parser->children;
  
  szs->num_groups++;
  if (children)
    while (*children)
      {
	calc_sizes(*children++, szs);
	szs->num_child_inputs++;	
    }  
}

static void
convert_options(const struct config_parser *parser,
		struct group *parent, unsigned parent_index,
		struct group **next_group,
		void ***next_input_slot)
{
  const struct config_parser **children = parser->children;
  struct group *group = (*next_group)++;

  group->parser = parser;
  group->parent = parent;
  group->parent_index = parent_index;

  if (!children)
    group->state.child_inputs = NULL;    
  else
    {
      size_t num_children;
      size_t i;
      for (num_children = 0; children[num_children]; num_children++)
	;
      group->state.child_inputs = *next_input_slot;
      *next_input_slot += num_children;

      for (i = 0; i < num_children; i++)
	convert_options(children[i], group, i, next_group, next_input_slot);
    }  
}

static int
parser_init(struct parser_state *state,
	    const struct config_parser *parser,
	    void *input)
{
  struct parser_sizes szs;
  size_t group_alloc;
  size_t input_alloc;
  void **next_input_slot;
  struct group *group;
  
  /* Allocate and initialize group structures */
  init_sizes(&szs);
  calc_sizes(parser, &szs);

  group_alloc = sizeof(*state->groups) * szs.num_groups;
  input_alloc = sizeof(*state->child_inputs) * szs.num_child_inputs;
  state->storage = malloc(group_alloc + input_alloc);

  if (!state->storage)
    return ENOMEM;

  state->groups = state->storage;
  state->egroup = state->groups + szs.num_groups;

  if (szs.num_child_inputs > 0)
    {
      state->child_inputs = (void *) ((char *) state->storage + group_alloc);
      memset(state->child_inputs, 0, input_alloc);
    }
  else
    state->child_inputs = NULL;

  group = state->groups;
  next_input_slot = state->child_inputs;

  convert_options(parser, NULL, 0, &group, &next_input_slot);

  assert(group == state->egroup);
  assert(next_input_slot == state->child_inputs + szs.num_child_inputs);

  /* Call with CONFIG_KEY_INIT, for propagation of child inputs */
  state->groups[0].state.input = input;

  for (group = state->groups; group < state->egroup; group++)
    {
      int err;
      
      if (group->parent)
	group->state.input = group->parent->state.child_inputs[group->parent_index];

      err = group->parser->handler(CONFIG_PARSE_KEY_INIT, 0, NULL, &group->state);
      if (err && err != EINVAL)
	{
	  /* Abort initialization */
	  free(state->storage);
	  state->storage = NULL;
	  return err;
	}
    }

  return 0;
}

static void
parser_finalize(struct parser_state *state)
{
  struct group *group;

  /* Call parsers once more, to do any final cleanup.  Errors are ignored.  */
  for (group = state->egroup - 1; group >= state->groups; group--)
    group->parser->handler (CONFIG_PARSE_KEY_END, 0, NULL, &group->state);

  free(state->storage);
  state->storage = NULL;
}

static int
parse_value_bool(uint32_t *value, unsigned length, const uint8_t *arg)
{
  if (length == 2 && !memcmp(arg, "no", 2))
    *value = 0;
  else if (length == 3 && !memcmp(arg, "yes", 3))
    *value = 1;
  else
    return EINVAL;

  return 0;
}

static int
parse_value_unsigned(uint32_t *value, unsigned length, const uint8_t *arg)
{
  fatal("Not implemented.\n");
}

/* NOTE: More or less duplicates nettle_buffer. But lshd-connection
   isn't linked with nettle. */
static void
list_append(uint32_t *length, uint32_t *size, uint8_t **list,
	    uint32_t token_length, const uint8_t *token)
{
  /* Allocates using lsh_space_alloc and lsh_space_realloc rather than
     malloc/realloc, so that the service_config calls can free it
     using lsh_space_free. */
  if (!*size)
    {
      *size = token_length + 100;
      *list = lsh_space_alloc(*size);
    }
  else if (*size < *length + token_length + 1)
    {
      *size = *size * 2 + token_length + 1;
      *list = lsh_space_realloc(*list, *size);
    }
  memcpy(*list + *length, token, token_length);
  (*list)[*length + token_length] = '\0';
  *length += token_length + 1;
}

static int
parse_value_list(uint32_t *length, uint8_t **list,
		 struct config_tokenizer *tokenizer)
{
  uint32_t size;
  unsigned level;
  unsigned start_line;

  *length = 0;
  size = 0;

  if (config_tokenizer_next(tokenizer) != TOK_STRING)
    return EINVAL;

  list_append (length, &size, list,
	       tokenizer->token_length, tokenizer->token);

  if (config_tokenizer_next(tokenizer) != TOK_EQUAL)
    {
      config_tokenizer_error(tokenizer, "Missing '='");
      goto fail;
    }

  if (config_tokenizer_next(tokenizer) != TOK_BEGIN_GROUP)
    {
      config_tokenizer_error(tokenizer, "Missing '{'");
      goto fail;
    }

  start_line = tokenizer->lineno;
  level = 1;

  for (;;)
    {
      switch (config_tokenizer_next(tokenizer))
	{
	case TOK_STRING:
	  list_append (length, &size, list,
		       tokenizer->token_length, tokenizer->token);
	  break;
	case TOK_BEGIN_GROUP:
	  level++;
	  list_append (length, &size, list, 1, "{");
	  break;
	case TOK_END_GROUP:
	  level--;
	  if (!level)
	    return 0;
	  list_append (length, &size, list, 1, "}");
	  break;
	case TOK_EQUAL:
	  list_append (length, &size, list, 1, "=");
	  break;
	case TOK_EOF:
	  werror("%z:%i: Unexpected end of file when parsing group\n",
		 tokenizer->file, start_line);
	  /* Fall through */
	case TOK_ERROR:
	  goto fail;
	}
    }
 fail:
  lsh_space_free(*list);	  
  return EINVAL;
}

static int
parser_parse_option(struct parser_state *state,
		    struct config_tokenizer *tokenizer)
{  
  struct group *group;
  int err = 0;

  for (group = state->groups; group < state->egroup; group++)
    {
      const struct config_parser *parser= group->parser; 
      const struct config_option *option;
     
      for (option = parser->options; option->type != CONFIG_TYPE_NONE; option++)
	{
	  if (config_tokenizer_looking_at (tokenizer, option->name))
	    {
	      uint32_t value;
	      const uint8_t *data;

	      if (option->type == CONFIG_TYPE_LIST)
		{
		  uint8_t *list;
		  err = parse_value_list(&value, &list, tokenizer);
		  data = list;
		}
	      else
		{
		  if (config_tokenizer_next(tokenizer) != TOK_EQUAL)
		    {
		      werror("%z:%i: Missing '=' for configuration option `%z'\n",
			     tokenizer->file, tokenizer->lineno,
			     option->name);
		      return EINVAL;
		    }
		  if (config_tokenizer_next(tokenizer) != TOK_STRING)
		    {
		      werror("%z:%i: Bad syntax for configuration option `%z'\n",
			     tokenizer->file, tokenizer->lineno,
			     option->name);
		      return EINVAL;
		    }
		  else
		    {
		      unsigned length = tokenizer->token_length;
		      const uint8_t *arg = tokenizer->token;
		      
		      switch (option->type)
			{
			default:
			  werror("%z:%i: Unknown configuration type %i for option `%z'\n",
				 tokenizer->file, tokenizer->lineno,
				 option->type, option->name);
			  return EINVAL;
	  
			case CONFIG_TYPE_BOOL:
			  err = parse_value_bool(&value, length, arg);
			  break;

			case CONFIG_TYPE_NUMBER:
			  err = parse_value_unsigned(&value, length, arg);
			  break;

			case CONFIG_TYPE_STRING:
			  value = length;
			  data = arg;
			  break;
			}
		    }
		}

	      if (err)
		werror("%z:%i: Bad value for configuration option `%z'\n",
		       tokenizer->file, tokenizer->lineno,
		       option->name);
	      else
		{
		  if (!config_tokenizer_eolp (tokenizer))
		    config_tokenizer_error(tokenizer,
					   "Ignoring spurious data at end of line");

		  err = group->parser->handler(option->key,
					       value, data, &group->state);
		}

	      /* FIXME: Use a special error code analogous to
		 ARGP_ERR_UNKNOWN. But which errno value can we borrow
		 for this use? */
	      return err;
	    }
	}
    }
  werror("%z:%i: Unknown configuration option `%s'\n",
	 tokenizer->file, tokenizer->lineno,
	 tokenizer->token_length, tokenizer->token);

  return EINVAL;
}

int
server_config_parse_string(const struct config_parser *parser,
			   const char *file,
			   uint32_t length, const uint8_t *data,
			   void *input)
{
  struct config_tokenizer tokenizer;
  struct parser_state state;

  int err;

  config_tokenizer_init(&tokenizer, file, length, data);
  
  err = parser_init(&state, parser, input);
  if (err)
    return err;

  while (!err)
    {
      enum config_token_type type = config_tokenizer_next(&tokenizer);
      switch (type)
	{
	default:
	  err = EINVAL;
	  break;
	case TOK_STRING:
	  err = parser_parse_option(&state, &tokenizer);
	  break;
	case TOK_EOF:
	  goto done;
	}
      /* FIXME: Require newline or separator between options? */
    }  
 done:
  
  parser_finalize(&state);
  return err;
}

int
server_config_parse_example(const struct config_parser *parser,
			    void *input)
{
  struct parser_state state;
  struct group *group;
  int err;

  err = parser_init(&state, parser, input);
  if (err)
    return err;

  for (group = state.egroup - 1; group >= state.groups; group--)
    {
      const struct config_parser *parser= group->parser; 
      const struct config_option *option;

      for (option = parser->options; option->type != CONFIG_TYPE_NONE; option++)
	if (option->example)
	  {
	    uint32_t value = 0;
	    const uint8_t *data = NULL;

	    unsigned length = strlen(option->example);

	    switch (option->type)
	      {
	      default:
		fatal("Internal error.\n");

	      case CONFIG_TYPE_LIST:
		{
		  struct config_tokenizer tokenizer;
		  uint8_t *list;
		  
		  config_tokenizer_init(&tokenizer, "example fragment",
					length, option->example);

		  err = parse_value_list(&value, &list, &tokenizer);
		  data = list;
		  break;
		}
	      case CONFIG_TYPE_BOOL:
		err = parse_value_bool(&value, length, option->example);
		break;

	      case CONFIG_TYPE_NUMBER:
		err = parse_value_unsigned(&value, length, option->example);
		break;

	      case CONFIG_TYPE_STRING:
		value = length;
		data = option->example;
		break;
	      }
	  
	    if (err)
	      fatal("Bad example value for configuration option `%z'\n",
		    option->name);
	    else
	      err = group->parser->handler(option->key, value, data, &group->state);

	  }
    }
  parser_finalize(&state);
  return err;
}

void
server_config_print_example(const struct config_parser *parser,
			    FILE *f)
{
  const struct config_option *option;

  for (option = parser->options; option->type != CONFIG_TYPE_NONE; option++)
    {
      fprintf(f, "# %s\n", option->doc);
      if (!option->example)
	fprintf(f, "# ");

      fprintf(f, "%s", option->name);
      
      if (option->example)
	{
	  if (option->type != CONFIG_TYPE_LIST)
	    fprintf(f, " =");
	  fprintf(f, " %s", option->example);
	}
      else switch(option->type)
	{
	default:
	  break;
	case CONFIG_TYPE_STRING:
	  fprintf(f, " = STRING");
	  break;
	case CONFIG_TYPE_BOOL:
	  fprintf(f, " = yes / no");
	  break;
	case CONFIG_TYPE_NUMBER:
	  fprintf(f, " = NUMBER");
	  break;
	case CONFIG_TYPE_LIST:
	  fprintf(f, " NAME { ARGS... }");
	  break;
	}

      fprintf(f, "\n\n");
    }

  if (parser->children)
    {
      const struct config_parser **children;

      for (children = parser->children; *children; children++)
	{
	  /* Empty line to separate groups */
	  fprintf(f, "\n");
	  server_config_print_example(*children, f);
	}
    }
}
