/* parse_config.c
 *
 * $id$
 *
 * Parsing of configuration files. */

#include "parse_config.h"

#include "format.h"
#include "parse.h"
#include "werror.h"
#include "xalloc.h"

#include <assert.h>
#include <string.h>

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

enum token_type
  { TOK_EOF, TOK_BEGIN_GROUP, TOK_END_GROUP, TOK_STRING, TOK_ERROR };

/* FIXME: Keep track of linenumber */
struct tokenizer
{
  struct simple_buffer buffer;
  enum token_type type;
  unsigned token_length;
  const char *token;
};

static void
tokenizer_init(struct tokenizer *self,
	       unsigned length, const unsigned char *data)
{
  simple_buffer_init(&self->buffer, length, data);
}

static enum token_type
next_token(struct tokenizer *self)
{
  /* FIXME: Share a char-class table with sexp_parser.c. */
  static const char char_class[0x100] =
    {
      /* HT, LF, VT, FF, CR */
      0,0,0,0,0,0,0,0,0,1,1,1,1,1,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      /* SPACE */
      1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      /* '{', '}' */
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,2,0,2,0,0,

      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    };
#define IS_SPACE(c) (char_class[c] & 1)
#define IS_SEPARATOR(c) (char_class[c] & 3)
  while (LEFT && IS_SPACE(*HERE))
    ADVANCE(1);

  if (!LEFT)
    self->type = TOK_EOF;
  else switch(*HERE)
    {
    case '{':
      self->type = TOK_BEGIN_GROUP;
      ADVANCE(1);
      break;
    case '}':
      self->type = TOK_END_GROUP;
      ADVANCE(1);
      break;
    default:
      {
	unsigned i;
	self->token = HERE;
	
	for (i = 0; i<LEFT && !IS_SEPARATOR(HERE[i]); i++)
	  ;
	self->token_length = i;
	ADVANCE(i);
      }
    }
  return self->type;
}

/* Can only be called if self->type == TOK_STRING */
static int
looking_at(struct tokenizer *self, const char *word)
{
  unsigned length = strlen(word);

  return (length == self->token_length
	  && !memcmp(self->token, word, length));
}

static struct lsh_string *
parse_word(struct tokenizer *self)
{
  struct lsh_string *s;
  if (self->type != TOK_STRING)
    return NULL;

  s = ssh_format("%ls", self->token_length, self->token);
  next_token(self);
  return s;
}

static struct config_setting *
parse_setting(struct tokenizer *self, struct config_setting *settings)
{
  struct lsh_string *s;
  enum config_type type;
  if (looking_at(self, "address"))
    type = CONFIG_ADDRESS;
  else if (looking_at(self, "user"))
    type = CONFIG_USER;
  else
    return NULL;

  next_token(self);
  s = parse_word(self);
  if (!s)
    return NULL;
  
  {
    /* Push new object on the list */
    NEW(config_setting, n);
    n->next = settings;
    settings = n;
  }
  
  settings->type = type;
  settings->value = s;

  return settings;
}

static struct config_setting *
parse_host_settings(struct tokenizer *self)
{
  struct config_setting *settings = NULL;

  while (self->type == TOK_STRING)
    {
      settings = parse_setting(self, settings);
      if (!settings)
	return NULL;
    }
  return settings;
}

static int
parse_token(struct tokenizer *self, enum token_type type)
{
  if (self->type == type)
    {
      next_token(self);
      return 1;
    }
  else
    return 0;
}

static struct config_host *
parse_hosts(struct tokenizer *self, struct config_host *hosts)
{
  while (self->type == TOK_STRING)
    {
      {
	/* Push new object on the list */
	NEW(config_host, n);
	n->next = hosts;
	hosts = n;
      }
      hosts->name = parse_word(self);
      assert(hosts->name);
      if (self->type == TOK_BEGIN_GROUP)
	{
	  hosts->settings = parse_host_settings(self);
	  if (!parse_token(self, TOK_END_GROUP))
	    return NULL;
	}
    }
  return hosts;
}

#if 0
static struct config_setting *
parse_group(struct tokenizer *self)
{
  struct config_setting *settings = NULL;

  while (self->type == TOK_STRING)
    {
      struct lsh_string *s;
      {
	/* Push new object on the list */
	NEW(config_setting, n);
	n->next = settings;
	settings = n;
      }
      if (looking_at(self, "address"))
	settings->type = CONFIG_ADDRESS;
      else if (looking_at(self, "user"))
	settings->type = CONFIG_USER;
      else if (looking_at(self, "hosts"))
	
      else
	return NULL;
      
      next_token(self);
      if (self->type != TOK_STRING)
	return NULL;

      s = parse_word(self);
      if (!s)
	return NULL;
      settings->value = s;
    }
  return settings;
}
#endif

static struct config_group *
parse_groups(struct tokenizer *self)
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
      groups->name = parse_word(self);
      groups->settings = NULL;
      groups->hosts = NULL;
      
      if (!parse_token(self, TOK_BEGIN_GROUP))
	return NULL;

      while (self->type != TOK_END_GROUP)
	{
	  if (looking_at(self, "hosts"))
	    {
	      groups->hosts = parse_hosts(self, groups->hosts);
	      if (!groups->hosts)
		return NULL;
	    }
	  else
	    {
	      groups->settings = parse_setting(self, groups->settings);
	      if (!groups->settings)
		return NULL;
	    }
	}
      if (!parse_token(self, TOK_END_GROUP))
	return NULL;
    }
  return groups;
}

struct config_group *
config_parse_string(const struct lsh_string *s)
{
  struct tokenizer t;
  tokenizer_init(&t, s->length, s->data);
  next_token(&t);

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
