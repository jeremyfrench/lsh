%{
  /* C declarations */
  #include "config_parse.h"

  #include "string_buffer.h"
  #include "xalloc.h"
  #include <ctype.h>
  
#define GABA_DEFINE
#include "config_parse.h.x"
#undef GABA_DEFINE
  
  struct parse_state
  {
    FILE *f;
    struct config_rule *value;
  };

#define YYPARSE_PARAM state
#define STATE ((struct parse_state *) state)

  static void yyerror(const char *s);
  static int
    yylex(YYSTYPE *val, void *state);

%}
/* Declarations */
%pure_parser

%union {
  struct lsh_string *string;
  struct config_pair *pair;
  struct config_rule *rule;
}

%token HOST
%token NET
%token DEFAULT
%token NL

%token <string> ID

%type <pair> pair config
%type <rule> rule rules type

%%
/* Grammar */
start: rules { STATE->value = $1; } ;

rules: /* Empty */ { $$ = NULL; }
	| rules rule { $2->next = $1; $$ = $1 }
	;

rule: type '{' config optsemi '}' { $1->config = $3; $$ = $1; } ;

type: HOST ID { $$ = make_config_rule(RULE_HOST, $2) }
	| NET ID { $$ = make_config_rule(RULE_NET, $2) }
	| DEFAULT { $$ = make_config_rule(RULE_DEFAULT, NULL) }
	;

config: /* Empty */ { $$ = NULL; }
	| config sep pair { $3->next = $1; $$ = $3; }
	;

sep: ';' | NL ;

optsemi: /* Empty */ | ';' ;

pair: ID ID { $$ = make_config_pair($1, $2) };

%%
/* C code */

static struct config_pair *
make_config_pair(struct lsh_string *name, struct lsh_string *value)
{
  NEW(config_pair, self);
  self->next = NULL;
  self->name = name;
  self->value = value;

  return self;
}

static struct config_rule *
make_config_rule(enum config_type type,
		 struct lsh_string *tag)
{
  NEW(config_rule, self);
  self->next = NULL;
  self->type = type;
  self->tag = tag;
  self->config = NULL;

  return self;
}

struct config_rule *
config_parse(FILE *f)
{
  struct parse_state state;
  state->f = f;

  return (yyparse(&state) == 0) ? state.value : NULL;
}

static void
skip_line(FILE *f)
{
  for (;;)
    {
      int c = getc(f);
      if (c == EOF)
	return 0;
      else if (c == '\n')
	return NL;
    }
}

static int
quoted_string(FILE *f, struct lsh_string **val)
{
  struct string_buffer buffer;
  string_buffer_init(&buffer, 20);

  for (;;)
    {
      int c = getc(f);
      switch (c)
	{
	case EOF:
	  werror("Parse error: Unexpected EOF in string.\n");
	  /* What should yylex return in errors? */
	fail:
	  string_buffer_clear(&buffer);
	  return -1;
	case '\n':
	  werror("Parse error: New line in quoted string.\n");
	  goto fail;
	case '\\':
	  switch (c = getc(f))
	    {
	    case '\\':
	      string_buffer_putc(&buffer, '\\');
	      break;
	    case 'n':
	      string_buffer_putc(&buffer, '\n');
	      break;
	    case 't':
	      string_buffer_putc(&buffer, '\t');
	      break;
	    default:
	      werror("Parse error: Unknown escape sequence `\\%c'\n",
		     c);
	      goto fail;
	    }
	  break;
	case '"':
	  *val = string_buffer_final(&buffer, buffer.left);
	  return STRING;
	default:
	  string_buffer_putc(&buffer, c);
	}
    }		     
}

/* Whitespace except '\n'. */
#define WS ' ': case '\t': case '\r': case '\v'

static int
get_word(FILE *f, int c, struct lsh_string **val)
{
  struct string_buffer buffer;
  struct lsh_string *s;
  
  string_buffer_init(&buffer, 20);
  
  string_buffer_putc(&buffer, c);

  for (;;)
    {
      c = getc(f);

      switch (c)
	{
	case '\n': case '{': case '}': case ';': 
	  ungetc(c, f);
	  /* Fall through */
	case WS:	  
	case EOF:
	  /* End of word found. Is it magic? */
	  s = string_buffer_final(&buffer, buffer->left);
	  switch (s->length)
	    {
	    case '3':
	      if (!memcmp(s->data, "net", 3))
		{
		  lsh_string_free(s);
		  return NET;
		}
	      break;
	    case '4':
	      if (!memcmp(s->data, "host", 4))
		{
		  lsh_string_free(s);
		  return HOST;
		}
	      break;
	    case '7':
	      if (!memcmp(s->data, "default", 7))
		{
		  lsh_string_free(s);
		  return DEFAULT;
		}
	      break;
	    }
	  *val = s;
	  return STRING;

	default:
	  string_buffer_putc(&buffer, c);
	}
    }
}

static int
yylex(YYSTYPE *val, void *state)
{
  for (;;)
    {
      int c = getc(STATE->f);
      switch (c)
	{
	case WS:
	  continue;
	case '"':
	  return quoted_string(STATE->f, &val->string);
	case '\n':
	  return NL;
	case '{': case '}': case ';':
	  return c;
	case '#':
	  return skip_line(STATE->f);
	case EOF:
	  return 0;
	default:
	  return word(STATE->f, c, &val->string);
	}
    }
}
