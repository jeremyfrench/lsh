/* sexp_parse.c
 *
 * $Id$ */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998 Ron Rivest, Niels Möller
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "sexp.h"

/* Forward declarations */
struct parse_node;
static void do_mark_parse_node(struct parse_node *n,
			       void (*mark)(struct lsh_object *o));
static void do_free_parse_node(struct parse_node *n);

#if 0
/* The first level decoder. Handles base-64 and hex codes,
 * and passes octets on to the scanner. */

#define SCAN_OCTET 1
#define SCAN_HEX 2
#define SCAN_BASE64 3
#define SCAN_TRANSPORT 4

/* CLASS:
   (class
     (name sexp_decode)
     (super read_handler)
     (vars
       ;; Scanning mode
       (mode . int)
       (next object scanner)))
*/
#endif

/* CLASS:
   (class 
     (name string_handler)
     (vars
       (handler method int "struct lsh_string *s")))
*/

#define HANDLE_STRING(h,s) ((h)->handler((h), (s)))

/* CLASS:
   (class
     (name parse)
     (super scanner)
     (vars
       ; How to parse the rest of the input stream
       (next object scanner)))
*/

/* CLASS:
   (class
     (name parse_s)
     (super parse)
     (vars
       (handler object string_handler)))
*/

/* CLASS:
   (class
     (name parse_sexp)
     (super scanner)
     (vars
       ; What to do with this expression
       (handler object sexp_handler)))
*/

/* CLASS:
   (class
     (name parse_literal_data)
     (super parse_s)
     (vars
       (i . UINT32)
       (data string)))
*/

static int do_parse_literal_data(struct scanner **s, int token)
{
  CAST(parse_literal_data, closure, *s);

  if (token < 0)
    return LSH_FAIL | LSH_SYNTAX;
  
  closure->data->string[closure->i++] = token;

  if (closure->data->length == closure->i)
    {
      struct lsh_string *res = closure->data;
      res->data = NULL;
      *s = closure->next;
      return HANDLE_STRING(closure->super.c, s, res);
    }
  return LSH_OK;
}

static struct scanner *make_parse_literal_data(UINT32 length,
					  struct string_handler *c)
{
  NEW(parse_literal_data, closure);

  closure->super.super->scan = do_parse_literal_data;
  closure->super.c = c;
  closure->i = 0;
  closure->data = lsh_string_alloc(length);

  return &closure->super.super;
}

/* FIXME: Arbitrary limit. */
#define SEXP_MAX_STRING 100000

/* CLASS:
   (class
     (name parse_literal)
     (super parse_s)
     (vars
       (length . UINT32)))
*/

static int do_parse_literal(struct scanner **s, int token)
{
  CAST(parse_literal, closure, *s);
  
  if (token < 0) goto fail;
  
  if (char_classes[token] & CHAR_digit)
    {
      closure->length = closure->length * 10 + (token - '0');
      if (closure->length > SEXP_MAX_STRING)
	goto fail;

      return LSH_OK;
    }
  else if (token == ':')
    {
      *s = make_parse_literal_data(closure->length, closure->super.c);
      return LSH_OK;
    }

 fail:
  *s = NULL;
  return LSH_FAIL | LSH_SYNTAX;
}

static struct scanner *make_parse_literal(UINT32 start,
					  struct string_handler *c)
{
  NEW(parse_literal, closure);

  closure->super.super.scan = do_parse_literal;
  closure->super.c = c;
  closure->length = start;

  return &closure->super.super;
}

/* CLASS:
   (class
     (name return_string)
     (super string_handler)
     (vars
       (c object sexp_handler)))
*/

static int do_return_string(struct string_handler *h,
			    struct lsh_string *data)
{
  CAST(return_string, closure, h);
  return LSH_PARSED_OBJECT |
    HANDLE_SEXP(closure->c, make_sexp_string(NULL, data));
}

static struct string_handler *make_return_string(struct sexp_handler *c)
{
  NEW(return_string, closure);

  closure->super.handler = do_return_string;
  closure->c = c;

  return &closure->super;
}

#define MAKE_PARSE(name)						\
static int do_parse##name(struct scanner **s, int token);		\
									\
static struct scanner *make_parse_##name(struct sexp_handler *h,	\
					 struct scanner *next)		\
{									\
  NEW(parse_c, closure);						\
									\
  closure->super.scan = do_parse##name;					\
  closure->handler = h;							\
  closure->next = next;							\
									\
  return &closure->super;						\
}									\
									\
static int do_parse##name(struct scanner **s, int token)
     
/* CLASS:
   (class
     (name parse_skip)
     (super parse_c)
     (vars
       (expect . int)
       (value object sexp)))
*/

static int do_parse_skip(struct scanner **s, int token)
{
  CAST(parse_skip, closure, *s);

  /* FIXME: If the token doesn't match, perhaps we should install NULL
   * instead? */
  
  *s = closure->super.next;

  if (token == closure->expect)
    return (closure->super.handler
	    ? HANDLE_SEXP(closure->super.handler, closure->value)
	    : LSH_OK);

  return LSH_FAIL | LSH_SYNTAX;  
}

static struct scanner *make_parse_skip(int token,
				       struct sexp *value,
				       struct sexp_handler *handler,
				       struct scanner *next)
{
  NEW(parse_skip, closure);

  closure->super.super.scan = do_parse_skip;
  closure->super.handler = handler;
  closure->super.next = next;
  closure->expect = token;
  closure->value = value;

  return &closure->super.super;
}

MAKE_PARSE(simple_string)
{
  CAST(parse_c, closure, *s);

  switch(token)
    {
    case TOKEN_EOS:
      fatal("Internal error!\n");      

    case '0':
      /* This should be a single zero digit, as there mustn't be unneccessary
       * leading zeros. */
      *s = make_parse_skip(':', sexp_z(""), closure->handler, closure->next);
      return LSH_OK:

    case '1': case '2': case '3':
    case '4': case '5': case '6':
    case '7': case '8': case '9':
      *s = make_parse_literal(token - '0',
			      make_return_string(closure->c), closure->next);
      return LSH_OK;

    default:
      /* Syntax error */
      return LSH_FAIL | LSH_SYNTAX;
    }
}

MAKE_PARSE(advanced_string)
{
  CAST(parse_c, closure, *s);

  switch(token)
    {
    case TOKEN_EOS:
      fatal("Internal error!\n");      

    case '0':
      /* This should be a single zero digit, as there mustn't be unneccessary
       * leading zeros. */
      *s = make_parse_skip(':', closure->next, sexp_z(""), closure->c);
      return LSH_OK:

    case '1': case '2': case '3':
    case '4': case '5': case '6':
    case '7': case '8': case '9':
      *s = make_parse_literal(token - '0',
				     make_return_string(closure->c));
      return LSH_OK;
    case '"':
      fatal("Quoted strings not implemented!\n");
    case '|':
      fatal("base-64 strings not implemented!\n");
    case '#':
      fatal("Hex strings not implemented!\n");
      
    default:
      /* Syntax error */
      return LSH_FAIL | LSH_SYNTAX;
    }
}

/* CLASS:
   (class
     (name return_string_display)
     (super string_handler)
     (vars
       (display string)
       (c object sexp_handler)))
*/

static int do_return_string_display(struct string_handler *h,
				    struct scanner **s,
				    struct lsh_string *data)
{
  CAST(return_string_display, closure, h);

  struct lsh_string *display = closure->display;

  closure->display = NULL;
  *s = NULL;

  return HANDLE_SEXP(closure->c, make_sexp_string(display, data));
}

static struct string_handler *
make_return_string_display(struct lsh_string *display,
			   struct sexp_handler *c)
{
  NEW(return_string_display, closure);

  closure->super.handler = do_return_string_display;
  closure->display = display;
  closure->c = c;

  return &closure->super;
}

/* CLASS:
   (class
     (name end_display)
     (super string_handler)
     (vars
       (c object sexp_handler)))
*/

static int do_end_display(struct string_handler *h, struct scanner **s,
			  struct lsh_string *data)
{
  CAST(end_display, closure, h);

  *s = make_parse_skip
    (']',
     make_parse_literal(0,
			       make_return_string_display(data, closure->c)),
     NULL, NULL);

  return LSH_OK;
}

static struct make_end_display(struct sexp_handler *c)
{
  NEW(end_display, closure);

  closure->super.handler = do_end_display;
  closure->c = c;

  return &closure->super;
}

/* Parse and construct a list (with hooks for both advanced and
 * canonical formats) */

/* CLASS:
   (class
     (name parse_list)
     (super parse_c)
     (vars ))
            ;; Construct a parser
       (element_parser pointer (function "struct scanner *"
                                         "struct sexp_handler *c"))
*/

/* Inter-element parser. Used to recognize the end of list ')' character,
 * and could also be used to skip optional whitespace. */

/* CLASS:
   (class
     (name parse_inter_list)
     (super scanner)
     (vars
       (list object parse_list)))
*/

struct parse_node
{
  struct parse_node *next;
  struct sexp *item;
};

static void do_mark_parse_node(struct parse_node *n,
			       void (*mark)(struct lsh_object *o))
{
  while(n)
    {
      mark(&n->item.super);
      n = n->next;
    }
}

static void do_free_parse_node(struct parse_node *n)
{
  while(n)
    {
      struct parse_node *old = n;
      n = n->next;
      lsh_space_free(old);
    }
}

/* CLASS:
   (class
     (name handle_element)
     (super sexp_handler)
     (vars
       ; Scanner to restore at the end of each element
       ;; (location . "struct scanner **")
       ;; (restore object scanner)
       ; Number of elements collected so far
       (count . unsigned)
       (head special "struct parse_node *"
             do_mark_parse_node do_free_parse_node)))
*/

static int do_handle_element(struct sexp_handler *h,
			     struct sexp *e)
{
  CAST(handle_element, closure, h);
  NEW_SPACE(parse_node, n);

  n->item = e;
  n->next = closure->head;

  h->head = n;
  h->count++;

  /* FIXME: It would be nice if we could simply restore an older
   * scanner here, but we can perhaps not do that becase the location
   * pointer is not gc-friendly.
   *
   * The problem is that we must be sure that the object (or stack
   * frame) location points into is still alive. I think that will
   * always be the case here, but I'm not sure.
   *
   * So instead, we return a special status code. */

  return LSH_PARSED_OBJECT;
}

static struct handle_element *make_handle_element(void)
{
  NEW(handle_element, closure);

  closure->count = 0;
  closure->head = NULL;

  closure->super.handler = do_handle_element;

  return closure;
}

static struct sexp *build_parsed_vector(struct handle_element *h)
{
  struct object_list *l = alloc_object_list(h->count);

  unsigned i;
  struct parse_node *n;
  
  for (n = h->head, i = h->count; n; n = n->next)
    {
      assert(i);
      LIST(l)[--i] = &n->item->super;
    }
  assert(!i);
  
  return sexp_v(l);
}

/* CLASS:
   (class
     (name parse_list)
     (super parse_c)
     (vars
       (elements object handle_element)
       ; Allow space between elements?
       (advanced . int)
       ; Used to parse each element
       (start object scanner)
       ; Current scanner
       (state object scanner))) */

static int do_parse_list(struct scanner **s, int token)
{
  CAST(parse_list, closure, *s);
  int res;
  
  if (token < 0)
    return LSH_FAIL | LSH_SYNTAX;

  if (!closure->state)
    {
      if (token == ')')
	{
	  *s = NULL;
	  return LSH_PARSED_OBJECT
	    | HANDLE_SEXP(closure->super.handler,
			  build_parsed_vector(closure->elements));
	}
      
      if (closure->advanced && (char_classes[token] & CHAR_space))
	return LSH_OK;

      closure->state = closure->start;
    }

  res = SCAN(closure->state, token);

  if (res == LSH_PARSED_OBJECT)
    /* Restart on next token */
    closure->state = NULL;
  
  return res & ~LSH_PARSED_OBJECT;
}

static struct scanner *
make_parse_list(int advanced,
		struct scanner (*make)(struct sexp_handler *c),
		struct sexp_handler *c)
{
  NEW(parse_list, closure);

  closure->elements = make_handle_element();
  closure->start = make(&closure->elements.super);
  closure->state = NULL;

  closure->super.c = c;
  closure->super.super.scan = do_parse_list;

  return &closure->super.super;
}
					  
/* Parser for the canonical format. */
MAKE_PARSE(canonical_sexp)
{
  CAST(parse_c, closure, *s);
  
  switch (token)
    {
    case TOKEN_EOS:
      fatal("Internal error!\n");      
    case '[':
      *s = make_parse_literal(0, make_end_display(closure->c));
      return LSH_OK:
    case '(':
      *s = make_parse_list(0, make_parse_canonical_sexp, closure->c);
      return LSH_OK;
    default:
      /* Should be a string */
      *s = make_parse_literal(0, make_return_string(closure->c));
      return SCAN(*s, token);
    }
}

/* CLASS:
   (class
     (name parse_base64)
     (super scanner)
     (vars
       (next object scanner);
       (end_marker . UINT8)))
*/

static do_parse_base64(struct scanner **s, int token)
{
  CAST(parse_base64, closure, *s);

  if (token < 0)
       return LSH_FAIL;
  
  if (token == closure->end_marker)
    {
      int res = SCAN(closure->next, TOKEN_EOF);
      if (
/* Parser for the canonical or transport format. */
MAKE_PARSE(transport_sexp)
{
  CAST(parse_c, closure, *s);
  
  switch (token)
    {
    case TOKEN_EOS:
      fatal("Internal error!\n");      
    case '[':
      *s = make_parse_literal(0, make_end_display(closure->c));
      return LSH_OK:
    case '(':
      *s = make_parse_list(0, make_parse_canonical_sexp, closure->c);
      return LSH_OK;
    case '{':
      *s = make_parse_base64('}', make_parse_canonical_sexp,
			     make_parse_skip(TOKEN_EOS), closure->c);
    default:
      /* Should be a string */
      *s = make_parse_literal(0, make_return_string(closure->c));
      return SCAN(*s, token);
    }
}

/* Parser for any format. */
MAKE_PARSE(advanced_sexp)
{
  CAST(parse_c, closure, *s);
  
  switch (token)
    {
    case TOKEN_EOS:
      fatal("Internal error!\n");      
    case '[':
      *s = make_parse_advanced_string(0, make_end_display(closure->c));
      return LSH_OK:
    case '(':
      *s = make_parse_list(1, make_parse_advanced_sexp, closure->c);
      return LSH_OK;
    case '{':
      *s = make_parse_base64('}', make_parse_advanced_sexp, closure->c);
    default:
      /* Should be a string */
      *s = make_parse_advanced_string(0, make_return_string(closure->c));
      return SCAN(*s, token);
    }
}

