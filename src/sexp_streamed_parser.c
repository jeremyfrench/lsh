/* sexp_streamed_parser.c
 *
 * $Id$ */

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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/* NOTE: This parser is designed to recieve a character at a time,
 * without ever having to block while reading the rest of an
 * expression. This is most likely way overkill, as we typically have
 * read a complete S-expression into a string before invoking the
 * parser. */

#include "sexp_parser.h"

#include "read_scan.h"
#include "sexp.h"
#include "werror.h"
#include "xalloc.h"

#include "sexp_table.h"

#include <assert.h>

/* Forward declarations */
struct parse_node;
static void do_mark_parse_node(struct parse_node *n,
				 void (*mark)(struct lsh_object *o));
static void do_free_parse_node(struct parse_node *n);

#include "sexp_parser.c.x"

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
     (name parse_string)
     (super parse)
     (vars
	 (handler object string_handler)))
*/

/* CLASS:
   (class
     (name parse_sexp)
     (super parse)
     (vars
	 ; What to do with this expression
	 (handler object sexp_handler)))
*/

/* CLASS:
   (class
     (name parse_literal_data)
     (super parse_string)
     (vars
	 (i . UINT32)
	 (data string)))
*/

static int do_parse_literal_data(struct scanner **s, int token)
{
  CAST(parse_literal_data, closure, *s);

  if (token < 0)
    return LSH_FAIL | LSH_SYNTAX;
  
  closure->data->data[closure->i++] = token;

  if (closure->data->length == closure->i)
    {
	struct lsh_string *res = closure->data;
	closure->data = NULL;
	*s = closure->super.super.next;
	return HANDLE_STRING(closure->super.handler, res);
    }
  return LSH_OK;
}

static struct scanner *
make_parse_literal_data(UINT32 length,
			  struct string_handler *handler,
			  struct scanner *next)
{
  NEW(parse_literal_data, closure);

  closure->super.super.super.scan = do_parse_literal_data;
  closure->super.super.next = next;
  closure->super.handler = handler;
  closure->i = 0;
  closure->data = lsh_string_alloc(length);

  return &closure->super.super.super;
}

/* FIXME: Arbitrary limit. */
#define SEXP_MAX_STRING 100000

/* CLASS:
   (class
     (name parse_literal)
     (super parse_string)
     (vars
	 (got_length . int)
	 (length . UINT32)))
*/

static int do_parse_literal(struct scanner **s, int token)
{
  CAST(parse_literal, closure, *s);
  
  if (token < 0) goto fail;

  if (sexp_char_classes[token] & CHAR_digit)
    {
	closure->length = closure->length * 10 + (token - '0');
	if (closure->length > SEXP_MAX_STRING)
	  goto fail;

	closure->got_length = 1;
	return LSH_OK;
    }
  else if (closure->got_length && (token == ':'))
    {
	*s = make_parse_literal_data(closure->length,
				     closure->super.handler,
				     closure->super.super.next);
	return LSH_OK;
    }

 fail:
  *s = NULL;
  return LSH_FAIL | LSH_SYNTAX;
}

static struct scanner *make_parse_literal(struct string_handler *handler,
					    struct scanner *next)
{
  NEW(parse_literal, closure);

  closure->super.super.super.scan = do_parse_literal;
  closure->super.super.next = next;
  closure->super.handler = handler;
  closure->got_length = 0;
  closure->length = 0;

  return &closure->super.super.super;
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
  return HANDLE_SEXP(closure->c, make_sexp_string(NULL, data));
}

static struct string_handler *make_return_string(struct sexp_handler *c)
{
  NEW(return_string, closure);

  closure->super.handler = do_return_string;
  closure->c = c;

  return &closure->super;
}

#define MAKE_PARSE(name)						\
static int do_parse_##name(struct scanner **s, int token);		\
									\
static struct scanner *make_parse_##name(struct sexp_handler *h,	\
					   struct scanner *next)	\
{									\
  NEW(parse_sexp, closure);						\
									\
  closure->super.super.scan = do_parse_##name;				\
  closure->super.next = next;						\
  closure->handler = h;							\
									\
  return &closure->super.super;						\
}									\
									\
static int do_parse_##name(struct scanner **s, int token)
     
/* CLASS:
   (class
     (name parse_skip)
     (super parse_sexp)
     (vars
	 (expect . int)
	 (value object sexp)))
*/

static int do_parse_skip(struct scanner **s, int token)
{
  CAST(parse_skip, closure, *s);

  /* FIXME: If the token doesn't match, perhaps we should install NULL
   * instead? */
  
  if (token == closure->expect)
    {
	*s = closure->super.super.next;
	return (closure->super.handler
		? HANDLE_SEXP(closure->super.handler, closure->value)
		: LSH_OK);
    }

  /* FIXME: More readable error message */
  werror("Expected token %d, got %d\n", closure->expect, token);
  
  *s = NULL;
  return LSH_FAIL | LSH_SYNTAX;  
}

static struct scanner *make_parse_skip(int token,
					 struct sexp *value,
					 struct sexp_handler *handler,
					 struct scanner *next)
{
  NEW(parse_skip, closure);

  closure->super.super.super.scan = do_parse_skip;
  closure->super.super.next = next;
  closure->super.handler = handler;
  closure->expect = token;
  closure->value = value;

  return &closure->super.super.super;
}

#if 0
MAKE_PARSE(simple_string)
{
  CAST(parse_sexp, closure, *s);

  switch(token)
    {
    case TOKEN_EOS:
	fatal("Internal error!\n");      

    case '0':
	/* This should be a single zero digit, as there mustn't be unneccessary
	 * leading zeros. */
	*s = make_parse_skip(':', sexp_z(""),
			     closure->handler, closure->super.next);
	return LSH_OK:

    case '1': case '2': case '3':
    case '4': case '5': case '6':
    case '7': case '8': case '9':
	*s = make_parse_literal(token - '0',
				make_return_string(closure->handler),
				closure->super.next);
	return LSH_OK;

    default:
	/* Syntax error */
	return LSH_FAIL | LSH_SYNTAX;
    }
}
#endif

#if 0
static int do_parse_advanced_string(struct scanner **s,
				      int token)
{
  CAST(parse_string, closure, *s);

  if (token < 0)
    return LSH_FAIL | LSH_SYNTEX;

  if (sexp_char_classes[token] & CHAR_digit)
    {
	*s = make_parse_length;
    }
  switch(token)
    {
    case '0':
	/* This should be a single zero digit, as there mustn't be unneccessary
	 * leading zeros. */
	*s = make_parse_skip(':', sexp_z(""),
			     closure->handler, closure->super.next);
	return LSH_OK:

    case '1': case '2': case '3':
    case '4': case '5': case '6':
    case '7': case '8': case '9':
	/* FIXME: Not only literals can have a length prefix */
	*s = make_parse_literal(make_return_string(closure->handler),
				closure->super.next);
	return SCAN(*s, token);
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

#endif

static struct scanner *make_parse_advanced_string(struct string_handler *h,
						    struct scanner *next)
{
  NEW(parse_string, closure);

  closure->handler = h;
  closure->super.next = next;

  return &closure->super.super;
}


#if 0
/* xxCLASS:
   (class
     (name return_string_display)
     (super string_handler)
     (vars
	 (display string)
	 (c object sexp_handler)))
*/

static int do_return_string_display(struct string_handler *h,
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
#endif

/* CLASS:
   (class
     (name handle_display)
     (super string_handler)
     (vars
	 (display string)
	 (c object sexp_handler)))
*/

static int do_handle_display(struct string_handler *h,
			       struct lsh_string *data)
{
  CAST(handle_display, closure, h);

  if (!closure->display)
    {
	closure->display = data;
	return LSH_OK;
    }
  else
    {
	struct lsh_string *display = closure->display;
	closure->display = NULL;

	return HANDLE_SEXP(closure->c,
			   make_sexp_string(display, data));
    }
}

static struct string_handler *make_handle_display(struct sexp_handler *c)
{
  NEW(handle_display, closure);

  closure->super.handler = do_handle_display;
  closure->display = NULL;
  closure->c = c;

  return &closure->super;
}

static struct scanner *
make_parse_display(struct scanner * (*make)(struct string_handler *h,
					      struct scanner *next),
		     struct sexp_handler *c,
		     struct scanner *next)
{
  struct string_handler *h = make_handle_display(c);

  return make(h,
		make_parse_skip(']', NULL, NULL,
				make(h, next)));
}

#if 0
/* Parse and construct a list (with hooks for both advanced and
 * canonical formats) */

/* xxCLASS:
   (class
     (name parse_list)
     (super parse_sexp)
     (vars 
	 ;; Construct a parser
	 (element_parser pointer (function "struct scanner *"
					   "struct sexp_handler *c"))))
*/

/* Inter-element parser. Used to recognize the end of list ')' character,
 * and could also be used to skip optional whitespace. */

/* xxCLASS:
   (class
     (name parse_inter_list)
     (super scanner)
     (vars
	 (list object parse_list)))
*/
#endif

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
	mark(&n->item->super);
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
	 (tail special "struct parse_node *"
	       do_mark_parse_node do_free_parse_node)))
*/

static int do_handle_element(struct sexp_handler *h,
			       struct sexp *e)
{
  CAST(handle_element, closure, h);
  struct parse_node *n;
  
  NEW_SPACE(n);

  n->item = e;
  n->next = closure->tail;

  closure->tail = n;
  closure->count++;

  return LSH_OK;
  
  #if 0
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
  #endif
}

static struct handle_element *make_handle_element(void)
{
  NEW(handle_element, closure);

  closure->count = 0;
  closure->tail = NULL;

  closure->super.handler = do_handle_element;

  return closure;
}

static struct sexp *build_parsed_vector(struct handle_element *h)
{
  struct object_list *l = alloc_object_list(h->count);

  unsigned i;
  struct parse_node *n;
  
  for (n = h->tail, i = h->count; n; n = n->next)
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
     (super parse_sexp)
     (vars
	 (elements object handle_element)
	 ; Allow space between elements?
	 (advanced . int)
	 ; Used to parse each element
	 (start object scanner)))

	 ; Current scanner
	 (state object scanner)))
*/

static int do_parse_list(struct scanner **s, int token)
{
  CAST(parse_list, closure, *s);
  
  if (token < 0)
    return LSH_FAIL | LSH_SYNTAX;

  if (token == ')')
    {
	*s = closure->super.super.next;
	return HANDLE_SEXP(closure->super.handler,
			   build_parsed_vector(closure->elements));
    }
	
  if (closure->advanced && (sexp_char_classes[token] & CHAR_space))
    return LSH_OK;

  *s = closure->start;
  return SCAN(*s, token);
}

static struct scanner *
make_parse_list(int advanced,
		  struct scanner * (*make)(struct sexp_handler *c,
					   struct scanner *next),
		  struct sexp_handler *handler,
		  struct scanner *next)
{
  NEW(parse_list, closure);

  closure->super.super.super.scan = do_parse_list;
  closure->super.super.next = next;
  closure->super.handler = handler;

  closure->advanced = advanced;
  closure->elements = make_handle_element();
  closure->start = make(&closure->elements->super,
			  &closure->super.super.super);

  return &closure->super.super.super;
}
					    
/* Parser for the canonical format. */
MAKE_PARSE(canonical_sexp)
{
  CAST(parse_sexp, closure, *s);
  
  switch (token)
    {
    case TOKEN_EOS:
	fatal("Internal error!\n");      
    case '[':
	*s = make_parse_display(make_parse_literal, closure->handler,
				closure->super.next);
	return LSH_OK;
    case '(':
	*s = make_parse_list(0, make_parse_canonical_sexp, closure->handler,
				closure->super.next);
	return LSH_OK;
    default:
	/* Should be a string */
	*s = make_parse_literal(make_return_string(closure->handler),
				closure->super.next);
	return SCAN(*s, token);
    }
}

/* CLASS:
   (class
     (name decode_base64)
     (super scanner)
     (vars
	 (next object scanner);
	 (end_marker . UINT8)))
*/

static int do_decode_base64(struct scanner **s, int token)
{
  CAST(decode_base64, closure, *s);

  fatal("do_decode_base64: Not implemented!\n");

#if 0
  if (token < 0)
	 return LSH_FAIL;
  
  if (token == closure->end_marker)
    {
	int res = SCAN(closure->next, TOKEN_EOF);
	if ()}
#endif
}

static struct scanner *make_decode_base64(int end,
					    struct scanner *s,
					    struct scanner *next)
{
  fatal("Not implemented!\n");
}

static struct scanner *
make_parse_transport(struct scanner * (*make)(struct sexp_handler *c,
						struct scanner *next),
		       struct sexp_handler *handler,
		       struct scanner *next)
{
  return
    make_decode_base64('{',
			 make(handler,
			      make_parse_skip(TOKEN_EOS,
					      NULL, NULL, NULL)),
			 next);
}

/* Parser for the canonical or transport format. */
MAKE_PARSE(transport_sexp)
{
  CAST(parse_sexp, closure, *s);
  
  switch (token)
    {
    case TOKEN_EOS:
	fatal("Internal error!\n");      
    case '[':
	*s = make_parse_display(make_parse_literal, closure->handler,
				closure->super.next);
	return LSH_OK;
    case '(':
	*s = make_parse_list(0, make_parse_canonical_sexp, closure->handler,
				closure->super.next);
	return LSH_OK;
    case '{':
	*s = make_parse_transport(make_parse_canonical_sexp,
				  closure->handler, closure->super.next);
	return LSH_OK;
    default:
	/* Should be a string */
	*s = make_parse_literal(make_return_string(closure->handler),
				closure->super.next);
	return SCAN(*s, token);
    }
}

/* Parser for any format. */
MAKE_PARSE(advanced_sexp)
{
  CAST(parse_sexp, closure, *s);
  
  switch (token)
    {
    case TOKEN_EOS:
	fatal("Internal error!\n");      
    case '[':
	*s = make_parse_display(make_parse_advanced_string, closure->handler,
				closure->super.next);
	return LSH_OK;
    case '(':
	*s = make_parse_list(1, make_parse_advanced_sexp, closure->handler,
			     closure->super.next);
	return LSH_OK;
    case '{':
	*s = make_parse_transport(make_parse_canonical_sexp,
				  closure->handler, closure->super.next);
	return LSH_OK;
    default:
	/* Should be a string */
	*s = make_parse_advanced_string(make_return_string(closure->handler),
					closure->super.next);
	return SCAN(*s, token);
    }
}

 
