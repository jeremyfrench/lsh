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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#if 0
#include "sexp_parser.h" 
#endif

#include "abstract_io.h"
#include "command.h"
#include "digits.h"
#include "format.h"
#include "sexp.h"
#include "werror.h"
#include "xalloc.h"

/* Automatically generated files. */
#include "sexp_table.h"

#include <assert.h>

#include "sexp_streamed_parser.c.x"

#define SEXP_ERROR(e, msg) \
EXCEPTION_RAISE(e, make_simple_exception(EXC_SEXP_SYNTAX, msg))

#define SEXP_EOF(e, msg) \
EXCEPTION_RAISE(e, make_simple_exception(EXC_SEXP_EOF, msg))

/* GABA:
   (class
     (name parser)
     (super read_handler)
     (vars
       ;;; Where to return values
       ;; (c object command_continuation)
       ; How to handle errors
       (e object exception_handler)
       ; What to do with the rest of the input stream
       (next object read_handler)))
*/

/* GABA:
   (class
     (name parse_value)
     (super parser)
     (vars
       (c object command_continuation)))
*/

/* GABA:
   (class
     (name string_handler)
     (vars
       (handler method void "struct lsh_string *s")))
*/

#define HANDLE_STRING(h ,s) ((h)->handler((h), (s)))

/* GABA:
   (class
     (name parse_string)
     (super parser)
     (vars
       (handler object string_handler)))
*/

#define MAKE_PARSE_VALUE(name)				\
static UINT32						\
do_parse_##name(struct read_handler **s,		\
                UINT32 available, UINT8 *data);		\
							\
static struct read_handler *				\
make_parse_##name(struct command_continuation *c,	\
                  struct exception_handler *e,		\
		  struct read_handler *next)		\
{							\
  NEW(parse_value, self);				\
							\
  self->super.super.handler = do_parse_##name;		\
  self->super.e = e;					\
  self->super.next = next;				\
  self->c = c;						\
							\
  return &self->super.super;				\
}							\
							\
static UINT32						\
do_parse_##name(struct read_handler **s,		\
                UINT32 available, UINT8 *data)

#define MAKE_PARSE_STRING(name)				\
static UINT32						\
do_parse_##name(struct read_handler **s,		\
                UINT32 available, UINT8 *data);		\
							\
static struct read_handler *				\
make_parse_##name(struct string_handler *handler,	\
                  struct exception_handler *e,		\
		  struct read_handler *next)		\
{							\
  NEW(parse_string, self);				\
							\
  self->super.super.handler = do_parse_##name;		\
  self->super.e = e;					\
  self->super.next = next;				\
  self->handler = handler;				\
							\
  return &self->super.super;				\
}							\
							\
static UINT32						\
do_parse_##name(struct read_handler **s,		\
                UINT32 available, UINT8 *data)


/* GABA:
   (class
     (name parse_literal_data)
     (super parse_string)
     (vars
	 (i . UINT32)
	 (data string)))
*/

static UINT32
do_parse_literal_data(struct read_handler **s,
		      UINT32 available,
		      UINT8 *data)
{
  CAST(parse_literal_data, self, *s);
  UINT32 left;
  
  if (!available)
    {
      SEXP_ERROR(self->super.super.e, "Unexpected EOF");
      *s = NULL;
      return 0;
    }

  left = self->data->length - self->i;

  if (available < left)
    {
      memcpy(self->data->data + self->i, data, available);
      self->i += available;
      return available;
    }
  else
    {
      struct lsh_string *res;

      memcpy(self->data->data + self->i, data, left);

      res = self->data;

      /* For gc */
      self->data = NULL;

      *s = self->super.super.next;
      HANDLE_STRING(self->super.handler, res);

      return left;
    }
}

static struct read_handler *
make_parse_literal_data(UINT32 length,
			struct string_handler *handler,
			struct exception_handler *e,
			struct read_handler *next)
{
  NEW(parse_literal_data, self);

  self->super.super.super.handler = do_parse_literal_data;
  self->super.super.next = next;
  self->super.super.e = e;
  self->super.handler = handler;
  self->i = 0;
  self->data = lsh_string_alloc(length);

  return &self->super.super.super;
}

/* FIXME: Arbitrary limit. */
#define SEXP_MAX_STRING 100000

/* GABA:
   (class
     (name parse_length)
     (super parse_string)
     (vars
	 (length . UINT32)))
*/

static UINT32
do_parse_length(struct read_handler **s,
		UINT32 available,
		UINT8 *data)
{
  CAST(parse_length, self, *s);
  UINT32 i;

  for (i = 0;
       (i < available) && (sexp_char_classes[data[i]] & CHAR_digit);
       i++)
    {
      self->length = self->length * 10 + (data[i] - '0');
      if (self->length > SEXP_MAX_STRING)
	  {
	    SEXP_ERROR(self->super.super.e, "Literal too large.");
	    *s = NULL;
	    return i;
	  }
    }
  if (i < available)
    {
      if (data[i] == ':')
	{
	  *s = make_parse_literal_data(self->length,
				       self->super.handler,
				       self->super.super.e,
				       self->super.super.next);
	  return i + 1;
	}
      else
	{
	  SEXP_ERROR(self->super.super.e, "Invalid literal");
	  *s = NULL;
	  return i;
	}
    }
  return i;
}

static UINT32
do_parse_empty_literal(struct read_handler **s,
		       UINT32 available,
		       UINT8 *data)
{
  CAST(parse_string, self, *s);

  if (!available)
    {
      SEXP_ERROR(self->super.e, "Unexpected EOF");
      *s = NULL;
      return 0;
    }

  if (data[0] == ':')
    {
      HANDLE_STRING(self->handler, ssh_format(""));
      *s = self->super.next;
      return 1;
    }
  else
    {
      SEXP_ERROR(self->super.e, "Invalid empty literal");
      *s = NULL;
      return 0;
    }
}
      
static struct read_handler *
make_parse_length(UINT8 first,
		  struct string_handler *handler,
		  struct exception_handler *e,
		  struct read_handler *next)
{
  switch (first)
    {
    case '1': case '2': case '3':
    case '4': case '5': case '6':
    case '7': case '8': case '9':
      {
	NEW(parse_length, self);
	
	self->super.super.super.handler = do_parse_length;
	self->super.super.e = e;
	self->super.super.next = next;
	self->super.handler = handler;
	self->length = first - '0';
      
	return &self->super.super.super;
      }
    case '0':
      {
	NEW(parse_string, self);
	self->super.super.handler = do_parse_empty_literal;
	self->super.e = e;
	self->super.next = next;
	self->handler = handler;
	
	return &self->super.super;
      }
    default:
      fatal("Internal error");
    }
}

MAKE_PARSE_STRING(literal)
{
  CAST(parse_string, self, *s);

  if (!available)
    {
      SEXP_ERROR(self->super.e, "Unexpected EOF");
      *s = NULL;
      return 0;
    }

  switch (data[0])
    {
    case '0': case '1': case '2': case '3': case '4':
    case '5': case '6': case '7': case '8': case '9':
      *s = make_parse_length(data[0], self->handler, self->super.e, self->super.next);
      return 1;

    default:
      SEXP_ERROR(self->super.e, "Invalid literal");
      *s = NULL;
      return 0;
    }
}

/* GABA:
   (class
     (name return_string)
     (super string_handler)
     (vars
	 (c object command_continuation)))
*/

static void
do_return_string(struct string_handler *s,
		 struct lsh_string *data)
{
  CAST(return_string, self, s);
  COMMAND_RETURN(self->c, make_sexp_string(NULL, data));
}

static struct string_handler *
make_return_string(struct command_continuation *c)
{
  NEW(return_string, self);

  self->super.handler = do_return_string;
  self->c = c;

  return &self->super;
}

/* GABA:
   (class
     (name parse_skip)
     (super parser)
     (vars
       (expect . UINT8)))
       ;; (value object sexp)))
*/

static UINT32
do_parse_skip(struct read_handler **s,
	      UINT32 available,
	      UINT8 *data)
{
  CAST(parse_skip, self, *s);

  if (!available)
    {
      SEXP_ERROR(self->super.e, "Unexpected EOF");
      *s = NULL;
      return 0;
    }
  
  if (data[0] == self->expect)
    {
	*s = self->super.next;
	return 1;
    }

  /* FIXME: More readable error message */
  werror("Expected token %i, got %i\n", self->expect, data[0]);
  SEXP_ERROR(self->super.e, "Unexpected character");
  *s = NULL;
  return 1;
}

static struct read_handler *
make_parse_skip(UINT8 token,
		struct exception_handler *e,
		struct read_handler *next)
{
  NEW(parse_skip, self);

  self->super.super.handler = do_parse_skip;
  self->super.next = next;
  self->super.e = e;
  self->expect = token;

  return &self->super.super;
}

/* GABA:
   (class
     (name handle_display)
     (super string_handler)
     (vars
	 (display string)
	 (c object command_continuation)))
*/

static void
do_handle_display(struct string_handler *s,
		  struct lsh_string *data)
{
  CAST(handle_display, self, s);

  if (!self->display)
    {
      self->display = data;
    }
  else
    {
      struct lsh_string *display = self->display;
      self->display = NULL;
      
      COMMAND_RETURN(self->c,
		     make_sexp_string(display, data));
    }
}

static struct string_handler *make_handle_display(struct command_continuation *c)
{
  NEW(handle_display, self);

  self->super.handler = do_handle_display;
  self->display = NULL;
  self->c = c;

  return &self->super;
}

static struct read_handler *
make_parse_display(struct read_handler * (*make)(struct string_handler *h,
						 struct exception_handler *e,
						 struct read_handler *next),
		   struct command_continuation *c,
		   struct exception_handler *e,
		   struct read_handler *next)
{
  struct string_handler *h = make_handle_display(c);

  return make(h, e,
	      make_parse_skip(']', e,
			      make(h, e, next)));
}


/* GABA:
   (class
     (name handle_element)
     (super command_continuation)
     (vars
	 ; Scanner to restore at the end of each element
	 ;; (location . "struct scanner **")
	 ;; (restore object scanner)
	 ; Number of elements collected so far
	 (count . unsigned)
	 (l struct object_queue)))

	 ;; (tail special "struct parse_node *"
	 ;;      do_mark_parse_node do_free_parse_node)))
*/

static void
do_handle_element(struct command_continuation *c,
		  struct lsh_object *o)
{
  CAST(handle_element, self, c);
  CHECK_SUBTYPE(sexp, o);

  self->count++;
  object_queue_add_tail(&self->l, o);
}

static struct handle_element *
make_handle_element(void)
{
  NEW(handle_element, self);

  self->count = 0;
  object_queue_init(&self->l);

  self->super.c = do_handle_element;

  return self;
}

static struct sexp *build_parsed_vector(struct handle_element *self)
{
  struct object_list *l = alloc_object_list(self->count);

  unsigned i;

  for (i = 0; i < self->count; i++)
    LIST(l)[i] = object_queue_remove_head(&self->l);
  
  assert(object_queue_is_empty(&self->l));
  
  return sexp_v(l);
}

/* GABA:
   (class
     (name parse_list)
     (super parse_value)
     (vars
	 (elements object handle_element)
	 ; Allow space between elements?
	 (advanced . int)
	 ; Used to parse each element
	 (start object read_handler)))

	 ; Current scanner
	 (state object read_handler)))
*/

static UINT32
do_parse_list(struct read_handler **s,
	      UINT32 available,
	      UINT8 *data)
{
  CAST(parse_list, self, *s);
  UINT32 i = 0;
  
  if (!available)
    {
      SEXP_ERROR(self->super.super.e, "Unexpected EOF");
      *s = NULL;
      return 0;
    }

  if (self->advanced)
    {
      while ( (i < available) && (sexp_char_classes[data[i]] & CHAR_space) )
	i++;

      if (i == available)
	return i;
    }
  
  if (data[i] == ')')
    {
      *s = self->super.super.next;
      COMMAND_RETURN(self->super.c,
		     build_parsed_vector(self->elements));
      return i + 1;
    }
	
  *s = self->start;
  return i;
  /* return i + READ_HANDLER(*s, available - i, data + i); */
}

static struct read_handler *
make_parse_list(int advanced,
		struct read_handler * (*make)(struct command_continuation *c,
					      struct exception_handler *e,
					      struct read_handler *next),
		struct command_continuation *c,
		struct exception_handler *e,
		struct read_handler *next)
{
  NEW(parse_list, self);

  self->super.super.super.handler = do_parse_list;
  self->super.super.e = e;
  self->super.super.next = next;
  self->super.c = c;

  self->advanced = advanced;
  self->elements = make_handle_element();
  self->start = make(&self->elements->super,
		     e,
		     &self->super.super.super);

  return &self->super.super.super;
}


MAKE_PARSE_VALUE(canonical_sexp)
{
  CAST(parse_value, self, *s);

  if (!available)
    {
      SEXP_EOF(self->super.e, "No more sexps.");
      *s = NULL;
      return 0;
    }

  switch(data[0])
    {
    case '[':
      *s = make_parse_display(make_parse_literal, self->c,
			      self->super.e, self->super.next);
      return 1;

    case '(':
      *s = make_parse_list(0, make_parse_canonical_sexp,
			   self->c, self->super.e, self->super.next);
      return 1;

    case '0': case '1': case '2': case '3': case '4':
    case '5': case '6': case '7': case '8': case '9':
      *s = make_parse_length(data[0], make_return_string(self->c),
			     self->super.e, self->super.next);
      return 1;

    default:
      SEXP_ERROR(self->super.e, "Invalid canonical expression");
      *s = NULL;
      return 0;
    }
}

static UINT32 do_expect_eof(struct read_handler **s,
			    UINT32 available,
			    UINT8 *data UNUSED)
{
  CAST(parser, self, *s);
  if (available)
    {
      SEXP_ERROR(self->e, "Expected EOF");
    }
  *s = NULL;
  return 0;
}

static struct read_handler *
make_expect_eof(struct exception_handler *e)
{
  NEW(parser, self);
  self->super.handler = do_expect_eof;
  self->e = e;
  self->next = NULL;

  return &self->super;
}


/* GABA:
   (class
     (name parse_base64)
     (super parser)
     (vars
       (state simple "struct base64_state")
       (inner object read_handler)))
*/

static UINT32
do_parse_base64(struct read_handler **s,
		UINT32 available,
		UINT8 *data)
{
  CAST(parse_base64, self, *s);
  UINT32 done;

  /* FIXME: Decoding one character at a time seems a little
   * inefficient. But it's the simplest way to ensure that we don't go
   * on after errors. To do something better, we would let
   * make_parse_transport() and similar functions install a proper
   * exception handler. */

  if (!available)
    {
      SEXP_ERROR(self->super.e, "Unexpected EOF in base 64 string.");
      return 0;
    }

  for (done = 0; done < available; )
    {
      int digit;
      switch ( (digit = base64_decode(&self->state, data[done++])) )
	{
	case BASE64_INVALID:
	  SEXP_ERROR(self->super.e, "Invalid base64 data.");
	  return done;
	case BASE64_END:
	  /* Pass EOF to the inner parser */
	  READ_HANDLER(self->inner, 0, NULL);
	  *s = self->super.next;
	  return done;
	case BASE64_SPACE:
	  /* Is space always ok? */
	case BASE64_PARTIAL:
	  continue;
	default:
	  {
	    UINT8 buffer;
	    
	    assert(digit >= 0);
	    buffer = digit;

	    /* Loop until the character is consumed. */
	    while (!READ_HANDLER(self->inner, 1, &buffer))
	      ;
	    return done;
	  }
	}
    }
  return done;
}
  
static struct read_handler *
make_parse_base64(UINT8 terminator,
		  struct read_handler *inner,
		  struct exception_handler *e,
		  struct read_handler *next)
{
  NEW(parse_base64, self);
  self->super.super.handler = do_parse_base64;
  self->super.e = e;
  self->super.next = next;
  self->inner = inner;

  base64_init(&self->state, terminator);

  return &self->super.super;
}

static struct read_handler *
make_parse_transport(struct read_handler * (*make)(struct command_continuation *c,
						   struct exception_handler *e,
						   struct read_handler *next),
		     struct command_continuation *c,
		     struct exception_handler *e,
		     struct read_handler *next)
{
  return
    make_parse_base64('}',
		      make(c, e, 
			   make_expect_eof(e)),
		      e,
		      next);
}

MAKE_PARSE_VALUE(transport_sexp)
{
  CAST(parse_value, self, *s);
  unsigned i;

  if (!available)
    {
      SEXP_EOF(self->super.e, "No more sexps.");
      *s = NULL;
      return 0;
    }
  
  for (i = 0;  (i < available) && (sexp_char_classes[data[i]] & CHAR_space); i++)
    ;
  
  if (i == available)
    return i;
  
  switch(data[i])
    {
    case '[':
      *s = make_parse_display(make_parse_literal, self->c,
			      self->super.e, self->super.next);
      return i + 1;

    case '(':
      *s = make_parse_list(0, make_parse_canonical_sexp,
			   self->c, self->super.e, self->super.next);
      return i + 1;

    case '0': case '1': case '2': case '3': case '4':
    case '5': case '6': case '7': case '8': case '9':
      *s = make_parse_length(data[i], make_return_string(self->c),
			     self->super.e, self->super.next);
      return i + 1;

    case '{':
      *s = make_parse_transport(make_parse_canonical_sexp,
				self->c, self->super.e, self->super.next);
      return i + 1;
    default:
      SEXP_ERROR(self->super.e, "Invalid transport-style expression");
      *s = NULL;
      return i;
    }
}

static UINT32
do_skip_comment(struct read_handler **s,
		UINT32 available, UINT8 *data)
{
  CAST(parser, self, *s);
  UINT32 i;
  
  if (!available)
    {
      SEXP_EOF(self->e, "EOF in comment.");
      *s = NULL;
      return 0;
    }
  
  for (i = 0;  (i < available) && (data[i] != 0xa); i++)
    ;
  
  if (i == available)
    *s = self->next;
  
  return i;
}

static struct read_handler *
make_parse_comment(struct exception_handler *e,
		   struct read_handler *next)
{
  NEW(parser, self);
  self->e = e;
  self->next = next;
  self->super.handler = do_skip_comment;

  return &self->super;
}

/* FIXME: Doesn't implement the full advanced syntax, but at least
 * allows extra white space. Also allows comments, starting with ';'
 * and terminating at end of line. */
MAKE_PARSE_VALUE(advanced_sexp)
{
  CAST(parse_value, self, *s);
  unsigned i;

  if (!available)
    {
      SEXP_EOF(self->super.e, "No more sexps.");
      *s = NULL;
      return 0;
    }
  
  for (i = 0;  (i < available) && (sexp_char_classes[data[i]] & CHAR_space); i++)
    ;
  
  if (i == available)
    return i;
  
  switch(data[i])
    {
    case '[':
      *s = make_parse_display(make_parse_literal, self->c,
			      self->super.e, self->super.next);
      return i + 1;

    case '(':
      *s = make_parse_list(0, make_parse_advanced_sexp,
			   self->c, self->super.e, self->super.next);
      return i + 1;

    case '0': case '1': case '2': case '3': case '4':
    case '5': case '6': case '7': case '8': case '9':
      *s = make_parse_length(data[i], make_return_string(self->c),
			     self->super.e, self->super.next);
      return i + 1;

    case '{':
      *s = make_parse_transport(make_parse_canonical_sexp,
				self->c, self->super.e, self->super.next);
      return i + 1;

    case ';':  /* Comment */
      *s = make_parse_comment(self->super.e, &self->super.super);
      return i+1;
      
    default:
      SEXP_ERROR(self->super.e, "Invalid ur unimplemented advanced-style expression");
      *s = NULL;
      return i;
    }
}

static UINT32
do_parse_loop(struct read_handler **s,
	      UINT32 available,
	      UINT8 *data)
{
  CAST(parser, self, *s);
    
  *s = self->next;
  return READ_HANDLER(*s, available, data);
}

static struct parser *
make_parse_loop(struct exception_handler *e,
		struct read_handler *next)
{
  NEW(parser, self);
  self->super.handler = do_parse_loop;
  self->e = e;
  self->next = next;

  return self;
}

struct read_handler *
make_read_sexp(int style, int goon,
	       struct command_continuation *c,
	       struct exception_handler *e)
{
  struct read_handler *reader;
  struct parser *loop = NULL;
  
  if (goon)
    {
      loop = make_parse_loop(e, NULL);
    }

  switch (style)
    {
    case SEXP_CANONICAL:
      reader = make_parse_canonical_sexp(c, e, &loop->super);
      break;
    case SEXP_TRANSPORT:
      reader = make_parse_transport_sexp(c, e, &loop->super);
      break;
    case SEXP_ADVANCED:
    case SEXP_INTERNATIONAL:
      reader = make_parse_advanced_sexp(c, e, &loop->super);
      break;
    default:
      fatal("Internal error!\n");
    }

  if (goon)
    {
      loop->next = reader;
      return &loop->super;
    }
  
  return reader;
}

  

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


static struct scanner *make_parse_advanced_string(struct string_handler *h,
						    struct scanner *next)
{
  NEW(parse_string, closure);

  closure->handler = h;
  closure->super.next = next;

  return &closure->super.super;
}

#endif

#if 0
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
#endif
