/* sexp.c
 *
 * An implementation of Ron Rivest's S-expressions, used in spki.
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

#include "sexp.h"

#include "format.h"
#include "werror.h"
#include "xalloc.h"

#include <assert.h>
#include <stdarg.h>

#define CLASS_DEFINE
#include "sexp.h.x"
#undef CLASS_DEFINE

#include "sexp.c.x"

/* CLASS:
   (class
     (name sexp_string)
     (super sexp)
     (vars
       (display string)
       (contents string)))
*/

static struct lsh_string *do_format_sexp_string(struct sexp *s, int style)
{
  CAST(sexp_string, self, s);

  switch(style)
    {
    case SEXP_TRANSPORT:
      fatal("Internal error!\n");
    case SEXP_ADVANCED:
      /* Special case of canonical, so we'll fal through for now. */
    case SEXP_CANONICAL:
      if (self->display)
	return ssh_format("[%ds]%ds",
			  self->display->length, self->display->data,
			  self->contents->length, self->contents->data);
      else
	return ssh_format("%ds",
			  self->contents->length, self->contents->data);
    default:
      fatal("do_format_sexp_string: Unknown output style.\n");
    }
}

/* Consumes its args (display may be NULL) */
static struct sexp *make_sexp_string(struct lsh_string *d, struct lsh_string *c)
{
  NEW(sexp_string, s);

  s->super.format = do_format_sexp_string;
  
  s->display = d;
  s->contents = c;
  
  return &s->super;
}

static struct lsh_string *do_format_sexp_tail(struct sexp_cons *c, int style)
{
  if (!c)
    return ssh_format(")");

  switch(style)
    {
    case SEXP_TRANSPORT:
      fatal("Internal error!\n");
    case SEXP_ADVANCED:
      /* Special case of canonical, so we'll fall through for now. */
    case SEXP_CANONICAL:
      return ssh_format("%ls %ls",
			sexp_format(c->car, style),
			do_format_sexp_tail(c->cdr, style));
    default:
      fatal("do_format_sexp_tail: Unknown output style.\n");
    }
}

static struct lsh_string *do_format_sexp_cons(struct sexp *s, int style)
{
  CAST(sexp_cons, self, s);

  switch(style)
    {
    case SEXP_TRANSPORT:
      fatal("Internal error!\n");
    case SEXP_ADVANCED:
      /* Special case of canonical, so we'll fal through for now. */
    case SEXP_CANONICAL:
      return ssh_format("(%ls", do_format_sexp_tail(self, style));
    default:
      fatal("do_format_sexp_tail: Unknown output style.\n");
    }
}

struct sexp *sexp_c(struct sexp *car, struct sexp_cons *cdr)
{
  NEW(sexp_cons, c);

  c->super.format = do_format_sexp_cons;
  
  c->car = car;
  c->cdr = cdr;

  return &c->super;
}

/* CLASS:
   (class
     (name sexp_vector)
     (super sexp)
     (vars
       ; FIXME: With better var-array support, this
       ; could use an embedded var-array instead.
       (elements object object_list)))
*/

static struct lsh_string *do_format_sexp_vector(struct sexp *e, int style)
{
  CAST(sexp_vector, v, e);

  unsigned i;
  UINT32 size;
  
  struct lsh_string **elements = alloca(LIST_LENGTH(v->elements)
					* sizeof(struct lsh_string *) );
  
  switch(style)
    {
    case SEXP_TRANSPORT:
      fatal("Internal error!\n");
    case SEXP_ADVANCED:
      /* Special case of canonical, so we'll fal through for now. */
    case SEXP_CANONICAL:
      {
	struct lsh_string *res;
	UINT8 *dst;
	
	assert(LIST_LENGTH(v->elements));
	for (i = 0, size = 0; i<LIST_LENGTH(v->elements); i++)
	  {
	    CAST_SUBTYPE(sexp, o, LIST(v->elements)[i]);
	    
	    elements[i] = sexp_format(o, style);
	    size += elements[i]->length;
	  }
	
	res = lsh_string_alloc(size + 2);
	dst = res->data;
	
	*dst++ = '(';
	for (i = 0; i<LIST_LENGTH(v->elements); i++)
	  {
	    memcpy(dst, elements[i]->data, elements[i]->length);
	    dst += elements[i]->length;
	    
	    lsh_string_free(elements[i]);
	  }
	*dst++ = ')';
	
	assert(dst == (res->data + res->length));
	
	return res;
      }
    default:
      fatal("do_format_sexp_vector: Unknown output style.\n");
    }
}

struct sexp *sexp_l(unsigned n, ...)
{
  va_list args;

  va_start(args, n);

  if (!n)
    {
      assert(va_arg(args, int) == -1);
      va_end(args);
      return NULL;
    }
  else
    {
      NEW(sexp_vector, v);

      v->super.format = do_format_sexp_vector;
      v->elements = make_object_listv(n, args);

      va_end(args);

      return &v->super;
    }
}

struct sexp *sexp_a(int a)
{
  return make_sexp_string(NULL, ssh_format("%la", a));
}

struct sexp *sexp_z(char *s)
{
  return make_sexp_string(NULL, ssh_format("%lz", s));
}

/* mpz->atom */
struct sexp *sexp_n(mpz_t n)
{
  return make_sexp_string(NULL, ssh_format("%ln", n));
}

struct sexp *sexp_sn(mpz_t n)
{
  fatal("sexp_sn: Signed numbers are not supported.\n");
}
    
struct lsh_string *sexp_format(struct sexp *e, int style)
{
  switch(style)
    {
    case SEXP_TRANSPORT:
      return ssh_format("{%lfs}",
			encode_base64(sexp_format(e, SEXP_CANONICAL), 1));
    case SEXP_ADVANCED:
    case SEXP_CANONICAL:
      return e
	? SEXP_FORMAT(e, style)
	: ssh_format("()");
    default:
      fatal("sexp_format: Unknown output style.\n");
    }
}

static void encode_base64_group(UINT32 n, UINT8 *dest)
{
  static const UINT8 digits[64] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"
    "ghijklmnopqrstuvwxyz0123456789+/";
  unsigned i;

  for (i = 0; i<4; i++)
    {
      dest[3 - i] = digits[n & 0x3f];
      n >>= 6;
    }
}

struct lsh_string *encode_base64(struct lsh_string *s, int free)
{
  UINT32 full_groups = (s->length) / 3;
  unsigned last = (s->length) % 3;

  struct lsh_string *res = lsh_string_alloc( (full_groups + !!last) * 4);

  UINT8 *src = s->data;
  UINT8 *dst = res->data;

  if (full_groups)
    {
      unsigned i;
      
      /* Loop over all but the last group. */
      for (i=0; i+1<full_groups; dst += 4, i++)
	{
	  encode_base64_group( ( (*src++) << 16)
			       | ( (*src++) << 8)
			       | (*src++), dst);
	}
    }
  switch(last)
    {
    case 0:
      /* Finished */
      break;
    case 1:
      encode_base64_group( (*src++) << 16, dst);
      dst += 2;
      *dst++ = '=';
      *dst++ = '=';
      break;
    case 2:
      encode_base64_group( ( (*src++) << 16)
			   | ( (*src++) << 8), dst);
      dst += 3;
      *dst++ = '=';
      break;
    default:
      fatal("encode_base64: Internal error!\n");
    }

  assert(dst == (res->data + res->length));

  if (free)
    lsh_string_free(s);
  
  return res;
}
