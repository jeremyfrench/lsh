/* buffer.c
 *
 * $Id$
 *
 * Buffering for sftp.
 */

#include "buffer.h"

#include "sftp.h"

#include <assert.h>
#include <stdarg.h>

#define FATAL(x) do { fputs("sftp-server: " x "\n", stderr); exit(EXIT_FAILURE); } while (0)

#if LSH
#include <stdlib.h>

struct sftp_input
{
  FILE *f;
  UINT32 left;
};

struct sftp_output
{
  FILE *f;

  /* The message type is the first byte of a message, after the
   * length. */
  UINT8 msg;

  /* The next word is either the id, or the version. */
  UINT32 first;

  /* The rest of the packet is variable length. */
  UINT8 *data;
  UINT32 size;
  UINT32 i;
};

/* Input */

static int
sftp_check_input(struct sftp_input *input, UINT32 length)
{
  if (input->left < length)
    return 0;

  input->left -= length;
  return 1;
}

int
sftp_get_data(struct sftp_input *i, UINT32 length, UINT8 *data)
{
  return sftp_check_input(i, length)
    && (fread(data, 1, length, i->f) == length);
}

#define GET_DATA(i, buf) \
(sftp_get_data((i), sizeof((buf)), (buf)))

int
sftp_get_uint8(struct sftp_input *i, UINT8 *value)
{
  return sftp_get_data(i, 1, value);    
}

int
sftp_get_uint32(struct sftp_input *i, UINT32 *value)
{
  UINT8 buf[4];
  if (!GET_DATA(i, buf))
    return 0;

  *value = READ_UINT32(buf);
  return 1;
}

#define READ_UINT64(p)				\
(  (((UINT64) (p)[0]) << 56)			\
 | (((UINT64) (p)[1]) << 48)			\
 | (((UINT64) (p)[2]) << 40)			\
 | (((UINT64) (p)[3]) << 32)			\
 | (((UINT64) (p)[4]) << 24)			\
 | (((UINT64) (p)[5]) << 16)			\
 | (((UINT64) (p)[6]) << 8)			\
 |  ((UINT64) (p)[7]))

int
sftp_get_uint64(struct sftp_input *i, UINT64 *value)
{
  UINT8 buf[8];
  if (!GET_DATA(i, buf))
    return 0;

  *value = READ_UINT64(buf);
  return 1;
}

UINT8 *
sftp_get_string(struct sftp_input *i, UINT32 *length)
{
  UINT8 *data;
  
  if (!(sftp_get_uint32(i, length) && sftp_check_input(i, *length)))
    return NULL;

  data = malloc(*length + 1);
  if (!data)
    return NULL;

  if (!sftp_get_data(i, *length, data))
    {
      free(data);
      return NULL;
    }

  /* NUL-terminate, for convenience */
  data[*length] = '\0';
  return data;
}

void
sftp_free_string(UINT8 *data)
{
  free(data);
}

int sftp_get_eod(struct sftp_input *i)
{
  return !i->left;
}

/* Input */
struct sftp_input *
sftp_make_input(FILE *f)
{
  struct sftp_input *i = malloc(sizeof(struct sftp_input));
  if (i)
    {
      i->f = f;
      i->left = 0;
    }
  return i;
}

/* Returns 1 of all was well, 0 on error, and -1 on EOF */
int
sftp_read_packet(struct sftp_input *i)
{
  UINT8 buf[4];
  int done;
  
  assert(i->left == 0);

  done = fread(buf, 1, sizeof(buf), i->f);

  switch (done)
    {
    case 0:
      return feof(i->f) ? -1 : 0;
    case 4:
      i->left = READ_UINT32(buf);
      return 1;
    default:
      return 0;
    }
}

/* Output */

static void
sftp_check_output(struct sftp_output *o, UINT32 length)
{
  UINT32 needed = o->i + length;
  if (!o->data || (needed > o->size))
  {
    UINT8 *p;
    UINT32 size = 2 * needed + 40;
    p = realloc(o->data, size);
    if (!p)
      FATAL("Virtual memory exhausted");

    o->data = p;
    o->size = size;
  }
}

void
sftp_put_data(struct sftp_output *o, UINT32 length, const UINT8 *data)
{
  sftp_check_output(o, length);

  memcpy(o->data + o->i, data, length);
  o->i += length;
}

#define PUT_DATA(o, buf) \
(sftp_put_data((o), sizeof((buf)), (buf)))

void
sftp_put_uint8(struct sftp_output *o, UINT8 value)
{
  sftp_check_output(o, 1);

  o->data[o->i++] = value;
}

void
sftp_put_uint32(struct sftp_output *o, UINT32 value)
{
  UINT8 buf[4];

  WRITE_UINT32(buf, value);
  PUT_DATA(o, buf);
}

#define WRITE_UINT64(p, i)			\
do {						\
  (p)[0] = ((i) >> 56) & 0xff;			\
  (p)[1] = ((i) >> 48) & 0xff;			\
  (p)[2] = ((i) >> 40) & 0xff;			\
  (p)[3] = ((i) >> 32) & 0xff;			\
  (p)[4] = ((i) >> 24) & 0xff;			\
  (p)[5] = ((i) >> 16) & 0xff;			\
  (p)[6] = ((i) >> 8) & 0xff;			\
  (p)[7] = (i) & 0xff;				\
} while(0)

void
sftp_put_uint64(struct sftp_output *o, UINT64 value)
{
  UINT8 buf[8];

  WRITE_UINT64(buf, value);
  PUT_DATA(o, buf);
}

void
sftp_put_string(struct sftp_output *o, UINT32 length, UINT8 *data)
{
  sftp_put_uint32(o, length);
  sftp_put_data(o, length, data);
}

UINT32
sftp_put_reserve_length(struct sftp_output *o)
{
  UINT32 index;
  sftp_check_output(o, 4);

  index = o->i;
  o->i += 4;

  return index;
}

void
sftp_put_length(struct sftp_output *o,
		UINT32 index,
		UINT32 length)
{
  assert( (index + 4) < o->i);
  WRITE_UINT32(o->data + index, length);
}

void
sftp_put_final_length(struct sftp_output *o,
		      UINT32 index)
{
  sftp_put_length(o, index, o->i - index);
}

UINT32
sftp_put_printf(struct sftp_output *o, const char *format, ...)
{
  /* Initial buffer space */
  size_t needed;
  int length;
  
  for (needed = 100;; needed *= 2)
    {
      va_list args;
      
      va_start(args, format);

      sftp_check_output(o, needed);
      length = vsnprintf(o->data + o->i, needed, format, args);
      
      va_end(args);

      if ( (length >= 0) && (length < needed))
	break;
    }
  o->i += length;
  
  return length;
}

/* If SIZE > 0 it is the desired field length, and
 * smaller output is padded with blanks. */
UINT32
sftp_put_strftime(struct sftp_output *o, UINT32 size, const char *format,
		  const struct tm *tm)
{
  /* Initial buffer space */
  size_t needed;
  int length;
  
  for (needed = size ? size : 100;; needed *= 2)
    {
      sftp_check_output(o, needed);
      length = strftime(o->data + o->i, needed, format, tm);

      if ( (length >= 0) && (length < needed))
	break;
    }

  while ( (unsigned) length < size)
    o->data[o->i + length++] = ' ';

  o->i += length;
  
  return length;
}

/* The first part of the buffer is always
 *
 * uint32 length
 * uint8  msg
 * uint32 id/version
 */

struct sftp_output *
sftp_make_output(FILE *f)
{
  struct sftp_output *o = malloc(sizeof(struct sftp_output));
  if (o)
    {
      o->f = f;
      o->data = NULL;
      o->size = 0;
      o->i = 0;
    }
  return o;
}

void
sftp_set_msg(struct sftp_output *o, UINT8 msg)
{
  o->msg = msg;
}

void
sftp_set_id(struct sftp_output *o, UINT32 id)
{
  o->first = id;
}

int
sftp_write_packet(struct sftp_output *o)
{
  UINT32 length = o->i + 5;
  UINT8 buf[9];

  WRITE_UINT32(buf, length);
  buf[4] = o->msg;
  WRITE_UINT32(buf + 5, o->first);

  if (fwrite(buf, 1, 9, o->f) != 9)
    return 0;
  if (fwrite(o->data, 1, o->i, o->f) != o->i)
    return 0;

  o->i = 0;

  /* FIXME: Flushing after each packet is sub-optimal. */
  if (fflush(o->f))
    return 0;

  return 1;
}

#endif /* LSH */

/* General functions */

void
sftp_clear_attrib(struct sftp_attrib *a)
{
  a->flags = 0;
  a->size = 0;
  a->uid = 0;
  a->gid = 0;
  a->permissions = 0;
  a->atime = 0;
  a->mtime = 0;
};

int
sftp_skip_extension(struct sftp_input *i)
{
  UINT32 length;
  UINT8 *data;
  unsigned j;
  
  /* Skip name and value*/
  for (j = 0; j<2; j++)
    {
      if (!(data = sftp_get_string(i, &length)))
	return 0;
      
      sftp_free_string(data);
    }
  return 1;
}

int
sftp_get_attrib(struct sftp_input *i, struct sftp_attrib *a)
{
  sftp_clear_attrib(a);
  
  if (!sftp_get_uint32(i, &a->flags))
    return 0;

  if (a->flags & SSH_FILEXFER_ATTR_SIZE)
    {
      if (!sftp_get_uint64(i, &a->size))
	return 0;
    }

  if (a->flags & SSH_FILEXFER_ATTR_UIDGID)
    {
      if (!sftp_get_uint32(i, &a->uid))
	return 0;

      if (!sftp_get_uint32(i, &a->gid))
	return 0;
    }

  if (a->flags & SSH_FILEXFER_ATTR_PERMISSIONS)
    {
      if (!sftp_get_uint32(i, &a->permissions))
	return 0;
    }

  if (a->flags & SSH_FILEXFER_ATTR_ACMODTIME)
    {
      if (!sftp_get_uint32(i, &a->atime))
	return 0;

      if (!sftp_get_uint32(i, &a->mtime))
	return 0;
    }

  if (a->flags & SSH_FILEXFER_ATTR_EXTENDED)
    {
      UINT32 count;
      UINT32 n;

      if (!sftp_get_uint32(i, &count))
	return 0;

      /* Just skip the extensions */
      for (n = 0; n < count; n++)
	if (!sftp_skip_extension(i))
	  return 0;
    }
  return 1;
}

void
sftp_put_attrib(struct sftp_output *o, const struct sftp_attrib *a)
{
  assert(!a->flags & SSH_FILEXFER_ATTR_EXTENDED);
  
  sftp_put_uint32(o, a->flags);

  if (a->flags & SSH_FILEXFER_ATTR_SIZE)
    sftp_put_uint64(o, a->size);

  if (a->flags & SSH_FILEXFER_ATTR_UIDGID)
    {
      sftp_put_uint32(o, a->uid);
      sftp_put_uint32(o, a->gid);
    }

  if (a->flags & SSH_FILEXFER_ATTR_PERMISSIONS)
    sftp_put_uint32(o, a->permissions);

  if (a->flags & SSH_FILEXFER_ATTR_ACMODTIME)
    {
      sftp_put_uint32(o, a->atime);
      sftp_put_uint32(o, a->mtime);
    }
}
