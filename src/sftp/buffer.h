/* buffer.h
 *
 * Buffering for sftp.
 */

#ifndef SFTP_BUFFER_H_INCLUDED
#define SFTP_BUFFER_H_INCLUDED

/* FIXME: We could use a configure test to check for __attribute__,
 * just like lsh does. */
#ifndef PRINTF_STYLE
# if __GNUC__ >= 2
#  define PRINTF_STYLE(f, a) __attribute__ ((__format__ (__printf__, f, a)))
# else
#  define PRINTF_STYLE(f, a)
# endif
#endif

#define LSH 1

#if LSH

#include "../lsh_types.h"

/* FIXME: Add to lsh_types.h */

#define UINT64 long long

#include <stdio.h>

struct sftp_input *
sftp_make_input(FILE *f);

/* Returns 1 of all was well, 0 on error, and -1 on EOF */
int
sftp_read_packet(struct sftp_input *i);

struct sftp_output *
sftp_make_output(FILE *f);

void
sftp_set_msg(struct sftp_output *o, UINT8 msg);

void
sftp_set_id(struct sftp_output *o, UINT32 id);

int
sftp_write_packet(struct sftp_output *o);

#else /* !LSH */
# error Needs either LSH config.h 
#endif /* !LSH */

#include <time.h>

struct sftp_input;
struct sftp_output;

/* Input */
int
sftp_get_data(struct sftp_input *i, UINT32 length, UINT8 *data);

int
sftp_get_uint8(struct sftp_input *i, UINT8 *value);

int
sftp_get_uint32(struct sftp_input *i, UINT32 *value);

int
sftp_get_uint64(struct sftp_input *i, UINT64 *value);

UINT8 *
sftp_get_string(struct sftp_input *i, UINT32 *length);

void
sftp_free_string(UINT8 *data);

int
sftp_get_eod(struct sftp_input *i);

/* Output */
void
sftp_put_data(struct sftp_output *o, UINT32 length, const UINT8 *data);

void
sftp_put_uint8(struct sftp_output *o, UINT8 value);

void
sftp_put_uint32(struct sftp_output *o, UINT32 value);

void
sftp_put_uint64(struct sftp_output *o, UINT64 value);

void
sftp_put_string(struct sftp_output *o, UINT32 length, UINT8 *data);

/* Returns index. */
UINT32
sftp_put_reserve_length(struct sftp_output *o);

void
sftp_put_final_length(struct sftp_output *o,
		      UINT32 index);

void
sftp_put_length(struct sftp_output *o,
		UINT32 index,
		UINT32 length);

UINT32
sftp_put_printf(struct sftp_output *o, const char *format, ...)
     PRINTF_STYLE(2,3);
     
UINT32
sftp_put_strftime(struct sftp_output *o, UINT32 size,
		  const char *format,
		  const struct tm *tm);

     
/* Constructed types. */

struct sftp_attrib
{
  UINT32 flags;
  UINT64 size;
  UINT32 uid;
  UINT32 gid;
  UINT32 permissions;

  /* NOTE: The representations of times is about to change. */
  UINT32 atime;
  UINT32 mtime;
};

void
sftp_clear_attrib(struct sftp_attrib *a);

int
sftp_get_attrib(struct sftp_input *i, struct sftp_attrib *a);

void
sftp_put_attrib(struct sftp_output *o, const struct sftp_attrib *a);

int
sftp_skip_extension(struct sftp_input *i);

#endif /* SFTP_BUFFER_H_INCLUDED */
