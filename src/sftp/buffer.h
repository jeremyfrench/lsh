/* buffer.h
 *
 * Buffering for sftp.
 */

#ifndef SFTP_BUFFER_H_INCLUDED
#define SFTP_BUFFER_H_INCLUDED

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

UINT8 *
sftp_put_reserve(struct sftp_output *o, UINT32 length);



#endif /* SFTP_BUFFER_H_INCLUDED */
