/* oop-line.h */

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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef OOP_LINE_H_INCLUDED
#define OOP_LINE_H_INCLUDED

#include <stdint.h>
#include <stdlib.h>

#include <oop.h>

/* Special return code from the line callback. */
extern int _oop_line_done;
#define OOP_LINE_DONE ((void *)& _oop_line_done)
  
typedef enum {
  OOP_LINE_OK,       /* A new line */
  OOP_LINE_EOF,      /* A (possibly empty) line terminated by EOF */
  OOP_LINE_ERROR,    /* I/O error occured, see errno */
  OOP_LINE_TOO_LONG, /* Line exceeding the maximum length */
  OOP_LINE_REST,     /* The remaining buffered data. */
} oop_line_event;
  
typedef struct oop_line oop_line;
  
/* LENGTH and DATA is one new line of data, newline character is not
   included. If the callback returns OOP_LINE_DONE, the callback is
   invoked again, with an EVENT == OOP_LINE_REST, and the data that
   remains in the buffer. If EVENT == OOP_LINE_REST, the callback is
   allowed to call oop_line_file_delete (after first cancelling any
   callback, as usual). */
typedef void *
oop_call_line(oop_line *line, oop_line_event event,
  	      size_t length, const uint8_t *data,
  	      void *state);
  
struct oop_line
{
  void (*on_line)(oop_line *line, oop_call_line *call, void *state);
  void (*cancel_line)(oop_line *line);
};
  
/* Reading lines from a file */
struct oop_line_file;
typedef struct oop_line_file oop_line_file;
  
/* Creates a new oop_line object, bound to the file descriptor FD, and
   with a maximum line length (including the terminating newline
   character) of MAX. */ 
oop_line_file *
oop_line_file_new(oop_source *source, int fd, size_t max);
  
/* Deletes the oop_line object. Any active callback must be cancelled
   first. */
void 
oop_line_file_delete(oop_line_file *line);
  
/* Get the registration interface */
oop_line *
oop_file_line(oop_line_file *line);

#endif /* OOP_LINE_H_INCLUDED */
