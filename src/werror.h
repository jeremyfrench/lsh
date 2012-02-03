/* werror.h
 *
 */

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

#ifndef LSH_ERROR_H_INCLUDED
#define LSH_ERROR_H_INCLUDED

#include <stdarg.h>

#include "lsh_argp.h"

#include "lsh.h"

#define GABA_DECLARE
#include "werror.h.x"
#undef GABA_DECLARE


/* GABA:
   (class
     (name werror_config)
     (vars
       (logfile string)
       (syslog . int)

       (quiet . int)
       (verbose . int)
       (trace . int)
       (debug . int)))
*/

void
init_werror_config(struct werror_config *self);

struct werror_config *
make_werror_config(void);

extern const struct argp werror_argp;
extern const struct config_parser werror_config_parser;

void toggle_quiet(void);
void toggle_verbose(void);
void toggle_trace(void);
void toggle_debug(void);

int werror_quiet_p(void);

int werror_init(struct werror_config *config);

void set_error_stream(int fd);
int get_error_stream(void);
void set_error_ignore(void);
void set_error_raw(int raw);

/* Tries to dup any error fd to something higher than STDERR_FILENO.
 * Used to be able to print any error messages while forking a child
 * process. */
int dup_error_stream(void);
     
#ifdef HAVE_SYSLOG
void set_error_syslog(void);
#endif

/* Format specifiers:
 *
 * %%  %-character
 * %e  an errno value, formated with strerror
 * %i  uint32_t
 * %c  int, interpreted as a single character to output
 * %n  mpz_t
 * %z  NUL-terminated string
 * %a  Insert a string containing one atom.
 * %s  uint32_t length, uint8_t *data
 * %S  lsh_string *s
 * %t  The type of an struct lsh_object *
 * %T  The type of an ssh message (int)
 *
 * Modifiers:
 *
 * x  hexadecimal output
 * f  Consume (and free) the input string
 * p  Filter out dangerous control characters
 * u  Input is in utf-8; convert to local charset
 */


void werror(const char *format, ...);
void trace(const char *format, ...);
void debug(const char *format, ...);
void verbose(const char *format, ...);
void die(const char *format, ...) NORETURN;

/* Displays the string with no prefix or new-line or buffering.
 * Suitable for progress indication. */
void werror_progress(const char *string);

void fatal(const char *format, ...) NORETURN;

#endif /* LSH_ERROR_H_INCLUDED */
