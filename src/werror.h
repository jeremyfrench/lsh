/* werror.h
 *
 */

#ifndef LSH_ERROR_H_INCLUDED
#define LSH_ERROR_H_INCLUDED

#include "lsh_types.h"

/* Global variables */
extern int debug_flag;
extern int quiet_flag;
extern int verbose_flag;

void werror(char *format, ...) PRINTF_STYLE(1,2);
void debug(char *format, ...) PRINTF_STYLE(1,2);
void verbose(char *format, ...) PRINTF_STYLE(1,2);

/* For outputting data recieved from the other end */
void werror_safe(UINT32 length, UINT8 *msg);
void debug_safe(UINT32 length, UINT8 *msg);
void verbose_safe(UINT32 length, UINT8 *msg);

void fatal(char *format, ...) PRINTF_STYLE(1,2) NORETURN;

#endif /* LSH_ERROR_H_INCLUDED */
