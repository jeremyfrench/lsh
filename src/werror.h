/* werror.h
 *
 */

#ifndef LSH_ERROR_H_INCLUDED
#define LSH_ERROR_H_INCLUDED

#ifdef __GNUC__
#define NORETURN __attribute__ ((noreturn))
#define PRINTF_STYLE(f, a) __attribute__ ((format(printf, f, a)))
#else
#define NORETURN
#define PRINTF_STYLE(f, a)
#endif

void werror(char *format, ...) PRINTF_STYLE(1,2);
void fatal(char *format, ...) PRINTF_STYLE(1,2) NORETURN;

#endif /* LSH_ERROR_H_INCLUDED */
