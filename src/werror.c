/* werror.c
 *
 */

#include "werror.h"

#include <stdio.h>
#include <stdarg.h>

void werror(char *format, ...) 
{
  va_list args;

  va_start(args, format);
  vfprintf(stderr, format, args);
  va_end(args);
}

void fatal(char *format, ...) 
{
  va_list args;

  va_start(args, format);
  vfprintf(stderr, format, args);
  va_end(args);

  abort();
}
