dnl Process this file with autoconf to produce a configure script.

dnl This configure.ac is only for building a standalone argp library.
AC_PREREQ(2.54)
AC_INIT(argp-ba.c)
AM_INIT_AUTOMAKE(argp, standalone-1.2)
AM_CONFIG_HEADER(config.h)

# GNU libc defaults to supplying the ISO C library functions only. The
# _GNU_SOURCE define enables these extensions, in particular we want
# errno.h to declare program_invocation_name. Enable it on all
# systems; no problems have been reported with it so far.
AC_GNU_SOURCE
	
# Checks for programs.
AC_PROG_CC
AC_PROG_MAKE_SET
AC_PROG_RANLIB
AM_PROG_CC_STDC

if test "x$am_cv_prog_cc_stdc" = xno ; then
  AC_ERROR([the C compiler doesn't handle ANSI-C])
fi

# Checks for libraries.

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS(limits.h malloc.h unistd.h)

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_ALLOCA
AC_FUNC_VPRINTF
AC_CHECK_FUNCS(strerror)

AC_REPLACE_FUNCS(mempcpy strndup strchrnul)
# FIXME: Need to include stdio.h when testing for these functions.
# At least on freebsd, putc_unlocked is a macro.
AC_CHECK_FUNCS(flockfile putc_unlocked)
AC_CHECK_FUNCS(fputs_unlocked fwrite_unlocked)

# Used only by argp-test.c, so don't use AC_REPLACE_FUNCS.
AC_CHECK_FUNCS(strdup asprintf)

AC_CHECK_DECLS([program_invocation_name, program_invocation_short_name],
               [], [], [[#include <errno.h>]])

# Set these flags *last*, or else the test programs won't compile
if test x$GCC = xyes ; then
  # Using -ggdb3 makes (some versions of) Redhat's gcc-2.96 dump core
  if "$CC" --version | grep '^2\.96$' 1>/dev/null 2>&1; then
    true
  else
    CFLAGS="$CFLAGS -ggdb3"
  fi
  CFLAGS="$CFLAGS -Wall -W \
 -Wmissing-prototypes -Wmissing-declarations -Wstrict-prototypes \
 -Waggregate-return \
 -Wpointer-arith -Wbad-function-cast -Wnested-externs"
fi

CPPFLAGS="$CPPFLAGS -I$srcdir"

AC_OUTPUT(Makefile testsuite/Makefile)
