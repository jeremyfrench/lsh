dnl -*- mode: shell-script; sh-indentation: 2; -*-
dnl $Id$

dnl Process this file with autoconf to produce a configure script.

AC_INIT([libspki], [0.1])
AC_CONFIG_SRCDIR([certificate.c])
AC_PREREQ(2.50)
AM_INIT_AUTOMAKE
AM_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_MAKE_SET
AC_PROG_RANLIB
AM_PROG_CC_STDC

if test "x$am_cv_prog_cc_stdc" = xno ; then
  AC_ERROR([the C compiler doesn't handle ANSI-C])
fi

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_UID_T
AC_TYPE_SIZE_T
AC_HEADER_TIME

# Needed by the supplied memcmp.c
AC_C_BIGENDIAN

# Checks for libraries
AC_CHECK_LIB(gmp, __gmpz_getlimbn,,
    [AC_MSG_ERROR(
    [GNU MP not found, or not 3.1 or up, see http://www.swox.com/gmp.])])

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
  -Wpointer-arith -Wbad-function-cast -Wnested-externs"
fi

AC_OUTPUT(Makefile testsuite/Makefile)
