dnl -*- mode: shell-script; sh-indentation: 2; -*-
dnl $Id$

dnl Process this file with autoconf to produce a configure script.

AC_INIT(sftp-server.c)

AM_INIT_AUTOMAKE(lsh-sftp, 1.0)

AM_CONFIG_HEADER(config.h)

CPPFLAGS="$CPPFLAGS -D_GNU_SOURCE"

echo "srcdir:$srcdir: top:$top_srcdir:"

dnl We take options

AC_ARG_WITH(secsh, 
  AC_HELP_STRING([--with-secsh=PROG],[set the default SecSH client used for transport]),
  [transport_prog="$withval"])

AC_ARG_ENABLE(before_opts, 
  AC_HELP_STRING([--enable-before-opts=OPTS],[set the default options to the SecSH client before the commandline.]),
  [before_opts="$withval"])

AC_ARG_ENABLE(after_opts,
  AC_HELP_STRING([--enable-after-opts=OPTS],[set the default options to the SecSH client after the commandline.]),
  [after_opts="$withval"])



dnl Checks for programs.
AC_PROG_CC
AC_PROG_MAKE_SET
AC_PROG_RANLIB
AM_PROG_CC_STDC

if test "x$am_cv_prog_cc_stdc" = xno ; then
  AC_ERROR([the C compiler doesn't handle ANSI-C])
fi



dnl Choose the correct secsh client

dnl FIXME: Ugly check to see if we're a part of lsh, how to do this better?

if test -f $srcdir/../lsh.c; then
  # We're a part of lsh
  # FIXME: We should probably do something smart with program_transform_name 
  # here, but what if we're configured with another 
  # --program-{prefix,suffix,transform-name} when the main lsh system?
  # (But then again, that could be the case with bindir too.
  
  transport_prog="$bindir/lshg"
  before_opts="--subsystem=sftp"
  after_opts="-G"

  # Now, make sure these are included properly when compiling.
 
  CPPFLAGS="$CPPFLAGS -DTRANSPORT_PROG='\"$transport_prog\"'"
  CPPFLAGS="$CPPFLAGS -DTRANSPORT_BEFORE_OPTS='\"$before_opts\"'"
  CPPFLAGS="$CPPFLAGS -DTRANSPORT_AFTER_OPTS='\"$after_opts\"'"
else
  # Stand alone

  if test -z "$transport_prog"; then
    # No sech-client given, try to find an lshg
    AC_CHECK_PROG(found_lshg, lshg, [lshg])

    if test "$found_lshg" = lshg; then 

      # Found lshg? Check if it takes the subsystem flag (skip if options are given).
   
      if test -z "$before_opts" -a -z "$after_opts"; then
        if "$found_lshg" --help | grep subsystem >/dev/null; then
          # Takes the subsystems flag?
          before_opts="--subsystem=sftp"
          transport_prog="lshg"
        else
          AC_MSG_WARN([Your lshg doesn't support subsystems])
        fi
      else
        # Options given, assume the user knows what she's doing.
        transport_prog="lshg"
      fi
    fi

    # No or bad (old) lshg found, try ssh
    if test -z "$transport_prog"; then
      AC_CHECK_PROG(found_ssh, ssh, [ssh])

      if test "$found_ssh" = ssh; then
        # FIXME: Should try to run with -s
        if test -z "$before_opts" -a -z "$after_opts"; then
          before_opts="-s"
  	after_opts="sftp"
          transport_prog="ssh"
        else
          # The user gave before or after?
          transport_prog="ssh"
        fi
      fi
    fi
  fi

  dnl If we still haven't defined either of before_opts and after_opts, try to decide from transport_prog
  dnl (happens if the user told us what to use, but not how).

  if test -z "$before_opts" -a -z "$after_opts"; then
    if test "$transport_prog" = "ssh"; then 
      before_opts="-s"
      after_opts="sftp"
    fi
    if test "$transport_prog" = "lshg"; then 
      before_opts="--subsystem=sftp"
    fi
  fi
       
  AC_DEFINE_UNQUOTED(TRANSPORT_PROG, "$transport_prog", Program used for connecting)
  AC_DEFINE_UNQUOTED(TRANSPORT_BEFORE_OPTS, "$before_opts", Options sent before argv)
  AC_DEFINE_UNQUOTED(TRANSPORT_AFTER_OPTS, "$after_opts", Options sent after argv)

fi
    
AC_MSG_NOTICE([Using $transport_prog as secsh-client, adding $before_opts in front of arguments and $after_opts after them.])






dnl Checks for header files.
AC_HEADER_STDC

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_UID_T
AC_TYPE_SIZE_T
AC_HEADER_TIME

AC_CHECK_SIZEOF(short, 2)
AC_CHECK_SIZEOF(int, 4)
AC_CHECK_SIZEOF(long, 4)
AC_CHECK_SIZEOF(off_t, 8,
[#include <stdio.h>
 #include <unistd.h>])



case $target_os in                                                                                                                             *cygwin* ) using_cygwin=yes; AC_DEFINE_UNQUOTED(USING_CYGWIN, 1, Are we using CygWin?) ;;                                                    * ) using_cygwin=no;;
esac



dnl Check for gcc's __attribute__ construction
AC_CACHE_CHECK(for __attribute__,
	       lsh_cv_c_attribute,
[ AC_TRY_COMPILE([
#include <stdlib.h>
],
[
static void foo(void) __attribute__ ((noreturn));

static void __attribute__ ((noreturn))
foo(void)
{
  exit(1);
}
],
lsh_cv_c_attribute=yes,
lsh_cv_c_attribute=no)])

if test "x$lsh_cv_c_attribute" = "xyes"; then
  AC_DEFINE(HAVE_GCC_ATTRIBUTE)
fi

dnl Checks for library functions.
AC_CHECK_FUNCS(pread pwrite)


# Checks for header files.
AC_CHECK_HEADERS([inttypes.h limits.h stdlib.h string.h sys/acl.h sys/file.h\
 sys/ioctl.h termios.h unistd.h glob.h memory.h errno.h fcntl.h \
 readline/readline.h readline/history.h readline.h history.h\
 netinet/in.h string.h sys/stat.h sys/types.h pwd.h grp.h])

# If we didn't find readline/readline.h or the readline library,
# warn

if test x"$ac_cv_header_readline_readline_h" = xno -o\
	x"$ac_cv_library_readline" = xno ; then
		AC_MSG_WARN([
You don't appear to have the readline library
(or there seems to be a problem with it). lsftp 
will still work, but it will be built in 
non interactive mode ONLY.
])
else 
# Check for libraries only if we found the includes
AC_CHECK_LIB([readline], [rl_callback_handler_remove])
# AC_CHECK_FUNCS([filename_completion_function rl_filename_completion_function completion_matches rl_completion_matches])

# Egrep the header files to find out whatever to use rl_foo or foo

AC_EGREP_HEADER( rl_completion_matches, readline/readline.h, 
AC_DEFINE(HAVE_RL_COMPLETION_MATCHES, 1, System has rl_completion_matches ))
AC_EGREP_HEADER(\*completion_matches, readline/readline.h, 
AC_DEFINE(HAVE_COMPLETION_MATCHES, 1, System has rl_completion_matches ))
AC_EGREP_HEADER( rl_completion_matches, readline.h, 
AC_DEFINE(HAVE_RL_COMPLETION_MATCHES, 1, System has rl_completion_matches ))
AC_EGREP_HEADER(\*completion_matches, readline.h, 
AC_DEFINE(HAVE_COMPLETION_MATCHES, 1, System has rl_completion_matches ))

AC_EGREP_HEADER( rl_filename_completion_function, readline/readline.h, 
AC_DEFINE(HAVE_RL_FILENAME_COMPLETION_FUNCTION, 1, System has rl_filename_completion_function ))
AC_EGREP_HEADER(\*filename_completion_function, readline/readline.h, 
AC_DEFINE(HAVE_FILENAME_COMPLETION_FUNCTION, 1, Sytsem has filename_completion_function ))
AC_EGREP_HEADER( rl_filename_completion_function, readline.h, 
AC_DEFINE(HAVE_RL_FILENAME_COMPLETION_FUNCTION, 1, System has rl_filename_completion_function ))
AC_EGREP_HEADER(\*filename_completion_function, readline.h, 
AC_DEFINE(HAVE_FILENAME_COMPLETION_FUNCTION, 1, System has filename_completion_function ))


AC_EGREP_HEADER( rl_char_is_quoted_p, readline/readline.h, 
AC_DEFINE(HAVE_RL_CHAR_IS_QUOTED_P, 1, System has rl_char_is_quoted_p ))
AC_EGREP_HEADER(\*char_is_quoted, readline/readline.h, 
AC_DEFINE(HAVE_CHAR_IS_QUOTED, 1, System has char_is_quoted ))
AC_EGREP_HEADER( rl_char_is_quoted, readline.h, 
AC_DEFINE(HAVE_RL_CHAR_IS_QUOTED_P, 1, System has rl_char_is_quoted_p ))
AC_EGREP_HEADER(\*char_is_quoted, readline.h, 
AC_DEFINE(HAVE_CHAR_IS_QUOTED, 1, System has char_is_quoted ))


# Check (and warn) if we disable history because of a missing history.h.

if test x"$ac_cv_header_readline_history_h" = xno -o\
	x"$ac_cv_library_readline" = xno ; then
		AC_MSG_WARN([
Your readline library do not appear to have the 
history function. History will be disabled.
])
else
AC_CHECK_LIB([readline], [using_history])
fi

fi

AC_CHECK_MEMBERS([struct stat.st_rdev])




# Checks for library functions.
AC_FUNC_ALLOCA
AC_FUNC_ERROR_AT_LINE

AC_FUNC_MALLOC

AC_PROG_GCC_TRADITIONAL
AC_HEADER_MAJOR
AC_HEADER_STDC
AC_HEADER_DIRENT
AC_HEADER_TIME





AC_CHECK_FUNCS([getcwd getwd strcoll strdup  getenv fnmatch dup2])




# Set these flags *last*, or else the test programs won't compile
if test x$GCC = xyes ; then
    CFLAGS="$CFLAGS -ggdb3 -Wall -W \
 -Wmissing-prototypes -Wmissing-declarations -Wstrict-prototypes \
 -Waggregate-return \
 -Wpointer-arith -Wbad-function-cast -Wnested-externs -Wcast-align"
fi

AC_OUTPUT([Makefile testsuite/Makefile])
