dnl $Id$

dnl Process this file with autoconf to produce a configure script.
AC_INIT([lsh], [1.5], [bug-lsh@gnu.org]) 
AC_PREREQ(2.52)
AC_CONFIG_SRCDIR([src/lsh_types.h])
AM_INIT_AUTOMAKE
AM_CONFIG_HEADER([config.h])

# AH_TEMPLATE([PACKAGE], [The name of this software distribution])
# AH_TEMPLATE([VERSION], [The version of this software distribution])

# FIXME: Move this to the Makefile, as recommended by the autoconf manual.

AH_TEMPLATE([PREFIX], [The installation prefix])
AC_DEFINE_UNQUOTED(PREFIX, "`echo $prefix | sed "s@^NONE@$ac_default_prefix@"`")

AH_TEMPLATE([SBINDIR], [sbin directory])
# NOTE: The definition below is broken.
AC_DEFINE_UNQUOTED(SBINDIR, "`echo $sbindir | sed "s@^NONE@$prefix/sbin@" | sed "s@^NONE@$ac_default_prefix@"`")

# We want an absolute path to the source-dir.
case "$srcdir" in
    /*)
    ;;
    *)
	oldsrcdir="$srcdir"
	srcdir="`cd \"$srcdir\";pwd`"
	AC_MSG_WARN([ Converted $oldsrcdir to $srcdir,
If this does not work, please use an absolute path to the configure script. ])
    ;;
esac

# src/rsync relies on lsh's definitions of WRITE_UINT32 etc.
CPPFLAGS="$CPPFLAGS -I$srcdir/src -DLSH"

# GNU libc defaults to supplying the ISO C library functions only. 
# initgroups() and strsignal() are extensions; the _GNU_SOURCE define
# enables these extensions.
# Enable it on all systems; no problems have been reported with it so far.

# We can't use AH_VERBATIM for this, as we want _GNU_SOURCE to be defined
# when running configure's test programs.
CPPFLAGS="$CPPFLAGS -D_GNU_SOURCE"

# Check options
AC_ARG_ENABLE(debug_alloc,
  AC_HELP_STRING([--enable-debug-alloc], [Enable memory allocation sanity checks]),,
  [enable_debug_alloc=no])

AH_TEMPLATE([DEBUG_ALLOC],
	    [Define to enable sanity checking on memory allocation and casting])
if test x$enable_debug_alloc = xyes ; then
  AC_DEFINE(DEBUG_ALLOC)
fi

AC_ARG_ENABLE(debug_trace,
  AC_HELP_STRING([--enable-debug-trace], [Enable tracing support]),,
  [enable_debug_trace=no])

AH_TEMPLATE([DEBUG_TRACE], [Define to enable tracing])
if test x$enable_debug_trace = xyes ; then
  AC_DEFINE(DEBUG_TRACE)
fi

AC_ARG_ENABLE(gcov,
  AC_HELP_STRING([--enable-gcov], [Instrument for gcov (requires a modern gcc)]),,
  [enable_gcov=no])

AC_ARG_WITH(zlib,
  AC_HELP_STRING([--without-zlib], [Don't use zlib compression]),,
  [with_zlib=yes])

AC_ARG_WITH(tcpwrappers,
  AC_HELP_STRING([--with-tcpwrappers], 
                [Use tcp-wrappers for filtering connections]),
  [if test -z "$withval"; then 
    with_tcpwrappers=yes; 
  else 
    with_tcpwrappers="$withval";
  fi],
  [with_tcpwrappers=no])

# Checking this variable is delayed until we have checked if zlib is
# actually available.

AC_ARG_ENABLE(pty,
  AC_HELP_STRING([--without-pty], [Disable pty support]),,
  [enable_pty=yes])

AH_TEMPLATE([WITH_PTY_SUPPORT], [Define to enable pty support])
if test x$enable_pty = xyes ; then
  AC_DEFINE(WITH_PTY_SUPPORT)
fi

AC_ARG_WITH(sshd1,
  AC_HELP_STRING([[--with-sshd1[=PROGRAM]]], [support fallback to SSH1 daemon]),,
  [with_sshd1=yes])

# Default sshd1 path
if test x$with_sshd1 = xyes ; then
  with_sshd1=/usr/local/sbin/sshd1
fi

AH_TEMPLATE([SSHD1], [Location of the SSH1 daemon])
AH_TEMPLATE([WITH_SSH1_FALLBACK], [Define to enable fallback to SSH1])
if test x$with_sshd1 != xno ; then
  AC_DEFINE(WITH_SSH1_FALLBACK)
  AC_DEFINE_UNQUOTED(SSHD1,"$with_sshd1")
fi

AC_ARG_ENABLE(srp,
  AC_HELP_STRING([--disable-srp], [Disable the (experimental) support for SRP]),,
  [enable_srp=yes])

AC_ARG_ENABLE(kerberos,
  AC_HELP_STRING([--disable-kerberos], [Don't support kerberos]),,
  [enable_kerberos=yes])

AC_ARG_ENABLE(pam,
  AC_HELP_STRING([--disable-pam], [Don't support PAM]),,
  [enable_pam=yes])

AH_TEMPLATE([WITH_SRP], [Define if SRP should be supported])
if test x$enable_srp = xyes ; then
  AC_DEFINE(WITH_SRP)
  SRP_PROGRAM=srp-gen
fi

AC_SUBST(SRP_PROGRAM)

AC_ARG_ENABLE(datafellows_workarounds,
  AC_HELP_STRING([--disable-datafellows-workarounds],
		 [Disable bug-compatibility with SSH Inc's clients and servers]),,
  [enable_datafellows_workarounds=yes])

AH_TEMPLATE([DATAFELLOWS_WORKAROUNDS],
	    [Define to support non-standard packets of ssh2])
if test x$enable_datafellows_workarounds = xyes ; then
  AC_DEFINE(DATAFELLOWS_WORKAROUNDS)
fi


AC_ARG_ENABLE(initgroups_workaround,
  AC_HELP_STRING([--enable-initgroups-workaround],
		 [Use a special initgroups for supporting more groups]),,
  [enable_initgroups_workaround=no])

AH_TEMPLATE([INITGROUPS_WORKAROUND],
	    [Define to enable the initgroups workaround])
if test x$enable_initgroups_workaround = xyes ; then
  AC_DEFINE(INITGROUPS_WORKAROUND)
fi


AC_ARG_ENABLE(tcp_forward,
  AC_HELP_STRING([--disable-tcp-forward], [Disable tcp forwarding]),,
  [enable_tcp_forward=yes])

AH_TEMPLATE([WITH_TCP_FORWARD], [Define to enable tcp forwarding])
if test x$enable_tcp_forward = xyes ; then
  AC_DEFINE(WITH_TCP_FORWARD)
fi

AC_ARG_ENABLE(x11_forward,
  AC_HELP_STRING([--disable-x11-forward], [Disable x11 forwarding (proxy only)]),,
  [enable_x11_forward=yes])

AH_TEMPLATE([WITH_X11_FORWARD], [Define to enable x11 forwarding])
if test x$enable_x11_forward = xyes ; then
  AC_DEFINE(WITH_X11_FORWARD)
fi

AC_ARG_ENABLE(agent_forward,
  AC_HELP_STRING([--disable-agent-forward], [Disable auth-agent forwarding (proxy only)]),,
  [with_agent_forward=yes])

AH_TEMPLATE([WITH_AGENT_FORWARD],
	    [Define to enable authentication agent forwarding])
if test x$disable_agent_forward = xyes ; then
  AC_DEFINE(WITH_AGENT_FORWARD)
fi

AC_ARG_WITH(scheme,
  AC_HELP_STRING([[--with-scheme[=PROGRAM]]], [Use a particular scheme implementation]),,
  [with_scheme=])

AC_ARG_WITH(system-argp,
  AC_HELP_STRING([--without-system-argp], [Don't use the system's argp]),,
  [with_system_argp=yes])

# IPv6 support
AC_ARG_ENABLE(ipv6,
  AC_HELP_STRING([--disable-ipv6], [Disable IPv6 support]),,
  [enable_ipv6=yes])

# utmp/wtmp logging 
AC_ARG_ENABLE(utmp,
  AC_HELP_STRING([--disable-utmp], [Disable utmp and wtmp support]),,
  [enable_utmp=yes])

AH_TEMPLATE([WITH_UTMP], [For utmp support])
if test x$enable_utmp = xyes ; then
  AC_DEFINE(WITH_UTMP)
fi

AC_ARG_WITH(include-path,
  AC_HELP_STRING([--with-include-path], [A colon-separated list of directories to search for include files]),,
  [with_include_path=''])

if test x$with_include_path != x ; then
  CPPFLAGS="$CPPFLAGS -I `echo $with_include_path | sed 's/:/ -I /g'`"
fi

AC_ARG_WITH(lib-path,
  AC_HELP_STRING([--with-lib-path], [A colon-separated list of directories to search for libraries]),,
  [with_lib_path=''])

if test x$with_lib_path != x ; then
  LDFLAGS="-L `echo $with_lib_path | sed 's/:/ -L /g'`"
fi

LSH_RPATH_INIT([`echo $with_lib_path | sed 's/:/ /g'` \
    `echo $exec_prefix | sed "s@^NONE@$prefix/lib@g" | sed "s@^NONE@$ac_default_prefix/lib@g"` \
    /usr/local/lib /sw/local/lib /sw/lib \
    /usr/gnu/lib /opt/gnu/lib /sw/gnu/lib /usr/freeware/lib /usr/pkg/lib])

dnl echo RPATH_CANDIDATE_DIRS = $RPATH_CANDIDATE_DIRS

# Checks for programs.
AC_PROG_CC
AC_PROG_MAKE_SET
AC_PROG_RANLIB
AM_PROG_CC_STDC

if test "x$am_cv_prog_cc_stdc" = xno ; then
  AC_MSG_ERROR([the C compiler doesn't handle ANSI-C])
fi

# Use a particular scheme implementation?
if test x$with_scheme != x ; then
  # If an absolute path is given, don't AC_PATH_PROG but just use it
  if grep "^/" > /dev/null <<EOF
$with_scheme 
EOF  
  then
    SCHEME_PROGRAM="$with_scheme" 
  else
    AC_PATH_PROG(SCHEME_PROGRAM, $with_scheme,, $PATH)
  fi
else  
  AC_PATH_PROGS(SCHEME_PROGRAM, guile scsh,, $PATH)
fi

if test "x$SCHEME_PROGRAM" = x ; then
  AC_MSG_WARN([No scheme implementation found.
This is fine as long as you don't modify the source files.])
  SCHEME_PROGRAM=false
fi

SCHEME_NAME=`basename $SCHEME_PROGRAM`
AC_SUBST(SCHEME_NAME)

# BASH gets set to the bogus value "/bin/sh" if /bin/sh is a bash.
# So unset it in that case.
if test "x$BASH" = x/bin/sh ; then
  unset BASH
fi

if test "x$BASH" = x; then    
  AC_PATH_PROG(BASH, bash,, $PATH)
fi
AC_ARG_VAR(BASH, bash shell)

if test "x$GROFF" = x; then
  AC_PATH_PROG(GROFF, groff,, $PATH)
fi
AC_ARG_VAR(GROFF, groff)

if test "x$M4" = x; then
  AC_PATH_PROG(M4, m4, m4)
fi
AC_ARG_VAR(M4, M4 macro processor)


# Checks for header files.
AC_HEADER_STDC

# We don't look in gmp2 anymore, as we need gmp-3.1 or better.
AC_CHECK_HEADERS(gmp.h,,
  AC_MSG_ERROR([gmp.h not found]))
  
AC_CHECK_HEADERS(fcntl.h strings.h sys/time.h unistd.h)
AC_CHECK_HEADERS(shadow.h)

if test x$with_zlib = xyes; then
  AC_CHECK_HEADERS(zlib.h,, [with_zlib=no])
fi
AC_CHECK_HEADERS(poll.h sys/poll.h)
AC_CHECK_HEADERS(libutil.h)
AC_CHECK_HEADERS(crypt.h)
AC_CHECK_HEADERS(pty.h)
AC_CHECK_HEADERS(stropts.h)
AC_CHECK_HEADERS(syslog.h)
AC_CHECK_HEADERS(argp.h)
AC_CHECK_HEADERS(sys/resource.h)

AC_CHECK_HEADERS(utmp.h, [have_utmp_h=yes], [have_utmp_h=no])
AC_CHECK_HEADERS(utmpx.h, [have_utmpx_h=yes], [have_utmpx_h=no])

dnl With current autoconfs we can't check for struct ut_tv with
dnl AC_CHECK_MEMBERS, but we can check for sub members. Leave the
dnl ut_tv check for clarity.

if test x$have_utmp_h = xyes; then
  AC_CHECK_MEMBERS([struct utmp.ut_host,
		    struct utmp.ut_name,
		    struct utmp.ut_user,
		    struct utmp.ut_time,
		    struct utmp.ut_tv,
		    struct utmp.ut_tv.tv_sec,
		    struct utmp.ut_id,
		    struct utmp.ut_syslen,
		    struct utmp.ut_session,
		    struct utmp.ut_pid,
		    struct utmp.ut_exit,
		    struct utmp.ut_addr,
		    struct utmp.ut_addr_v6],,,
[# if HAVE_UTMP_H
#  include <utmp.h>
# endif
])
fi

if test x$have_utmpx_h = xyes; then
  AC_CHECK_MEMBERS([struct utmpx.ut_host,
		    struct utmpx.ut_name,
		    struct utmpx.ut_user,
		    struct utmpx.ut_time,
		    struct utmpx.ut_id,
		    struct utmpx.ut_tv,
		    struct utmpx.ut_tv.tv_sec,
		    struct utmpx.ut_syslen,
		    struct utmpx.ut_session,
		    struct utmpx.ut_pid,
		    struct utmpx.ut_exit,
		    struct utmpx.ut_addr,
		    struct utmpx.ut_addr_v6],,,
[# if HAVE_UTMPX_H
#  include <utmpx.h>
# endif
])
fi



if test x$enable_kerberos = xyes; then
  AC_CHECK_HEADERS(krb5.h,, [enable_kerberos=no])
fi

if test x$enable_pam = xyes; then
  AC_CHECK_HEADERS(security/pam_appl.h,, [enable_pam=no])
fi

# Some systems (in particular, Unixware) doesn't have socklen_t, but
# uses size_t. Falling back to int will cause some warnings.

# AC_CHECK_TYPE doesn't work, probably because the type in
# question is not defined in sys/types.h.

AC_TYPE_SOCKLEN_T

AC_CHECK_LIB(gmp, __gmpz_getlimbn,,
    [AC_MSG_ERROR(
    [GNU MP not found, or not 3.1 or up, see http://www.swox.com/gmp.])])

# AC_SEARCH_LIBGMP(gmp gmp2,
#   [LSH_RPATH_FIX],
#   [AC_MSG_ERROR([GMP is missing. Get gmp-2.0.2 or better from ftp://ftp.gnu.org/pub/gnu/gmp]) ])

AC_CHECK_LIB([oop], [oop_sys_new],,
  [AC_MSG_ERROR([liboop is missing. Get liboop from http://www.liboop.org])])

LSH_RPATH_FIX

if test x$with_zlib = xyes; then
  AC_CHECK_LIB(z, inflate,, [with_zlib=no])
fi

if test x$with_zlib = xyes; then
  LSH_RPATH_FIX
fi

# FIXME: Should we let people use --with-tcpwrappers=/here/they/are?

if test x$with_tcpwrappers = xyes; then
  AC_CHECK_LIB(wrap, request_init,, 
  [
      AC_MSG_WARN([Failed to link libwrap, you might try adding -lsocket to LDFLAGS])
      with_tcpwrappers=no
  ])

  AC_CHECK_HEADER(tcpd.h,, [with_tcpwrappers=no])

  if test x$with_tcpwrappers = xno; then
    AC_MSG_WARN([Failed to find a working tcpwrappers setup, disabling wrappers])
  fi
fi

if test x$with_tcpwrappers = xyes; then
  LSH_RPATH_FIX
  AC_DEFINE(WITH_TCPWRAPPERS,1,[Whatever to use tcpwrappers])
else
  AC_DEFINE(WITH_TCPWRAPPERS,0,[Whatever to use tcpwrappers])
fi


# X11 stuff. We only need libXau.
AC_PATH_X

if test -z "$no_x" ; then
    CPPFLAGS="$CPPFLAGS -I$x_includes"
    LDFLAGS="$LDFLAGS -L$x_libraries"
    LSH_RPATH_ADD($x_libraries)
fi

AC_CHECK_HEADERS(X11/Xauth.h)
AC_CHECK_LIB(Xau, XauGetAuthByAddr)
LSH_RPATH_FIX

AC_ARG_VAR(XAUTH_PROGRAM, Program used to handle .Xauthority-files by lshd)

if test -z "$XAUTH_PROGRAM"; then
  AC_PATH_PROG(XAUTH_PROGRAM, xauth,, /usr/X11R6/bin:/usr/openwin/bin:/usr/X/bin:/usr/X11/bin:/usr/bin:/usr/bin/X:/usr/bin/X11)
fi

if test -z "$XAUTH_PROGRAM"; then
  AC_MSG_WARN(Couldn't find xauth, try passing XAUTH_PROGRAM=/path/to/xauth to configure)
else
  AC_DEFINE_UNQUOTED(XAUTH_PROGRAM, "$XAUTH_PROGRAM", Program used by lshd to handle .Xauthority-files)
fi

AC_CHECK_LIB(crypt, crypt)
AC_CHECK_LIB(xnet, inet_addr)
AC_CHECK_LIB(socket, setsockopt)
# logwtmp is also in libutil
AC_CHECK_LIB(util, openpty)

# glibc has a nis-library "libnsl", which we don't need. So use
# AC_SEARCH_LIBS rather than AC_CHECK_LIB.
AC_SEARCH_LIBS(gethostbyname, nsl)

# This macro is new in autoconf-2.13
AC_SEARCH_LIBS(syslog, bsd socket inet, [AC_DEFINE(HAVE_SYSLOG)])

AH_TEMPLATE([WITH_ZLIB], [Define if zlib should be used])
# Should we use zlib?
if test x$with_zlib = xyes ; then
  AC_DEFINE(WITH_ZLIB)
fi

# The kerberos libraries are needed only to support the
# krb-check-passwd program, so we put them $KRB_LIBS, not in the
# ordinary $LIBS.

if test x$enable_kerberos = xyes; then
  AC_CHECK_KRB_LIB(roken, strlcpy)
  AC_CHECK_KRB_LIB(resolv, dn_expand)
  AC_CHECK_KRB_LIB(des, des_cbc_encrypt)
  AC_CHECK_KRB_LIB(asn1, der_get_octet_string)
  AC_CHECK_KRB_LIB(krb5, krb5_cc_gen_new,, [enable_kerberos=no])
fi

AH_TEMPLATE([WITH_KERBEROS], [For kerberos])
if test x$enable_kerberos = xyes; then
  AC_DEFINE(WITH_KERBEROS)
  KRB_PROGRAM=lsh-krb-checkpw
fi

AC_SUBST(KRB_LIBS)
AC_SUBST(KRB_PROGRAM)

AH_TEMPLATE([WITH_PAM], [For PAM])
if test x$enable_pam = xyes; then
  AC_CHECK_LIB(pam,pam_start,, enable_pam=no )

  if test x$enable_pam = xyes; then
    AC_DEFINE(WITH_PAM)
    PAM_PROGRAM=lsh-pam-checkpw
  else
    AC_MSG_WARN([pam_start not found in libpam, disabling PAM])
  fi
fi

AC_SUBST(PAM_PROGRAM)

AH_TEMPLATE([WITH_GCOV], [Use gcov])
if test "x$enable_gcov" = "xyes"; then
  CFLAGS="$CFLAGS -ftest-coverage -fprofile-arcs"
  AC_DEFINE(WITH_GCOV)
fi

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_UID_T
AC_TYPE_SIZE_T
AC_HEADER_TIME

# Needed by the supplied memcmp.c
AC_C_BIGENDIAN

AC_CHECK_SIZEOF(short, 2)
AC_CHECK_SIZEOF(int, 4)
AC_CHECK_SIZEOF(long, 4)

# FIXME: We should check that a pid_t fits in an int
	
# Checks for library functions.

AC_FUNC_ALLOCA
AC_FUNC_MEMCMP
AC_FUNC_VPRINTF
AC_CHECK_FUNCS(select socket strerror strsignal strtol)
AC_CHECK_FUNCS(getrusage gettimeofday)
AC_CHECK_FUNCS(getspnam)
AC_CHECK_FUNCS(vsnprintf inet_aton)
AC_CHECK_FUNCS(openpty)
AC_CHECK_FUNCS(cfmakeraw)
AC_CHECK_FUNCS(logwtmp login logout pututline pututxline updwtmp updwtmpx)
AC_CHECK_FUNCS(getaddrinfo getnameinfo gai_strerror)
AC_CHECK_FUNCS(setrlimit)
AC_FUNC_GETPGRP
AC_CHECK_FUNCS(syslog)
AC_REPLACE_FUNCS(memxor)

# FIXME: Is there a better way in autoconf 2.50?
AC_CACHE_CHECK([if netdb.h defines AI_NUMERICHOST],
  lsh_cv_sys_ai_numerichost,
  [AC_EGREP_CPP(yes,
    [#include <netdb.h>
     #ifdef AI_NUMERICHOST
     yes
     #endif
    ], lsh_cv_sys_ai_numerichost=yes,
       lsh_cv_sys_ai_numerichost=no)])

AH_TEMPLATE([HAVE_AI_NUMERICHOST], [Define if AI_NUMERICHOST exists])
if test x$lsh_cv_sys_ai_numerichost = xyes ; then
  AC_DEFINE(HAVE_AI_NUMERICHOST)
fi

AC_CHECK_FUNCS(poll,,[AC_LIBOBJ([jpoll])])

# Test if the libc includes a good enough argp.
if test x$with_system_argp = xyes ; then
  AC_LIB_ARGP(,with_system_argp=no)
fi

# We don't use LIBOBJS for this, as the LIBOBJS are added to
# liblsh.a, and we can't add an archive to an archive.
LIBARGP=""
if test x$with_system_argp = xno ; then
  # FIXME: Perhaps it's better to use an absolute path?
  LIBARGP="argp/libargp.a"
fi

AC_SUBST(LIBARGP)

# Check for broken shutdown
AC_CACHE_CHECK(for working shutdown on AF_UNIX sockets,
	       lsh_cv_func_shutdown_works_on_unix_sockets,
[
AC_TRY_RUN([
#include <stdio.h>

#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <signal.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

/* Creates a one-way socket connection. Returns 1 on success, 0 on
 * failure. fds[0] is for reading, fds[1] for writing (like for the
 * pipe() system call). */
static int make_pipe(int *fds)
{

#ifndef SHUT_RD
#define SHUT_RD 0
#define SHUT_WR 1
#define SHUT_RDWR 2
#endif

  if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0)
    {
      fprintf(stderr, "socketpair() failed: %s\n", strerror(errno));
      return 0;
    }
  fprintf(stderr, "Created socket pair. Using fd:s %d <-- %d\n", fds[0], fds[1]);

  if(shutdown(fds[0], SHUT_WR) < 0)
    {
      fprintf(stderr, "shutdown(%d, SHUT_WR) failed: %s\n",
	      fds[0], strerror(errno));
      return 0;
    }
  if (shutdown(fds[1], SHUT_RD) < 0)
    {
      fprintf(stderr, "shutdown(%d, SHUT_RD) failed: %s\n",
	      fds[1], strerror(errno));
      return 0;
    }

  return 1;
}

int main(int argc, char **argv)
{
  int fds[2];
  
  if (!make_pipe(fds))
    exit(1);

  if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
    {
      fprintf(stderr, "signal failed.\n");
      exit(1);
    }

  if ( (write(fds[1], "foo", 3) < 0)
       && (errno == EPIPE))
    exit(1);

  exit(0);
}
], lsh_cv_func_shutdown_works_on_unix_sockets=yes,
   lsh_cv_func_shutdown_works_on_unix_sockets=no,
   lsh_cv_func_shutdown_works_on_unix_sockets=yes)])

AH_TEMPLATE([SHUTDOWN_WORKS_WITH_UNIX_SOCKETS],
	    [Define to indicate that shutdown seems to work properly])
if test x$lsh_cv_func_shutdown_works_on_unix_sockets = xyes ; then
    AC_DEFINE(SHUTDOWN_WORKS_WITH_UNIX_SOCKETS)
fi

AC_CACHE_CHECK(
  [for working UNIX98 ptys],
  lsh_cv_sys_unix98_ptys,
  AC_TRY_RUN([
  /* Try to obtain a working UNIX98-style pty master and slave */
  /* Based on example code from the GNU C library documentation */
  #include <stdlib.h>	/* EXIT_FAILURE, EXIT_SUCCESS, ptsname */
  #include <unistd.h>	/* close(2) */
  
  #include <sys/types.h>	/* open(2) */
  #include <sys/stat.h>	/* - " -   */
  #ifdef HAVE_FCNTL_H
  #  include <fcntl.h>	/* - " -   */
  #endif
  #ifdef HAVE_STROPTS_H
  #  include <stropts.h>	/* isastream() */
  #endif
  
  int main(int argc, char* argv[]) {
    int master, slave;
    char *name;
  
    master = open("/dev/ptmx", O_RDWR); /* PTY master multiplex */
    if (master < 0) {
  	  exit(EXIT_FAILURE);
    }
  
    if (grantpt(master) < 0 || unlockpt(master) < 0)
      goto close_master;
    name = ptsname(master);
    if (name == NULL)
      goto close_master;
  
    slave = open(name, O_RDWR);
    if (slave == -1)
      goto close_master;
  
  #ifdef HAVE_STROPTS_H
    if (isastream(slave))
      {
  	if (ioctl(slave, I_PUSH, "ptem") < 0
  	    || ioctl(slave, I_PUSH, "ldterm") < 0)
  	  goto close_slave;
      }
  #endif
  
    exit(0);
  
  close_slave:
    close (slave);
  
  close_master:
    close (master);
    exit(1);
  }
  ],
  [lsh_cv_sys_unix98_ptys=yes],
  [lsh_cv_sys_unix98_ptys=no],
  # Pessimistic default for cross compilation.
  [lsh_cv_sys_unix98_ptys=no]))

AH_TEMPLATE([HAVE_UNIX98_PTYS],
	    [Define if a we have working UNIX98 pty handling])
if test x$lsh_cv_sys_unix98_ptys = xyes; then
  AC_DEFINE(HAVE_UNIX98_PTYS)
fi
  
# Check for gcc's __attribute__ construction
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

AH_TEMPLATE([HAVE_GCC_ATTRIBUTE], [Define if the compiler understands __attribute__])
if test "x$lsh_cv_c_attribute" = "xyes"; then
  AC_DEFINE(HAVE_GCC_ATTRIBUTE)
fi

# Check for gcc's __FUNCTION__ variable
AC_CACHE_CHECK(for __FUNCTION__,
	       lsh_cv_c_FUNCTION,
  [ AC_TRY_COMPILE(,
      [ #if __GNUC__ == 3
	#  error __FUNCTION__ is broken in gcc-3
	#endif
        void foo(void) { char c = __FUNCTION__[0]; } ],
      lsh_cv_c_FUNCTION=yes,
      lsh_cv_c_FUNCTION=no)])

AH_TEMPLATE([HAVE_GCC_FUNCTION],
	    [Define if the compiler understands __FUNCTION__])
if test "x$lsh_cv_c_FUNCTION" = "xyes"; then
  AC_DEFINE(HAVE_GCC_FUNCTION)
fi

AC_MSG_CHECKING(for BSD pty names)

AH_TEMPLATE([PTY_BSD_SCHEME_FIRST_CHARS],
	    [Possible first characters in a /dev/ptyXX name])
AH_TEMPLATE([PTY_BSD_SCHEME_SECOND_CHARS],
	    [Possible second characters in a /dev/ptyXX name])

# FIXME: What is most portable, tr -d '\n' or tr -d '\012' ?
AC_DEFINE_UNQUOTED(PTY_BSD_SCHEME_FIRST_CHARS, "`ls /dev/pty* | cut -c 9-9 | uniq | tr -d '\n'`")
AC_DEFINE_UNQUOTED(PTY_BSD_SCHEME_SECOND_CHARS, "`ls /dev/pty* | cut -c 10-10 | sort | uniq | tr -d '\n'`")

# FIXME: How can we test if the bsd scheme is likely to work?
AH_TEMPLATE([PTY_BSD_SCHEME], [Traditional BSD pty handling])
AC_DEFINE(PTY_BSD_SCHEME)
AC_MSG_RESULT([done])

# IPv6 support

if test x$enable_ipv6 = xyes ; then
  if test x$ac_cv_func_getaddrinfo != xyes ; then
    AC_MSG_WARN([getaddrinfo not found. Disabling IPv6 support])
    enable_ipv6=no
  elif test x$ac_cv_func_gai_strerror != xyes ; then
    AC_MSG_WARN([gai_strerror not found. Disabling IPv6 support])
    enable_ipv6=no
  elif test x$lsh_cv_sys_ai_numerichost != xyes ; then
    AC_MSG_WARN([AI_NUMERICHOST not defined. Disabling IPv6 support])
    enable_ipv6=no
  fi
fi

AH_TEMPLATE([WITH_IPV6], [For Ipv6 support])
if test x$enable_ipv6 = xyes ; then
  AC_DEFINE(WITH_IPV6)
fi

AC_CONFIG_SUBDIRS(src/argp)
AC_CONFIG_SUBDIRS(src/nettle)
AC_CONFIG_SUBDIRS(src/sftp)

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

# Don't enable -Wcast-align as it results in tons of warnings in the
# DES code. And when using stdio.
# Don't enable -Waggregate-return, as that causes warnings for glibc
# inttypes.h.

fi

AC_CONFIG_FILES([Makefile doc/Makefile misc/Makefile
	  src/Makefile src/scm/Makefile
	  src/testsuite/Makefile src/rsync/Makefile
	  src/nettle/Makefile
	  contrib/Makefile contrib/lsh.spec])
AC_OUTPUT
