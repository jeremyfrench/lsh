dnl AC_CHECK_MEMBER(includes, struct, field)
AC_DEFUN(AC_CHECK_MEMBER,
[ AC_CACHE_CHECK([if $2 has member $3],
    lsh_cv_decl_struct_$2_$3,
    [AC_TRY_COMPILE([$1],
changequote(<{, }>)dnl
      <{ struct $2 x; (void) &x.$3; }>,
changequote([, ])dnl
      [lsh_cv_decl_struct_$2_$3=yes],
      [lsh_cv_decl_struct_$2_$3=no])])
  if test x$lsh_cv_decl_struct_$2_$3 = xyes; then
    AC_DEFINE_UNQUOTED(`echo HAVE_$3 | tr 'abcdefghijklmnopqrstuvwxyz' 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'`)
  fi
])

dnl AC_CHECK_VAR(VAR, INCLUDES)
AC_DEFUN(AC_CHECK_VAR,
[ AC_CACHE_CHECK(
    [for $1],
    lsh_cv_var_$1,
    AC_TRY_LINK([$2], [void *p = (void *) &$1;],
		[lsh_cv_var_$1=yes],
		[lsh_cv_var_$1=no]))
  if eval "test \"`echo '$lsh_cv_var_'$1`\" = yes"; then
    AC_DEFINE_UNQUOTED(HAVE_`echo $1 | tr 'abcdefghijklmnopqrstuvwxyz' 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'`)
  fi
])

dnl Try to detect the type of the third arg to getsockname() et al
AC_DEFUN(AC_TYPE_SOCKLEN_T,
[AC_CACHE_CHECK([for socklen_t in sys/socket.h], ac_cv_type_socklen_t,
[AC_EGREP_HEADER(socklen_t, sys/socket.h,
  [ac_cv_type_socklen_t=yes], [ac_cv_type_socklen_t=no])])
if test $ac_cv_type_socklen_t = no; then
        AC_MSG_CHECKING(for AIX)
        AC_EGREP_CPP(yes, [
#ifdef _AIX
 yes
#endif
],[
AC_MSG_RESULT(yes)
AC_DEFINE(socklen_t, size_t)
],[
AC_MSG_RESULT(no)
AC_DEFINE(socklen_t, int)
])
fi
])

dnl checks for gmp version 2 or later. 
dnl AC_CHECK_LIBGMP(library, [, if-found [, if-not-found]])
AC_DEFUN(AC_CHECK_LIBGMP,
[AC_CACHE_CHECK([for mpz_get_d in -l$1], ac_cv_lib_$1_mpz_get_d,
[ac_save_libs="$LIBS"
LIBS="-l$1 $LIBS"
AC_TRY_LINK(dnl
[#include <gmp.h>
],
[mpz_get_d(0);],
ac_cv_lib_$1_mpz_get_d=yes,
ac_cv_lib_$1_mpz_get_d=no)
LIBS="$ac_save_LIBS"
])
if test x$ac_cv_lib_$1_mpz_get_d = xyes ; then
ifelse([$2], ,
[AC_DEFINE(HAVE_LIBGMP)
LIBS="-l$1 $LIBS"
], [$2])
ifelse([$3], , ,
[else
$3
])dnl
fi
])

dnl checks for gmp version 2 or later. 
dnl AC_SEARCH_LIBGMP(libraries, [, if-found [, if-not-found]])
AC_DEFUN(AC_SEARCH_LIBGMP,
[AC_CACHE_CHECK([for library containing mpz_get_d], ac_cv_search_mpz_get_d,
[ac_search_save_LIBS="$LIBS"
ac_cv_search_mpz_get_d="no"
for i in $1; do
LIBS="-l$i $LIBS"
AC_TRY_LINK(dnl
[#include <gmp.h>
],
[mpz_get_d(0);],
[ac_cv_search_mpz_get_d=-l$i
break
])
done
LIBS="$ac_search_save_LIBS"
])
if test "x$ac_cv_search_mpz_get_d" != xno ; then
  LIBS="$ac_cv_search_mpz_get_d $LIBS"
ifelse([$2], ,
[AC_DEFINE(HAVE_LIBGMP)
], [$2])
ifelse([$3], , ,
[else
$3
])dnl
fi
])

dnl LSH_PATH_ADD(path-id, directory)
AC_DEFUN(LSH_PATH_ADD,
[AC_MSG_CHECKING($2)
ac_exists=no
if test -d "$2/." ; then
  ac_real_dir=`cd $2 && pwd`
  if test -n "$ac_real_dir" ; then
    ac_exists=yes
    for old in $1_REAL_DIRS ; do
      ac_found=no
      if test x$ac_real_dir = x$old ; then
        ac_found=yes;
	break;
      fi
    done
    if test $ac_found = yes ; then
      AC_MSG_RESULT(already added)
    else
      AC_MSG_RESULT(added)
      # LIBS="$LIBS -L $2"
      $1_REAL_DIRS="$ac_real_dir [$]$1_REAL_DIRS"
      $1_DIRS="$2 [$]$1_DIRS"
    fi
  fi
fi
if test $ac_exists = no ; then
  AC_MSG_RESULT(not found)
fi
])

dnl LSH_RPATH_ADD(dir)
AC_DEFUN(LSH_RPATH_ADD, [LSH_PATH_ADD(RPATH_CANDIDATE, $1)])

dnl LSH_RPATH_INIT(candidates)
AC_DEFUN(LSH_RPATH_INIT,
[AC_MSG_CHECKING([for -R flag])
RPATHFLAG=''
case `uname -sr` in
  OSF1\ V4.*)
    RPATHFLAG="-rpath "
    ;;
  IRIX\ 6.*)
    RPATHFLAG="-rpath "
    ;;
  IRIX\ 5.*)
    RPATHFLAG="-rpath "
    ;;
  SunOS\ 5.*)
    if test "$TCC" = "yes"; then
      # tcc doesn't know about -R
      RPATHFLAG="-Wl,-R,"
    else
      RPATHFLAG=-R
    fi
    ;;
  Linux\ 2.*)
    RPATHFLAG="-Wl,-rpath,"
    ;;
  *)
    :
    ;;
esac

if test x$RPATHFLAG = x ; then
  AC_MSG_RESULT(none)
else
  AC_MSG_RESULT([using $RPATHFLAG])
fi

RPATH_CANDIDATE_REAL_DIRS=''
RPATH_CANDIDATE_DIRS=''

AC_MSG_RESULT([Searching for libraries])

for d in $1 ; do
  LSH_RPATH_ADD($d)
done
])    

dnl Try to execute a main program, and if it fails, try adding some
dnl -R flag.
dnl LSH_RPATH_FIX
AC_DEFUN(LSH_RPATH_FIX,
[if test $cross_compiling = no -a "x$RPATHFLAG" != x ; then
  ac_success=no
  AC_TRY_RUN([int main(int argc, char **argv) { return 0; }],
    ac_success=yes, ac_success=no, :)
  
  if test $ac_success = no ; then
    AC_MSG_CHECKING([Running simple test program failed. Trying -R flags])
dnl echo RPATH_CANDIDATE_DIRS = $RPATH_CANDIDATE_DIRS
    ac_remaining_dirs=''
    ac_rpath_save_LIBS="$LIBS"
    for d in $RPATH_CANDIDATE_DIRS ; do
      if test $ac_success = yes ; then
  	ac_remaining_dirs="$ac_remaining_dirs $d"
      else
  	LIBS="$RPATHFLAG$d $LIBS"
dnl echo LIBS = $LIBS
  	AC_TRY_RUN([int main(int argc, char **argv) { return 0; }],
  	  [ac_success=yes
  	  ac_rpath_save_LIBS="$LIBS"
  	  AC_MSG_RESULT([adding $RPATHFLAG$d])
  	  ],
  	  [ac_remaining_dirs="$ac_remaining_dirs $d"], :)
  	LIBS="$ac_rpath_save_LIBS"
      fi
    done
    RPATH_CANDIDATE_DIRS=$ac_remaining_dirs
  fi
  if test $ac_success = no ; then
    AC_MSG_RESULT(failed)
  fi
fi
])
