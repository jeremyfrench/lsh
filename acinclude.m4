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
[AC_CACHE_CHECK(for socklen_t in sys/socket.h, ac_cv_type_socklen_t,
[AC_EGREP_HEADER(socklen_t, sys/socket.h,
  ac_cv_type_socklen_t=yes, ac_cv_type_socklen_t=no)])
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
