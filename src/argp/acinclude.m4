dnl AC_CHECK_VAR(VAR, TYPE)
AC_DEFUN(AC_CHECK_VAR,
[ AC_CACHE_CHECK(
    [for $1],
    argp_cv_var_$1,
    AC_TRY_LINK(, [extern $2 $1; void *p = (void *) &$1;],
		[argp_cv_var_$1=yes],
		[argp_cv_var_$1=no]))
  if eval "test \"`echo '$argp_cv_var_'$1`\" = yes"; then
    AC_DEFINE_UNQUOTED(HAVE_`echo $1 | tr 'abcdefghijklmnopqrstuvwxyz' 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'`)
  fi
])
