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

dnl AC_CHECK_LIBGMP(library, [, if-found [, if-not-found]])
AC_DEFUN(AC_CHECK_LIBGMP,
[AC_CACHE_CHECK([for mpz_get_d in -l$1], ac_cv_lib_$1_mpz_get_d,
[ac_save_libs="$LIBS"
LIBS="-l$1 $LIBS"
AC_TRY_LINK(dnl
[#if HAVE_GMP_H
#include <gmp.h>
#else
double mpz_get_d();
#endif
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
else
ifelse([$3], , , [$3
])dnl
fi
])

dnl   dnl LSH_CHECK_LIB(library, symbol, includes [, if-found [, if-not-found
dnl   dnl               [, other-libraries]]])
dnl   AC_DEFUN(AC_CHECK_LIB,
dnl   [AC_MSG_CHECKING([for $2 in -l$1])
dnl   dnl Use a cache variable name containing both the library and function name,
dnl   dnl because the test really is for library $1 defining function $2, not
dnl   dnl just for library $1.  Separate tests with the same $1 and different $2s
dnl   dnl may have different results.
dnl   ac_lib_var=`echo $1['_']$2 | sed 'y%./+-%__p_%'`
dnl   AC_CACHE_VAL(ac_cv_lib_$ac_lib_var,
dnl   [ac_save_LIBS="$LIBS"
dnl   LIBS="-l$1 $6 $LIBS"
dnl   AC_TRY_LINK(dnl
dnl   ifelse(AC_LANG, [FORTRAN77], ,
dnl   ifelse([$2], [main], , dnl Avoid conflicting decl of main.
dnl   [/* Override any gcc2 internal prototype to avoid an error.  */
dnl   ]ifelse(AC_LANG, CPLUSPLUS, [#ifdef __cplusplus
dnl   extern "C"
dnl   #endif
dnl   ])dnl
dnl   [/* We use char because int might match the return type of a gcc2
dnl   	  builtin and then its argument prototype would still apply.  */
dnl   char $2();
dnl   ])
dnl   [$3]dnl User's includes 
dnl   ),
dnl   		  [$2()],
dnl   		  eval "ac_cv_lib_$ac_lib_var=yes",
dnl   		  eval "ac_cv_lib_$ac_lib_var=no")
dnl   LIBS="$ac_save_LIBS"
dnl   ])dnl
dnl   if eval "test \"`echo '$ac_cv_lib_'$ac_lib_var`\" = yes"; then
dnl   	AC_MSG_RESULT(yes)
dnl   	ifelse([$4], ,
dnl   [changequote(, )dnl
dnl   	ac_tr_lib=HAVE_LIB`echo $1 | sed -e 's/[^a-zA-Z0-9_]/_/g' \
dnl   	  -e 'y/abcdefghijklmnopqrstuvwxyz/ABCDEFGHIJKLMNOPQRSTUVWXYZ/'`
dnl   changequote([, ])dnl
dnl   	AC_DEFINE_UNQUOTED($ac_tr_lib)
dnl   	LIBS="-l$1 $LIBS"
dnl   ], [$4])
dnl   else
dnl   	AC_MSG_RESULT(no)
dnl   ifelse([$5], , , [$5
dnl   ])dnl
dnl   fi
dnl   ])
dnl   
dnl   dnl LSH_CHECK_LIBGMP(library, symbol, [, if-found [, if-not-found
dnl   dnl                  [, other-libraries]]])
dnl   AC_DEFUN(LSH_CHECK_LIBGMP,
dnl   [AC_MSG_CHECKING([for $2 in -l$1])
dnl   dnl Use a cache variable name containing both the library and function name,
dnl   dnl because the test really is for library $1 defining function $2, not
dnl   dnl just for library $1.  Separate tests with the same $1 and different $2s
dnl   dnl may have different results.
dnl   ac_lib_var=`echo $1['_']$2 | sed 'y%./+-%__p_%'`
dnl   AC_CACHE_VAL(ac_cv_lib_$ac_lib_var,
dnl   [ac_save_LIBS="$LIBS"
dnl   LIBS="-l$1 $5 $LIBS"
dnl   AC_TRY_LINK(dnl
dnl   ifelse(AC_LANG, [FORTRAN77], ,
dnl   ifelse([$2], [main], , dnl Avoid conflicting decl of main.
dnl   dnl  [/* Override any gcc2 internal prototype to avoid an error.  */
dnl   dnl  ]ifelse(AC_LANG, CPLUSPLUS, [#ifdef __cplusplus
dnl   dnl  extern "C"
dnl   dnl  #endif
dnl   dnl  ])
dnl   [/* We need to include gmp header, as most symbols are really macros. */
dnl   #if HAVE_GMP_H
dnl   #include <gmp.h>
dnl   #endif
dnl    /* We use char because int might match the return type of a gcc2
dnl   	  builtin and then its argument prototype would still apply.  */
dnl   char $2();
dnl   ])),
dnl   		  [$2()],
dnl   		  eval "ac_cv_lib_$ac_lib_var=yes",
dnl   		  eval "ac_cv_lib_$ac_lib_var=no")
dnl   LIBS="$ac_save_LIBS"
dnl   ])dnl
dnl   if eval "test \"`echo '$ac_cv_lib_'$ac_lib_var`\" = yes"; then
dnl   	AC_MSG_RESULT(yes)
dnl   	ifelse([$3], ,
dnl   [changequote(, )dnl
dnl   	ac_tr_lib=HAVE_LIB`echo $1 | sed -e 's/[^a-zA-Z0-9_]/_/g' \
dnl   	  -e 'y/abcdefghijklmnopqrstuvwxyz/ABCDEFGHIJKLMNOPQRSTUVWXYZ/'`
dnl   changequote([, ])dnl
dnl   	AC_DEFINE_UNQUOTED($ac_tr_lib)
dnl   	LIBS="-l$1 $LIBS"
dnl   ], [$3])
dnl   else
dnl   	AC_MSG_RESULT(no)
dnl   ifelse([$4], , , [$4
dnl   ])dnl
dnl   fi
dnl   ])
