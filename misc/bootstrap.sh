#! /bin/sh

bash make_am
aclocal
autoheader
autoconf
automake -a
./configure
(cd src && for f in *.h *.c; do make $f.x; done)
rm -f src/*.xT
(cd src && make atoms_defines.h atoms_gperf.c atoms_table.c prime_table.h sexp_table.h digit_table.h)
