#! /bin/sh

# Build all automatically generated files that are not present in the
# CVS repository.

# This script is for use in the build directory, after you have run
# configure to create the needed Makefiles.

(cd src && for f in *.h *.c; do make $f.x; done)
rm -f src/*.xT
(cd src && make atoms_defines.h atoms_gperf.c atoms_table.c \
	   prime_table.h sexp_table.h digit_table.h packet_types.h)
