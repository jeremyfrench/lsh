# Process this file with automake to produce Makefile.in

noinst_LIBRARIES = librsync.a
noinst_HEADERS = rsync.h

# Needed for finding the nettle include files in the source tree
# and nettle-stdint.h in the build tree.
AM_CPPFLAGS = -I$(srcdir)/.. -I../nettle

librsync_a_SOURCES = generate.c receive.c checksum.c send.c


