
# FIXME: Create a link to nettle directory instead?
AM_CPPFLAGS = -O0 -I$(top_srcdir) -I$(top_srcdir)/..
AM_LDFLAGS = -L../../nettle

TS_PROGS = principal-test date-test tag-test read-acl-test \
	   lookup-acl-test read-cert-test cdsa-reduce-test

TS_SH = check-signature-test

TS_ALL = $(TS_PROGS) $(TS_SH)

noinst_PROGRAMS = $(TS_PROGS)

LDADD = testutils.o ../libspki.a -lnettle

include .dist_cdsa

EXTRA_DIST = testutils.c testutils.h $(TS_SH) \
	run-tests $(dist_cdsa) 

DISTCLEANFILES = test.in

all:
	@echo make check to build testprograms.

.PHONY: check

check: $(TS_ALL)
	LD_LIBRARY_PATH=../../nettle/.lib srcdir=$(srcdir) \
		$(srcdir)/run-tests $(TS_ALL)

