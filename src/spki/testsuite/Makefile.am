
# FIXME: Create a link to nettle directory instead?
AM_CPPFLAGS = -O0 -I$(top_srcdir) -I$(top_srcdir)/..
AM_LDFLAGS = -L../../nettle

TS_PROGS = principal-test date-test read-acl-test read-cert-test
TS_SH =

TS_ALL = $(TS_PROGS) $(TS_SH)

noinst_PROGRAMS = $(TS_PROGS)

LDADD = testutils.o ../libspki.a -lnettle

EXTRA_DIST = testutils.c testutils.h $(TS_SH) \
	functions.sh run-tests setup-env key-1.private key-2.private \
	fake-sshd1

CLEANFILES =

all:
	@echo make check to build testprograms.

.PHONY: check

check: $(TS_ALL)
	LD_LIBRARY_PATH=../../nettle/.lib srcdir=$(srcdir) \
		$(srcdir)/run-tests $(TS_ALL)

