
# FIXME: Create a link to nettle directory instead?
AM_CFLAGS = -O0 -I$(top_srcdir) -I$(top_srcdir)/..
AM_LDFLAGS = -L..

TS_PROGS = subject-test
TS_SH =

TS_ALL = $(TS_PROGS) $(TS_SH)

noinst_PROGRAMS = $(TS_PROGS)

LDADD = ../libspki.a -lnettle

EXTRA_DIST = testutils.c testutils.h $(TS_SH) \
	functions.sh run-tests setup-env key-1.private key-2.private \
	fake-sshd1

CLEANFILES =

all:
	@echo make check to build testprograms.

.PHONY: check

check: $(TS_ALL)
	srcdir=$(srcdir) $(srcdir)/run-tests $(TS_ALL)

