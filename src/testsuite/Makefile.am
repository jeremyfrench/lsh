# Testsuite

AM_CFLAGS = -O0
AM_CPPFLAGS = -I$(srcdir)/..

TS_PROGS = arcfour-test aes-test blowfish-test cast128-test \
	   des-test \
	   serpent-test twofish-test \
           md5-test sha1-test rsa-test dsa-test spki-tag-test \
           string-test parse-config-test sockaddr2info-test

TS_SH = conv-1-test conv-2-test conv-3-test \
	export-1-test keygen-1-test keygen-2-test \
	write-key-1-test write-key-2-test seed-test \
	lsh-1-test lsh-2-test lsh-3-test lsh-4-test \
	lsh-5-test lsh-6-test lsh-7-test lsh-8-test lsh-9-test \
	lsh-cat-test lshg-1-test lshg-cat-test lshg-cat-2-test \
	tcpip-local-test tcpip-remote-test \
	lshg-tcpip-local-test ssh1-fallback-test \
	rapid7-lsh-test rapid7-lshd-test

TS_ALL = $(TS_PROGS) $(TS_SH)

noinst_PROGRAMS = $(TS_PROGS)

LDADD = testutils.o ../liblsh.a ../spki/libspki.a ../nettle/libnettle.a \
	$(addprefix ../,@LIBARGP@)

include .dist_rapid7

EXTRA_DIST = testutils.c testutils.h $(TS_SH) \
	functions.sh run-tests setup-env key-1.private key-2.private \
	fake-sshd1 $(dist_rapid7)

# FIXME: Move into some tmp directory.
CLEANFILES = foo foo.pub test-seed-1 test-seed-2 test.out1 test.out2

# Files and directories used by the test cases.
distclean-local:
	rm -rf temphome home *.pid

DISTCLEANFILES = yarrow-seed-file

all:
	@echo make check to build testprograms.

.PHONY: check-some check-more

# sexp-conv may be dynamically linked
check: $(TS_ALL)
	LD_LIBRARY_PATH="`pwd`/../nettle/.lib" srcdir=$(srcdir) \
		$(srcdir)/run-tests $(TS_ALL)

