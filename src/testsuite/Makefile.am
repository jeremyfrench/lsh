# Testsuite

AM_CFLAGS = -O0

# Tests that can be used without any special setup.
TS_PROGS = arcfour-test aes-test blowfish-test cast128-test \
	   des-test \
	   serpent-test twofish-test \
           md5-test sha1-test rsa-test dsa-test spki-tag-test \
           string-test parse-config-test

TS_SH = conv-1-test conv-2-test conv-3-test \
	export-1-test keygen-1-test keygen-2-test \
	write-key-1-test write-key-2-test seed-test \
	lsh-1-test lsh-2-test lsh-3-test lsh-4-test \
	lsh-5-test lsh-6-test lsh-7-test lsh-8-test lsh-9-test \
	lsh-cat-test lshg-1-test lshg-cat-test lshg-cat-2-test \
	tcpip-local-test tcpip-remote-test \
	lshg-tcpip-local-test ssh1-fallback-test

TS_ALL = $(TS_PROGS) $(TS_SH)

# Don't use automakes testsuite support
# TESTS = $(TS_PROGS) $(TS_SH)

# SUFFIXES = .c .o
noinst_PROGRAMS = $(TS_PROGS)

LDADD = testutils.o ../liblsh.a ../nettle/libnettle.a \
	$(addprefix ../,@LIBARGP@)

EXTRA_DIST = testutils.c testutils.h $(TS_SH) \
	functions.sh run-tests setup-env key-1.private key-2.private \
	fake-sshd1

# FIXME: Move into some tmp directory.
CLEANFILES = foo foo.pub test-seed-1 test-seed-2 test.out1 test.out2

# Files and directories used by the test cases.
distclean-local:
	rm -rf temphome home *.pid

DISTCLEANFILES = yarrow-seed-file

all:
	@echo make check to build testprograms.

# M4FLAGS = -P #-s
# %.c: macros.m4 %.m4
# 	$(M4) $(M4FLAGS) $^ > $@T
# 	test -s $@T && mv -f $@T $@


.PHONY: check-some check-more

check: $(TS_ALL)
	srcdir=$(srcdir) $(srcdir)/run-tests $(TS_ALL)

