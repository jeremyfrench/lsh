# Testsuite

TESTS = des-test
# SUFFIXES = .c .o
noinst_PROGRAMS = $(TESTS)

LDADD = ../liblsh.a ../symmetric/libsymmetric.a

EXTRA_DIST = macros.m4 $(SOURCES:.c=.m4)

all:
	@echo make check to build testprograms.

%.c: macros.m4 %.m4
	$(M4) -s -P $^ > $@

