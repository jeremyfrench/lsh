# Testsuite

TESTS = des-test spki-tag-test
# SUFFIXES = .c .o
noinst_PROGRAMS = $(TESTS)

LDADD = ../liblsh.a ../symmetric/libsymmetric.a

EXTRA_DIST = macros.m4 $(SOURCES:.c=.m4)

all:
	@echo make check to build testprograms.

M4FLAGS = -P #-s
%.c: macros.m4 %.m4
	$(M4) $(M4FLAGS) $^ > $@

