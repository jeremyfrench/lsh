# Testsuite

TS_PROGS = des-test spki-tag-test
TS_SH = keygen-test
TESTS = $(TS_PROGS) $(TS_SH)

# SUFFIXES = .c .o
noinst_PROGRAMS = $(TS_PROGS)

LDADD = ../liblsh.a ../symmetric/libsymmetric.a

EXTRA_DIST = macros.m4 $(SOURCES:.c=.m4) $(TS_SH)

all:
	@echo make check to build testprograms.

M4FLAGS = -P #-s
%.c: macros.m4 %.m4
	$(M4) $(M4FLAGS) $^ > $@

