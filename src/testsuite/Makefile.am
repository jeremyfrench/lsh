# Testsuite

TESTS = des-test
# SUFFIXES = .c .o
noinst_PROGRAMS = $(TESTS)

LDADD = ../liblsh.a ../symmetric/libsymmetric.a

all:
	@echo make check to build testprograms.

%.c: macros.m4 %.m4
	m4 -s -P $^ > $@

