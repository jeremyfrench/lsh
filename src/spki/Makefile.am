SUBDIRS = . testsuite

# FIXME: Create a link to nettle directory instead?
AM_CPPFLAGS = -I$(srcdir)/..

noinst_LIBRARIES = libspki.a
# libspkiincludedir = $(includedir)/nettle

libspki_a_SOURCES = certificate.c parse.c

# Does this get $(srcdir) right?
$(srcdir)/spki-types.h: spki-types.in process-types
	$(srcdir)/process-types header < $< > $@T
	test -s $@T && mv -f $@T $@

$(srcdir)/spki-type-names.h: spki-types.in process-types
	$(srcdir)/process-types names < $< > $@T
	test -s $@T && mv -f $@T $@

GPERF_FLAGS = -LANSI-C -t -c -C -l -E -o -k1,$$ -N spki_gperf

$(srcdir)/spki-gperf.h: spki-types.in process-types
	$(srcdir)/process-types gperf < $< | tee spki-gperf.in \
		| gperf $(GPERF_FLAGS) | sed 's/{""}/{"", 0}/g' \
		> $@T
	test -s $@T && mv -f $@T $@

EXTRA_DIST = spki-types.in spki-types.h spki-gperf.h spki-type-names.h

.PHONY: bootstrap
bootstrap: spki-types.h spki-gperf.h spki-type-names.h
