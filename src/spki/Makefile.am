SUBDIRS = . testsuite

# FIXME: Create a link to nettle directory instead?
AM_CPPFLAGS = -I$(srcdir)/..

noinst_LIBRARIES = libspki.a
# libspkiincludedir = $(includedir)/nettle

libspki_a_SOURCES = certificate.c parse.c

# Does this get $(srcdir) right? Uses GNU make features
spki-types.h: spki-types.in process-types
	$(srcdir)/process-types header < $< > $(srcdir)/$(@F)T
	test -s $(srcdir)/$(@F)T && mv -f $(srcdir)/$(@F)T $(srcdir)/$(@F)

spki-type-names.h: spki-types.in process-types
	$(srcdir)/process-types names < $< > $(srcdir)/$(@F)T
	test -s $(srcdir)/$(@F)T && mv -f $(srcdir)/$(@F)T $(srcdir)/$(@F)

GPERF_FLAGS = -LANSI-C -t -c -C -l -E -o -k1,$$ -N spki_gperf

spki-gperf.h: spki-types.in process-types
	$(srcdir)/process-types gperf < $< | tee spki-gperf.in \
		| gperf $(GPERF_FLAGS) | sed 's/{""}/{"", 0}/g' \
		> $(srcdir)/$(@F)T
	test -s $(srcdir)/$(@F)T && mv -f $(srcdir)/$(@F)T $(srcdir)/$(@F)

EXTRA_DIST = spki-types.in spki-types.h spki-gperf.h spki-type-names.h

.PHONY: bootstrap
bootstrap: spki-types.h spki-gperf.h spki-type-names.h
