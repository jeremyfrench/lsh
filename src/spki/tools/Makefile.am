noinst_PROGRAMS = spki-check-signature

# FIXME: Create a link to nettle directory instead?
AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/..
AM_LDFLAGS = -L.. -L../../nettle/

# libnettle.a and libspki.a are added at the end to make sure all
# programs depend on it. It seems there's no DEPENDENCIES variable
# that affects all programs.

LDADD = -lspki -lnettle ../libspki.a ../../nettle/libnettle.a
