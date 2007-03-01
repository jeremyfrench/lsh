# Process this file with automake to produce Makefile.in

SUBDIRS = argp rsync nettle scm sftp spki . testsuite

include .dist_classes
include .dist_headers

BUILT_SOURCES = environ.h

# Kludge needed for finding the nettle/nettle-types.h file in the build tree
AM_CPPFLAGS = -I./nettle

SCHEME = $(SCHEME_PROGRAM) -l $(srcdir)/scm/$(SCHEME_NAME)-compat.scm

EXTRA_PROGRAMS = lsh-krb-checkpw lsh-pam-checkpw srp-gen

# @SRP_PROGRAM@ are broken at the moment
bin_PROGRAMS = lsh lsh-transport lsh-keygen lsh-writekey lsh-decrypt-key \
	       lsh-decode-key lsh-export-key lsh-make-seed
	       

sbin_PROGRAMS = lshd lshd-userauth lshd-connection lshd-pty-helper \
	@KRB_PROGRAM@ @PAM_PROGRAM@

bin_SCRIPTS = lsh-authorize ssh-conv lsh-upgrade lsh-upgrade-key lcp lshg
noinst_LIBRARIES = liblsh.a

# Don't use BUILT_SOURCES, as all these files are #included, and can't be
# compiled or dependency checked independently.

generated_sources = atoms_defines.h atoms_gperf.c atoms_table.c \
	packet_types.h

.PHONY: bootstrap

# Not all potential .x files can be generated
bootstrap: $(generated_sources) $(dist_classes)
	(cd spki && $(MAKE) bootstrap)

# Old files:
#
# client_keyexchange.c client_userauth.c connection_commands.c
# 
# read_packet.c write_packet.c
# client_x11.c server_x11.c tcpforward_commands.c

# Obsoleted files: read_data.c read_file.c read_line.c abstract_io.c
# write_buffer.c channel_commands.c string_buffer.c handshake.c
# lshd_keyexchange.c debug.c gateway_commands.c lshg.c


liblsh_a_SOURCES = algorithms.c alist.c arglist.c atoms.c \
	channel.c channel_io.c channel_forward.c \
	charset.c \
	client.c client_escape.c \
	client_pty.c client_session.c client_tcpforward.c \
	combinators.c command.c compress.c \
	connection.c \
	crypto.c \
	daemon.c \
	dh_exchange.c \
	dsa.c \
	encrypt.c \
	exception.c \
	format.c gc.c \
	interact.c io.c io_commands.c \
	gateway.c gateway_channel.c \
	keyexchange.c \
	list.c \
	lock_file.c \
	lsh_string.c parse.c \
	parse_config.c \
	pkcs5.c \
	pty-helper.c \
	queue.c \
	randomness.c \
	reaper.c resource.c \
	rsa.c \
	server.c \
	server_pty.c server_session.c server_tcpforward.c \
	server_config.c \
	service_read.c \
	sexp.c socks.c \
	spki.c srp_exchange.c \
	ssh_read.c ssh_write.c \
	suspend.c \
	tcpforward.c \
	tokenize_config.c \
	translate_signal.c tty.c \
	unix_interact.c unix_process.c unix_random.c \
	werror.c \
	xalloc.c xauth.c zlib.c

liblsh_a_LIBADD = @LIBOBJS@

# config_parse.c: config_parse.y
# 	bison $< -o $@T
# 	test -s $@T && mv -f $@T $@

# FIXME: Won't work if the filename contains `,', `\', `"' or newline.
# NOTE: This rule is used by non-maintainer builds, so avoid using
# $< and $@ which are only available with GNU make.
environ.h: environ.h.in Makefile
	(echo '/* Automatically generated from environ.h.in, by make. */' ; \
	sed -e 's,@''prefix@,$(prefix),' \
	    -e 's,@''bindir@,$(bindir),' \
	    -e 's,@''sbindir@,$(sbindir),' \
	    -e 's,@''libexecdir@,$(libexecdir),' \
	    -e 's,@''sysconfdir@,$(sysconfdir),' \
	  < $(srcdir)/environ.h.in) >environ.hT
	test -s environ.hT && mv -f environ.hT environ.h

atoms_defines.h: atoms.in process_atoms
	$(srcdir)/process_atoms header <$< >$@T
	test -s $@T && mv -f $@T $@

# With the next version of gperf, add -F ", 0"
GPERF_FLAGS = -LANSI-C -t -c -C -l -k1,3,6,10,21,$$ -N gperf_atom 
atoms_gperf.c: atoms.in process_atoms
	$(srcdir)/process_atoms gperf <$< \
             | gperf $(GPERF_FLAGS) | sed 's/{""}/{"", 0}/g' >$@T 
	test -s $@T && mv -f $@T $@

atoms_table.c: atoms.in process_atoms
	$(srcdir)/process_atoms table <$< >$@T
	test -s $@T && mv -f $@T $@

packet_types.h: ssh.h invert-defs
	$(srcdir)/invert-defs <$< >$@T
	test -s $@T && mv -f $@T $@

lsh_krb_checkpw_LDADD=@KRB_LIBS@

LDADD = liblsh.a spki/libspki.a nettle/libnettle.a @LIBARGP@

# FIXME: We still link with gmp and zlib, to avoid that we'd need to
# remove them from LIBS. The only libraries really needed by
# non-transport programs are liboop and perhaps libXau.

lshd_pty_helper_SOURCES = lshd-pty-helper.c pty-helper.c 
lshd_pty_helper_LDADD =

lshd_SOURCES = lshd.c transport.c transport_read.c transport_write.c \
	transport_forward.c server_keyexchange.c

lsh_transport_SOURCES = lsh-transport.c transport.c transport_read.c transport_write.c \
	transport_forward.c client_keyexchange.c

class-map: $(srcdir)/make-class-map .dist_classes $(dist_classes)
	cat $(dist_classes) | grep '^CLASS:' \
	| sort | awk -f $(srcdir)/make-class-map > $@

# Is this rule needed?
# all-recursive check-recursive: config.h

EXTRA_DIST = lsh-authorize ssh-conv lcp lshg \
	lsh-upgrade lsh-upgrade-key \
	atoms.in process_atoms \
	environ.h.in \
	invert-defs \
	$(generated_sources) \
	sexp_chars.in \
	$(dist_headers) $(dist_classes)

CLEANFILES = *.hT *.cT *.xT
DISTCLEANFILES = environ.h
MAINTAINERCLEANFILES = $(dist_classes) $(DEP_FILES)

# Class files
# SUFFIXES = .xh .xc

.PHONY: gcov-list
gcov-list:
	for f in *.c; do gcov "$$f"; done
	grep -c '##' *.gcov | grep -v ':0$$' | sort -t : -k 2 -nr >gcov-list

.PHONY: depend
depend:
	rm -f $(DEP_FILES)
	make $(DEP_FILES)

# This is GNU make specific

%.x: % $(srcdir)/scm/gaba.scm $(srcdir)/scm/compiler.scm
	$(SCHEME) -e main -l $(srcdir)/scm/compiler.scm \
		  -s $(srcdir)/scm/gaba.scm <$< >$@T
	test -s $@T && mv -f $@T $@

ETAGS_ARGS = -r '/     (name[ \t]+\([a-zA-Z0-9_]+\)/\1/' \
             -r '/DEFINE[^(]*(\([a-zA-Z0-9_]+\)/\1/'

