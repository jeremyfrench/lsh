# Process this file with automake to produce Makefile.in

SUBDIRS = argp rsync nettle scm sftp spki . testsuite

include .dist_classes
include .dist_headers

BUILT_SOURCES = environ.h

# AUTOMAKE_OPTIONS = foreign

# # To remake all Makefile.am-files, run
# #
# # 	./make_am
# #
# # You should run ./make_am --rethink after recompiling, but before
# # making a dist, as it uses dependency information to figure out which
# # header files should be included in th dist. How to tell this to
# # make? FIXME: These rules won't remake Makefile.am files in
# # subdrectries.
# 
# # FIXME: Use the BASH variable to execute the script. The problem is
# # that the script attempts to start itself with "$0 args".
# 
# Makefile.am: Makefile.am.in
# 	(cd $(top_srcdir) && $(MAKE) src/Makefile.am)

SCHEME = $(SCHEME_PROGRAM) -l $(srcdir)/scm/$(SCHEME_NAME)-compat.scm

EXTRA_PROGRAMS = lsh-krb-checkpw lsh-pam-checkpw srp-gen

bin_PROGRAMS = lsh lshg lsh-keygen lsh-writekey lsh-decrypt-key \
	       lsh-decode-key lsh-export-key lsh-make-seed \
	       @SRP_PROGRAM@

sbin_PROGRAMS = lshd lsh-execuv @KRB_PROGRAM@ @PAM_PROGRAM@
bin_SCRIPTS = lsh-authorize ssh-conv lsh-upgrade lsh-upgrade-key
noinst_PROGRAMS = pkcs5-test
noinst_SCRIPTS = lcp
noinst_LIBRARIES = liblsh.a

# Don't use BUILT_SOURCES, as all these files are #included, and can't be
# compiled or dependency checked independently.

generated_sources = atoms_defines.h atoms_gperf.c atoms_table.c \
	packet_types.h

# BUILT_SOURCES = config_parse.c

.PHONY: bootstrap

# Not all potential .x files can be generated
bootstrap: $(generated_sources) $(dist_classes)
	(cd spki && $(MAKE) bootstrap)

liblsh_a_SOURCES = abstract_io.c abstract_crypto.c abstract_compress.c \
	algorithms.c alist.c atoms.c \
	bignum.c \
	channel.c channel_commands.c channel_forward.c \
	charset.c \
	client.c client_escape.c client_keyexchange.c \
	client_pty.c client_session.c client_userauth.c client_x11.c \
	combinators.c command.c compress.c \
	parse_config.c connection.c connection_commands.c \
	crypto.c \
	daemon.c \
	debug.c dh_exchange.c \
	dsa.c dsa_keygen.c encrypt.c \
	exception.c \
	format.c gc.c \
	gateway.c gateway_channel.c gateway_commands.c \
	handshake.c \
	interact.c io.c io_commands.c \
	keyexchange.c \
	list.c lookup_verifier.c \
	lock_file.c \
	pad.c parse.c \
	pkcs5.c \
	publickey_crypto.c queue.c \
	randomness.c \
	read_data.c read_file.c read_line.c read_packet.c \
	reaper.c resource.c \
	rsa.c rsa_keygen.c \
	server.c server_authorization.c server_keyexchange.c \
	server_password.c server_publickey.c \
	server_pty.c server_session.c server_userauth.c \
	server_x11.c sexp.c \
	spki.c srp_exchange.c ssh1_fallback.c \
	string_buffer.c suspend.c \
	tcpforward.c tcpforward_commands.c \
	translate_signal.c tty.c \
	unix_interact.c unix_process.c unix_random.c unix_user.c \
	unpad.c userauth.c \
	werror.c write_buffer.c xalloc.c xauth.c zlib.c

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

# # FIXME: Generate these dependencies in some other way.
# client.o: environ.h
# 
# client_pty.o: environ.h
# 
# gateway.o: environ.h
# 
# lshd.o: environ.h
# 
# lsh-keygen.o: environ.h
# 
# lsh-make-seed.o: environ.h
# 
# lsh.o: environ.h
# 
# lsh-writekey.o: environ.h
# 
# server_session.o: environ.h
# 
# server_x11.o: environ.h
# 
# srp-gen.o: environ.h
# 
# unix_random: environ.h
# 
# unix_user: environ.h

atoms_defines.h: atoms.in process_atoms
	$(BASH) $(srcdir)/process_atoms header <$< >$@T
	test -s $@T && mv -f $@T $@

# With the next version of gperf, add -F ", 0"
GPERF_FLAGS = -LANSI-C -t -c -C -l -k1,3,6,10,$$ -N gperf_atom 
atoms_gperf.c: atoms.in process_atoms
	$(BASH) $(srcdir)/process_atoms gperf <$< \
             | gperf $(GPERF_FLAGS) | sed 's/{""}/{"", 0}/g' >$@T 
	test -s $@T && mv -f $@T $@

atoms_table.c: atoms.in process_atoms
	$(BASH) $(srcdir)/process_atoms table <$< >$@T
	test -s $@T && mv -f $@T $@

PRIME_LIMIT = 1024

# We don't want an explicit dependency on the executable program
# prime_table.h: prime_table.c
# 	$(MAKE) prime_table
# 	./prime_table $(PRIME_LIMIT) >$@T
# 	test -s $@T && mv -f $@T $@
# 
# prime_table_LDADD =

sexp_table.h: sexp_chars.in $(srcdir)/scm/make-char-classes.scm
	$(SCHEME) -e main -s $(srcdir)/scm/make-char-classes.scm <$< >$@T
	test -s $@T && mv -f $@T $@

# digit_table_LDADD =
# 
# # We don't want an explicit dependency on the executable program
# digit_table.h: digit_table.c
# 	$(MAKE) digit_table
# 	./digit_table >$@T
# 	test -s $@T && mv -f $@T $@

packet_types.h: ssh.h invert-defs
	$(srcdir)/invert-defs <ssh.h >$@T
	test -s $@T && mv -f $@T $@

lsh_krb_checkpw_LDADD=@KRB_LIBS@

lsh_execuv_LDADD=

# typedescr.h: ssh.h $(top_srcdir)/misc/mk-reverse-table
# 	  $(PERL) $(top_srcdir)/misc/mk-reverse-table ssh.h >$@T
# 	  if test -s $@T ; then mv -f $@T $@ ; else touch $@ ; fi

LDADD = liblsh.a spki/libspki.a nettle/libnettle.a @LIBARGP@

# lshg needs ssh_format, which need bignum functions from nettle.
# lshg_LDADD = liblsh.a @LIBARGP@

class-map: $(srcdir)/make-class-map $(dist_classes)
	cat $(dist_classes) | grep '^CLASS:' \
	| sort | awk -f $(srcdir)/make-class-map > $@

# Is this rule needed?
# all-recursive check-recursive: config.h

EXTRA_DIST = lsh-authorize ssh-conv lcp \
	lsh-upgrade lsh-upgrade-key \
	atoms.in process_atoms \
	environ.h.in \
	invert-defs \
	$(generated_sources) \
	sexp_chars.in \
	jpoll.h jpoll.c \
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

