## Process this file with automake to produce Makefile.in

AUTOMAKE_OPTIONS = foreign
SUBDIRS = lib

bin_PROGRAMS = lsh lshd

# Don't use BUILT_SOURCES, as all these files are #included, and can't be
# compiled or dependency checked independently.

generated_sources = atoms_defines.h atoms_gperf.c atoms_table.c

common_sources = alist.c atoms.c bignum.c channel.c \
	charset.c connection.c crypto.c \
	debug.c disconnect.c encrypt.c format.c getopt.c io.c keyexchange.c \
	packet_ignore.c pad.c parse.c publickey_crypto.c \
	randomness.c \
	read_data.c read_line.c read_packet.c service.c \
	translate_signal.c unpad.c \
	werror.c write_buffer.c xalloc.c

lsh_SOURCES = $(common_sources) lsh.c client.c client_keyexchange.c \
	client_password.c client_userauth.c

lshd_SOURCES = $(common_sources) lshd.c reaper.c server.c server_keyexchange.c \
	server_password.c server_userauth.c

atoms_defines.h: atoms.in process_atoms
	bash process_atoms header <atoms.in >atoms_defines.h

atoms_gperf.c: atoms.in process_atoms Makefile
	bash process_atoms gperf <atoms.in \
             | gperf -t -c -l -k1,7,$$ -N gperf_atom >atoms_gperf.c

atoms_table.c: atoms.in process_atoms
	bash process_atoms table <atoms.in >atoms_table.c

LDADD = @LIBOBJS@ lib/libsymmetric.a

lsh_DEPENDENCIES = @LIBOBJS@ symmetric
lshd_DEPENDENCIES = @LIBOBJS@ symmetric

.PHONY: symmetric
symmetric:
	(cd lib && $(MAKE) libsymmetric.a)

EXTRA_DIST = atoms.in process_atoms $(generated_sources) HACKING

