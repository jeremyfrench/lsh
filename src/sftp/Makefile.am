SUBDIRS = . testsuite

AUTOMAKE_OPTIONS = foreign

bin_PROGRAMS = lsftp

sbin_PROGRAMS = sftp-server

noinst_PROGRAMS = sftp-test-client dump-hex

EXTRA_DIST = buffer.h client.h filemode.h idcache.h sftp.h werror.h xmalloc.h

sftp_server_SOURCES = sftp-server.c buffer.c filemode.c idcache.c xmalloc.c

sftp_test_client_SOURCES = sftp-test-client.c buffer.c xmalloc.c werror.c client.c

lsftp_SOURCES = commands.c commands.h lsftp.c rl.c rl.h \
	sftp_c.c sftp_c.h sftp.h sftp_bind.h sftp_bind.c \
	str_utils.c str_utils.h lsftp.h dc.c dc.h \
	gnu_stuff.h gnu_stuff.c misc_fun.c misc_fun.h \
	buffer.c buffer.h xmalloc.c xmalloc.h
