SUBDIRS = . testsuite

AUTOMAKE_OPTIONS = foreign

bin_PROGRAMS = lsftp

sbin_PROGRAMS = sftp-server

noinst_PROGRAMS = sftp-test-client dump-hex

EXTRA_DIST = buffer.h client.h filemode.h idcache.h sftp.h werror.h xmalloc.h

shared_src = buffer.c buffer.h io_input.c io_output.c io.h \
	     xmalloc.c werror.h werror.c

sftp_server_SOURCES = sftp-server.c $(shared_src) filemode.c idcache.c

sftp_test_client_SOURCES = sftp-test-client.c $(shared_src) client.c

lsftp_SOURCES = commands.c commands.h lsftp.c rl.c rl.h \
	sftp_c.c sftp_c.h sftp.h sftp_bind.h sftp_bind.c \
	str_utils.c str_utils.h lsftp.h dc.c dc.h \
	gnu_stuff.h gnu_stuff.c misc_fun.c misc_fun.h \
	$(shared_src)
