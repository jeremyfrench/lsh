CC=gcc
CFLAGS = -O2 -ggdb3 -Wall
CPPFLAGS = -DHAVE_CONFIG_H -I.. -I../..

OBJS = buffer.o
HEADERS = buffer.h

all: sftp-server sftp-test-client

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $<

%: %.o $(OBJS)
	$(CC) -o $@ $^

# sftp-server: sftp-server.o buffer.o
# sftp-server: sftp-server.o buffer.o
# 
# sftp-server.o: sftp-server.c buffer.h
