/* -*- mode: c; c-style: bsd; c-basic-offset: 8 -*-
 *
 * Copyright (c) 2000 Markus Friedl, Niels Möller.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <errno.h>

#ifdef OPENSSH
#include "includes.h"
RCSID("$OpenBSD: sftp-server.c,v 1.10 2001/01/10 22:56:22 markus Exp $");

#include "ssh.h"
#include "buffer.h"
#include "bufaux.h"
#include "getput.h"
#include "xmalloc.h"

#define INPUT_BUFFER Buffer *
#define OUTPUT_BUFFER Buffer *

/* helper */
#define GET_UINT32(b, v) (*(v) = buffer_get_int((b)))
#define GET_UINT64(b, v) (*(v) = buffer_get_int64((b)))
#define GET_STRING(b, l, d) (*(d) = buffer_get_string((b), (l)))

#define FREE xfree

#if 0
#define get_int64()			buffer_get_int64(&iqueue);
#define get_int()			buffer_get_int(&iqueue);
#define get_string(lenp)		buffer_get_string(&iqueue, lenp);
#endif
#define TRACE				debug

#else /* !OPENSSH */

#include <stdio.h>

struct file_input {
	FILE * f;
	uint32_t left;
};

#define INPUT_BUFFER struct file_input *
#define OUTPUT_BUFFER FILE *

/* FIXME: Ought to use autoconf */
#define u_int64_t unsigned long long
#define u_int32_t unsigned
#define u_int8_t unsigned char

/* Copied from lsh_types.h */
/* Reads a 32-bit integer, in network byte order */
#define READ_UINT32(p)				\
((((u_int32_t) (p)[0]) << 24)			\
 | (((u_int32_t) (p)[1]) << 16)			\
 | (((u_int32_t) (p)[2]) << 8)			\
 | ((u_int32_t) (p)[3]))

#define WRITE_UINT32(p, i)			\
do {						\
  (p)[0] = ((i) >> 24) & 0xff;			\
  (p)[1] = ((i) >> 16) & 0xff;			\
  (p)[2] = ((i) >> 8) & 0xff;			\
  (p)[3] = (i) & 0xff;				\
} while(0)

#define READ_UINT64(p)				\
(  (((u_int64_t) (p)[0]) << 56)
 | (((u_int64_t) (p)[1]) << 48)			\
 | (((u_int64_t) (p)[2]) << 40)			\
 | (((u_int64_t) (p)[3]) << 32)			\
 | (((u_int64_t) (p)[4]) << 24)			\
 | (((u_int64_t) (p)[5]) << 16)			\
 | (((u_int64_t) (p)[6]) << 8)			\
 |  ((u_int64_t) (p)[7]))

#define WRITE_UINT64(p, i)			\
do {						\
  (p)[0] = ((i) >> 56) & 0xff;			\
  (p)[1] = ((i) >> 48) & 0xff;			\
  (p)[2] = ((i) >> 40) & 0xff;			\
  (p)[3] = ((i) >> 32) & 0xff;			\
  (p)[4] = ((i) >> 24) & 0xff;			\
  (p)[5] = ((i) >> 16) & 0xff;			\
  (p)[6] = ((i) >> 8) & 0xff;			\
  (p)[7] =  (i) & 0xff;				\
} while(0)

static int check_left(struct file_input *i, u_int32_t len)
{
	if (i->left < len)
		return 0;

	i->left -= len;
	return 1;
}

define READ_DATA(buf)					\
do {							\
	if (!check_left(i, sizeof(buf)))		\
		return 0;				\
							\
	if (fread(buf, 1, sizeof(buf), i->f) != 4)	\
		return 0;				\
} while(0)
	
static int GET_UINT32(struct file_input *i, u_int32_t *result)
{
	u_int8_t buf[4];

	READ_DATA(buf);

	*result = READ_UINT32(buf);
	return 1;
}

static int GET_UINT64(struct file_input *i, u_int64_t *result)
{
	u_int8_t buf[8];

	READ_DATA(buf);

	*result = READ_UINT64(buf);
	return 1;
}

static int GET_STRING(struct file_input *i, u_int32_t *length,
		      u_int8_t **data)
{
	if (!GET_UINT32(i, length))
		return 0;

	if (!check_left(i, length))
		return 0;

	*data = malloc(length);
	if (!*data)
		return 0;

	if (fread(*data, 1, length, i) != length)
	{
		free(*data);
		return 0;
	}
	return 1;
}

#define FREE free

#define WRITE_DATA(buf) \
(fwrite(buf, 1, sizeof(buf), o) == sizeof(buf))
	
static int PUT_UINT32(FILE *o, u_int32_t value)
{
	u_int8_t buf[4];
	WRITE_UINT32(buf, value);

	return WRITE_DATA(buf);
}

static int PUT_UINT64(FILE *o, u_int64_t value)
{
	u_int8_t buf[8];
	WRITE_UINT64(buf, value);

	return WRITE_DATA(buf);
}

static int PUT_STRING(FILE *o, u_int32_t length, u_int8_t *data)
{
	return PUT_UINT32(o, length)
		&& (fwrite(data, 1, length, o) == length);
}
	
/* GCC extension */
#define TRACE(format, ... args) fprintf(stderr, format, ## args)


#endif /* !OPENSSH */

#include "sftp.h"

#if 0
/* input and output queue */
Buffer iqueue;
Buffer oqueue;
#endif

/* portable attibutes, etc. */

typedef struct Attrib Attrib;
typedef struct Stat Stat;

struct Attrib
{
	u_int32_t	flags;
	u_int64_t	size;
	u_int32_t	uid;
	u_int32_t	gid;
	u_int32_t	perm;
	u_int32_t	atime;
	u_int32_t	mtime;
};

struct Stat
{
	char *name;
	char *long_name;
	Attrib attrib;
};

int
errno_to_portable(int unixerrno)
{
	int ret = 0;
	switch (unixerrno) {
	case 0:
		ret = SSH2_FX_OK;
		break;
	case ENOENT:
	case ENOTDIR:
	case EBADF:
	case ELOOP:
		ret = SSH2_FX_NO_SUCH_FILE;
		break;
	case EPERM:
	case EACCES:
	case EFAULT:
		ret = SSH2_FX_PERMISSION_DENIED;
		break;
	case ENAMETOOLONG:
	case EINVAL:
		ret = SSH2_FX_BAD_MESSAGE;
		break;
	default:
		ret = SSH2_FX_FAILURE;
		break;
	}
	return ret;
}

int
flags_from_portable(int pflags)
{
	int flags = 0;
	switch (pflags && (SSH2_FXF_READ & SSH2_FXF_WRITE))
	{
	case SSH2_FXF_READ:
		flags = O_RDONLY;
		break;
	case SSH2_FXF_WRITE:
		flags = O_WRONLY;
		break;
	case SSH_FXP_READ | SSH_FXP_WRITE:
		flags = O_RDWR;
		break;
	default:
		/* FIXME: Can't do this on unix. We have to report an
		 * error somehow */
		abort();
	}
	if (pflags & SSH2_FXF_CREAT)
		flags |= O_CREAT;
	if (pflags & SSH2_FXF_TRUNC)
		flags |= O_TRUNC;
	if (pflags & SSH2_FXF_EXCL)
		flags |= O_EXCL;
	return flags;
}

void
attrib_clear(Attrib *a)
{
	a->flags = 0;
	a->size = 0;
	a->uid = 0;
	a->gid = 0;
	a->perm = 0;
	a->atime = 0;
	a->mtime = 0;
}

/* FIXME: Should perhaps be renamed to get_attrib */
int
decode_attrib(INPUT_BUFFER b, Attrib *a)
{
	attrib_clear(a);
	if (!GET_UINT32(b, &a->flags))
		return 0;
	
	if ((a->flags & SSH2_FILEXFER_ATTR_SIZE)
	    && !GET_UINT64(b, &a->size))
		return 0;

	if ((a->flags & SSH2_FILEXFER_ATTR_UIDGID)
	    && !(GET_UINT32(b, &a->uid)
		 && GET_UINT32(b, &a->gid)))
		return 0;

	if ((a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS)
	    && !GET_UINT32(b, &a->perm))
		return 0;
	
	if ((a->flags & SSH2_FILEXFER_ATTR_ACMODTIME)
	    && !(GET_UINT32(b, &a->atime)
		 && GET_UINT32(b, &a->mtime)))
		return 0;

	/* vendor-specific extensions */
	if (a->flags & SSH2_FILEXFER_ATTR_EXTENDED)
	{
		/* Ignore all extensions */
		u_int32_t count;
		u_int32_t i;
		u_int32_t type_length;
		u_int8_t *type;
		u_int32_t data_length;
		u_int8_t *data;

		if (!GET_UINT32(b, &count))
			return 0;
		
		for (i = 0; i < count; i++)
		{
			if (!GET_STRING(b, &type_length, &type))
				return 0;
			FREE(type);
			
			if (!GET_STRING(b, &data_length, &data))
				return 0;

			FREE(data);
		}
	}
	return 1;
}

void
encode_attrib(OUPUT_BUFFER b, Attrib *a)
{
	if (!PUT_UINT32(b, a->flags))
		return 0;

	if ((a->flags & SSH2_FILEXFER_ATTR_SIZE)
	    && !PUT_UINT64(b, a->size))
		return 0;

	if ((a->flags & SSH2_FILEXFER_ATTR_SIZE)
	    && !(PUT_UINT32(b, a->uid)
		 && PUT_UINT32(b, a->gid)))
		return 0;

	if ((a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS)
	    && !PUT_UINT32(b, a->perm))
		return 0;

	/* FIXME: Use a better representation of times. */
	if ((a->flags & SSH2_FILEXFER_ATTR_ACMODTIME)
	    && !(PUT_UINT32(b, a->atime)
		 && PUT_UINT32(b, a->mtime)))
		return 0;

	return 1;
}

void
stat_to_attrib(struct stat *st, Attrib *a)
{
	attrib_clear(a);
	a->flags |= SSH2_FILEXFER_ATTR_SIZE;
	a->size = st->st_size;
	a->flags |= SSH2_FILEXFER_ATTR_UIDGID;
	a->uid = st->st_uid;
	a->gid = st->st_gid;
	a->flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;
	a->perm = st->st_mode;
	a->flags |= SSH2_FILEXFER_ATTR_ACMODTIME;
	a->atime = st->st_atime;
	a->mtime = st->st_mtime;
}

#if 0
Attrib *
get_attrib(void)
{
	return decode_attrib(&iqueue);
}
#endif

/* handle handles */

enum handle_type {
	HANDLE_UNUSED,
	HANDLE_DIR,
	HANDLE_FILE
};

typedef struct Handle Handle;
struct Handle {
	enum handle_type use;
	DIR *dirp;
	int fd;
	char *name;
};

#define HANDLES_MAX 100
/* FIXME: Allocate this dynamically */
Handle	handles[HANDLES_MAX];

void
handle_init(void)
{
	int i;
	for(i = 0; i < sizeof(handles)/sizeof(Handle); i++)
		handles[i].use = HANDLE_UNUSED;
}

int
handle_new(enum handle_type use, char *name, int fd, DIR *dirp)
{
	int i;
	assert(use != HANDLE_UNUSED);
	
	for(i = 0; i < sizeof(handles)/sizeof(Handle); i++) {
		if (handles[i].use == HANDLE_UNUSED) {
			handles[i].use = use;
			handles[i].dirp = dirp;
			handles[i].fd = fd;
			handles[i].name = name;
			return i;
		}
	}
	return -1;
}

int
handle_is_ok(int i, enum handle_type type)
{
	return i >= 0 && i < HANDLES_MAX &&
	    handles[i].use == type;
}

int
handle_is_used(int i)
{
	return i >= 0 && i < HANDLES_MAX &&
	    handles[i].use != HANDLE_UNUSED;
}

int
put_handle(OUTPUT_BUFFER o, int handle)
{
	return PUT_UINT32(b, 4)
		&& PUT_UINT32(b, handle);
}

int get_handle(INPUT_BUFFER i, int *handle)
{
	u_int32_t length;
	u_int32_t value;
	
	if (GET_UINT32(i, &length)
	    && (length == 4)
	    && GET_UINT32(i, &value))
	{
		*handle = value;
		return 1;
	}
	return 0;
}

#if 0
int
handle_to_string(int handle, char **stringp, int *hlenp)
{
	char buf[1024];
	if (stringp == NULL || hlenp == NULL)
		return -1;
	snprintf(buf, sizeof buf, "%d", handle);
	*stringp = xstrdup(buf);
	*hlenp = strlen(*stringp);
	return 0;
}

int
handle_from_string(char *handle, u_int hlen)
{
/* XXX OVERFLOW ? */
	char *ep;
	long lval = strtol(handle, &ep, 10);
	int val = lval;
	if (*ep != '\0')
		return -1;
	if (handle_is_ok(val, HANDLE_FILE) ||
	    handle_is_ok(val, HANDLE_DIR))
		return val;
	return -1;
}
#endif

/* FIXME: This is used only by process_readdir, which could use fchdir
 * instead. */
char *
handle_to_name(int handle)
{
	if (handle_is_ok(handle, HANDLE_DIR)||
	    handle_is_ok(handle, HANDLE_FILE))
		return handles[handle].name;
	return NULL;
}

DIR *
handle_to_dir(int handle)
{
	if (handle_is_ok(handle, HANDLE_DIR))
		return handles[handle].dirp;
	return NULL;
}

int
handle_to_fd(int handle)
{
	if (handle_is_ok(handle, HANDLE_FILE)) 
		return handles[handle].fd;
	return -1;
}

int
handle_close(int handle)
{
	int ret = -1;
	if (handle_is_ok(handle, HANDLE_FILE)) {
		ret = close(handles[handle].fd);
		handles[handle].use = HANDLE_UNUSED;
	} else if (handle_is_ok(handle, HANDLE_DIR)) {
		ret = closedir(handles[handle].dirp);
		handles[handle].use = HANDLE_UNUSED;
	} else {
		errno = ENOENT;
	}
	return ret;
}

#if 0
int
get_handle(void)
{
	char *handle;
	int val = -1;
	u_int hlen;
	handle = get_string(&hlen);
	if (hlen < 256)
		val = handle_from_string(handle, hlen);
	xfree(handle);
	return val;
}
#endif

/* send replies */

/* XXX */

void
send_msg(Buffer *m)
{
	int mlen = buffer_len(m);
	buffer_put_int(&oqueue, mlen);
	buffer_append(&oqueue, buffer_ptr(m), mlen);
	buffer_consume(m, mlen);
}

void
send_status(u_int32_t id, u_int32_t error)
{
	Buffer msg;
	TRACE("sent status id %d error %d", id, error);
	buffer_init(&msg);
	buffer_put_char(&msg, SSH2_FXP_STATUS);
	buffer_put_int(&msg, id);
	buffer_put_int(&msg, error);
	send_msg(&msg);
	buffer_free(&msg);
}
void
send_data_or_handle(char type, u_int32_t id, char *data, int dlen)
{
	Buffer msg;
	buffer_init(&msg);
	buffer_put_char(&msg, type);
	buffer_put_int(&msg, id);
	buffer_put_string(&msg, data, dlen);
	send_msg(&msg);
	buffer_free(&msg);
}

void
send_data(u_int32_t id, char *data, int dlen)
{
	TRACE("sent data id %d len %d", id, dlen);
	send_data_or_handle(SSH2_FXP_DATA, id, data, dlen);
}

void
send_handle(u_int32_t id, int handle)
{
	char *string;
	int hlen;
	handle_to_string(handle, &string, &hlen);
	TRACE("sent handle id %d handle %d", id, handle);
	send_data_or_handle(SSH2_FXP_HANDLE, id, string, hlen);
	xfree(string);
}

void
send_names(u_int32_t id, int count, Stat *stats)
{
	Buffer msg;
	int i;
	buffer_init(&msg);
	buffer_put_char(&msg, SSH2_FXP_NAME);
	buffer_put_int(&msg, id);
	buffer_put_int(&msg, count);
	TRACE("sent names id %d count %d", id, count);
	for (i = 0; i < count; i++) {
		buffer_put_cstring(&msg, stats[i].name);
		buffer_put_cstring(&msg, stats[i].long_name);
		encode_attrib(&msg, &stats[i].attrib);
	}
	send_msg(&msg);
	buffer_free(&msg);
}

void
send_attrib(u_int32_t id, Attrib *a)
{
	Buffer msg;
	TRACE("sent attrib id %d have 0x%x", id, a->flags);
	buffer_init(&msg);
	buffer_put_char(&msg, SSH2_FXP_ATTRS);
	buffer_put_int(&msg, id);
	encode_attrib(&msg, a);
	send_msg(&msg);
	buffer_free(&msg);
}

/* parse incoming */

void
process_init(void)
{
	Buffer msg;
	int version = buffer_get_int(&iqueue);

	TRACE("client version %d", version);
	buffer_init(&msg);
	buffer_put_char(&msg, SSH2_FXP_VERSION);
	buffer_put_int(&msg, SSH2_FILEXFER_VERSION);
	send_msg(&msg);
	buffer_free(&msg);
}

void
process_open(void)
{
	u_int32_t id, pflags;
	Attrib *a;
	char *name;
	int handle, fd, flags, mode, status = SSH2_FX_FAILURE;

	id = get_int();
	name = get_string(NULL);
	pflags = get_int();		/* portable flags */
	a = get_attrib();
	flags = flags_from_portable(pflags);
	mode = (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) ? a->perm : 0666;
	TRACE("open id %d name %s flags %d mode 0%o", id, name, pflags, mode);
	fd = open(name, flags, mode);
	if (fd < 0) {
		status = errno_to_portable(errno);
	} else {
		handle = handle_new(HANDLE_FILE, xstrdup(name), fd, NULL);
		if (handle < 0) {
			close(fd);
		} else {
			send_handle(id, handle);
			status = SSH2_FX_OK;
		}
	}
	if (status != SSH2_FX_OK)
		send_status(id, status);
	xfree(name);
}

void
process_close(void)
{
	u_int32_t id;
	int handle, ret, status = SSH2_FX_FAILURE;

	id = get_int();
	handle = get_handle();
	TRACE("close id %d handle %d", id, handle);
	ret = handle_close(handle);
	status = (ret == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
}

void
process_read(void)
{
	char buf[64*1024];
	u_int32_t id, len;
	int handle, fd, ret, status = SSH2_FX_FAILURE;
	u_int64_t off;

	id = get_int();
	handle = get_handle();
	off = get_int64();
	len = get_int();

	TRACE("read id %d handle %d off %qd len %d", id, handle, off, len);
	if (len > sizeof buf) {
		len = sizeof buf;
		log("read change len %d", len);
	}
	fd = handle_to_fd(handle);
	if (fd >= 0) {
		if (lseek(fd, off, SEEK_SET) < 0) {
			error("process_read: seek failed");
			status = errno_to_portable(errno);
		} else {
			ret = read(fd, buf, len);
			if (ret < 0) {
				status = errno_to_portable(errno);
			} else if (ret == 0) {
				status = SSH2_FX_EOF;
			} else {
				send_data(id, buf, ret);
				status = SSH2_FX_OK;
			}
		}
	}
	if (status != SSH2_FX_OK)
		send_status(id, status);
}

void
process_write(void)
{
	u_int32_t id;
	u_int64_t off;
	u_int len;
	int handle, fd, ret, status = SSH2_FX_FAILURE;
	char *data;

	id = get_int();
	handle = get_handle();
	off = get_int64();
	data = get_string(&len);

	TRACE("write id %d handle %d off %qd len %d", id, handle, off, len);
	fd = handle_to_fd(handle);
	if (fd >= 0) {
		if (lseek(fd, off, SEEK_SET) < 0) {
			status = errno_to_portable(errno);
			error("process_write: seek failed");
		} else {
/* XXX ATOMICIO ? */
			ret = write(fd, data, len);
			if (ret == -1) {
				error("process_write: write failed");
				status = errno_to_portable(errno);
			} else if (ret == len) {
				status = SSH2_FX_OK;
			} else {
				log("nothing at all written");
			}
		}
	}
	send_status(id, status);
	xfree(data);
}

void
process_do_stat(int do_lstat)
{
	Attrib *a;
	struct stat st;
	u_int32_t id;
	char *name;
	int ret, status = SSH2_FX_FAILURE;

	id = get_int();
	name = get_string(NULL);
	TRACE("%sstat id %d name %s", do_lstat ? "l" : "", id, name);
	ret = do_lstat ? lstat(name, &st) : stat(name, &st);
	if (ret < 0) {
		status = errno_to_portable(errno);
	} else {
		a = stat_to_attrib(&st);
		send_attrib(id, a);
		status = SSH2_FX_OK;
	}
	if (status != SSH2_FX_OK)
		send_status(id, status);
	xfree(name);
}

void
process_stat(void)
{
	process_do_stat(0);
}

void
process_lstat(void)
{
	process_do_stat(1);
}

void
process_fstat(void)
{
	Attrib *a;
	struct stat st;
	u_int32_t id;
	int fd, ret, handle, status = SSH2_FX_FAILURE;

	id = get_int();
	handle = get_handle();
	TRACE("fstat id %d handle %d", id, handle);
	fd = handle_to_fd(handle);
	if (fd  >= 0) {
		ret = fstat(fd, &st);
		if (ret < 0) {
			status = errno_to_portable(errno);
		} else {
			a = stat_to_attrib(&st);
			send_attrib(id, a);
			status = SSH2_FX_OK;
		}
	}
	if (status != SSH2_FX_OK)
		send_status(id, status);
}

struct timeval *
attrib_to_tv(Attrib *a)
{
	static struct timeval tv[2];
	tv[0].tv_sec = a->atime;
	tv[0].tv_usec = 0;
	tv[1].tv_sec = a->mtime;
	tv[1].tv_usec = 0;
	return tv;
}

void
process_setstat(void)
{
	Attrib *a;
	u_int32_t id;
	char *name;
	int ret;
	int status = SSH2_FX_OK;

	id = get_int();
	name = get_string(NULL);
	a = get_attrib();
	TRACE("setstat id %d name %s", id, name);
	if (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		ret = chmod(name, a->perm & 0777);
		if (ret == -1)
			status = errno_to_portable(errno);
	}
	if (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		ret = utimes(name, attrib_to_tv(a));
		if (ret == -1)
			status = errno_to_portable(errno);
	}
	send_status(id, status);
	xfree(name);
}

void
process_fsetstat(void)
{
	Attrib *a;
	u_int32_t id;
	int handle, fd, ret;
	int status = SSH2_FX_OK;

	id = get_int();
	handle = get_handle();
	a = get_attrib();
	TRACE("fsetstat id %d handle %d", id, handle);
	fd = handle_to_fd(handle);
	if (fd < 0) {
		status = SSH2_FX_FAILURE;
	} else {
		if (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
			ret = fchmod(fd, a->perm & 0777);
			if (ret == -1)
				status = errno_to_portable(errno);
		}
		if (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
			ret = futimes(fd, attrib_to_tv(a));
			if (ret == -1)
				status = errno_to_portable(errno);
		}
	}
	send_status(id, status);
}

void
process_opendir(void)
{
	DIR *dirp = NULL;
	char *path;
	int handle, status = SSH2_FX_FAILURE;
	u_int32_t id;

	id = get_int();
	path = get_string(NULL);
	TRACE("opendir id %d path %s", id, path);
	dirp = opendir(path); 
	if (dirp == NULL) {
		status = errno_to_portable(errno);
	} else {
		handle = handle_new(HANDLE_DIR, xstrdup(path), 0, dirp);
		if (handle < 0) {
			closedir(dirp);
		} else {
			send_handle(id, handle);
			status = SSH2_FX_OK;
		}
		
	}
	if (status != SSH2_FX_OK)
		send_status(id, status);
	xfree(path);
}

/*
 * XXX, draft-ietf-secsh-filexfer-00.txt says: 
 * The recommended format for the longname field is as follows:
 * -rwxr-xr-x   1 mjos     staff      348911 Mar 25 14:29 t-filexfer
 * 1234567890 123 12345678 12345678 12345678 123456789012
 */
char *
ls_file(char *name, struct stat *st)
{
	char buf[1024];
	snprintf(buf, sizeof buf, "0%o %d %d %qd %d %s",
	    st->st_mode, st->st_uid, st->st_gid, (long long)st->st_size,
	    (int)st->st_mtime, name);
	return xstrdup(buf);
}

void
process_readdir(void)
{
	DIR *dirp;
	struct dirent *dp;
	char *path;
	int handle;
	u_int32_t id;

	id = get_int();
	handle = get_handle();
	TRACE("readdir id %d handle %d", id, handle);
	dirp = handle_to_dir(handle);
	path = handle_to_name(handle);
	if (dirp == NULL || path == NULL) {
		send_status(id, SSH2_FX_FAILURE);
	} else {
		Attrib *a;
		struct stat st;
		char pathname[1024];
		Stat *stats;
		int nstats = 10, count = 0, i;
		stats = xmalloc(nstats * sizeof(Stat));
		while ((dp = readdir(dirp)) != NULL) {
			if (count >= nstats) {
				nstats *= 2;
				stats = xrealloc(stats, nstats * sizeof(Stat));
			}
/* XXX OVERFLOW ? */
			snprintf(pathname, sizeof pathname,
			    "%s/%s", path, dp->d_name);
			if (lstat(pathname, &st) < 0)
				continue;
			a = stat_to_attrib(&st);
			stats[count].attrib = *a;
			stats[count].name = xstrdup(dp->d_name);
			stats[count].long_name = ls_file(dp->d_name, &st);
			count++;
			/* send up to 100 entries in one message */
			if (count == 100)
				break;
		}
		if (count > 0) {
			send_names(id, count, stats);
			for(i = 0; i < count; i++) {
				xfree(stats[i].name);
				xfree(stats[i].long_name);
			}
		} else {
			send_status(id, SSH2_FX_EOF);
		}
		xfree(stats);
	}
}

void
process_remove(void)
{
	char *name;
	u_int32_t id;
	int status = SSH2_FX_FAILURE;
	int ret;

	id = get_int();
	name = get_string(NULL);
	TRACE("remove id %d name %s", id, name);
	ret = unlink(name);
	status = (ret == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	xfree(name);
}

void
process_mkdir(void)
{
	Attrib *a;
	u_int32_t id;
	char *name;
	int ret, mode, status = SSH2_FX_FAILURE;

	id = get_int();
	name = get_string(NULL);
	a = get_attrib();
	mode = (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) ?
	    a->perm & 0777 : 0777;
	TRACE("mkdir id %d name %s mode 0%o", id, name, mode);
	ret = mkdir(name, mode);
	status = (ret == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	xfree(name);
}

void
process_rmdir(void)
{
	u_int32_t id;
	char *name;
	int ret, status;

	id = get_int();
	name = get_string(NULL);
	TRACE("rmdir id %d name %s", id, name);
	ret = rmdir(name);
	status = (ret == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	xfree(name);
}

void
process_realpath(void)
{
	char resolvedname[MAXPATHLEN];
	u_int32_t id;
	char *path;

	id = get_int();
	path = get_string(NULL);
	if (path[0] == '\0') {
		xfree(path);
		path = xstrdup(".");
	}
	TRACE("realpath id %d path %s", id, path);
	if (realpath(path, resolvedname) == NULL) {
		send_status(id, errno_to_portable(errno));
	} else {
		Stat s;
		attrib_clear(&s.attrib);
		s.name = s.long_name = resolvedname;
		send_names(id, 1, &s);
	}
	xfree(path);
}

void
process_rename(void)
{
	u_int32_t id;
	char *oldpath, *newpath;
	int ret, status;

	id = get_int();
	oldpath = get_string(NULL);
	newpath = get_string(NULL);
	TRACE("rename id %d old %s new %s", id, oldpath, newpath);
	ret = rename(oldpath, newpath);
	status = (ret == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	xfree(oldpath);
	xfree(newpath);
}

void
process_extended(void)
{
	u_int32_t id;
	char *request;

	id = get_int();
	request = get_string(NULL);
	send_status(id, SSH2_FX_OP_UNSUPPORTED);		/* MUST */
	xfree(request);
}

/* stolen from ssh-agent */

void
process(void)
{
	u_int msg_len;
	u_int type;
	u_char *cp;

	if (buffer_len(&iqueue) < 5)
		return;		/* Incomplete message. */
	cp = (u_char *) buffer_ptr(&iqueue);
	msg_len = GET_32BIT(cp);
	if (msg_len > 256 * 1024) {
		error("bad message ");
		exit(11);
	}
	if (buffer_len(&iqueue) < msg_len + 4)
		return;
	buffer_consume(&iqueue, 4);
	type = buffer_get_char(&iqueue);
	switch (type) {
	case SSH2_FXP_INIT:
		process_init();
		break;
	case SSH2_FXP_OPEN:
		process_open();
		break;
	case SSH2_FXP_CLOSE:
		process_close();
		break;
	case SSH2_FXP_READ:
		process_read();
		break;
	case SSH2_FXP_WRITE:
		process_write();
		break;
	case SSH2_FXP_LSTAT:
		process_lstat();
		break;
	case SSH2_FXP_FSTAT:
		process_fstat();
		break;
	case SSH2_FXP_SETSTAT:
		process_setstat();
		break;
	case SSH2_FXP_FSETSTAT:
		process_fsetstat();
		break;
	case SSH2_FXP_OPENDIR:
		process_opendir();
		break;
	case SSH2_FXP_READDIR:
		process_readdir();
		break;
	case SSH2_FXP_REMOVE:
		process_remove();
		break;
	case SSH2_FXP_MKDIR:
		process_mkdir();
		break;
	case SSH2_FXP_RMDIR:
		process_rmdir();
		break;
	case SSH2_FXP_REALPATH:
		process_realpath();
		break;
	case SSH2_FXP_STAT:
		process_stat();
		break;
	case SSH2_FXP_RENAME:
		process_rename();
		break;
	case SSH2_FXP_EXTENDED:
		process_extended();
		break;
	default:
		error("Unknown message %d", type);
		break;
	}
}

int
main(int ac, char **av)
{
	fd_set rset, wset;
	int in, out, max;
	ssize_t len, olen;

	handle_init();

        log_init("sftp-server", SYSLOG_LEVEL_DEBUG1, SYSLOG_FACILITY_AUTH, 0);

	in = dup(STDIN_FILENO);
	out = dup(STDOUT_FILENO);

	max = 0;
	if (in > max)
		max = in;
	if (out > max)
		max = out;

	buffer_init(&iqueue);
	buffer_init(&oqueue);

	for (;;) {
		FD_ZERO(&rset);
		FD_ZERO(&wset);

		FD_SET(in, &rset);
		olen = buffer_len(&oqueue);
		if (olen > 0)
			FD_SET(out, &wset);

		if (select(max+1, &rset, &wset, NULL, NULL) < 0) {
			if (errno == EINTR)
				continue;
			exit(2);
		}

		/* copy stdin to iqueue */
		if (FD_ISSET(in, &rset)) {
			char buf[4*4096];
			len = read(in, buf, sizeof buf);
			if (len == 0) {
				debug("read eof");
				exit(0);
			} else if (len < 0) {
				error("read error");
				exit(1);
			} else {
				buffer_append(&iqueue, buf, len);
			}
		}
		/* send oqueue to stdout */
		if (FD_ISSET(out, &wset)) {
			len = write(out, buffer_ptr(&oqueue), olen);
			if (len < 0) {
				error("write error");
				exit(1);
			} else {
				buffer_consume(&oqueue, len);
			}
		}
		/* process requests from client */
		process();
	}
}
