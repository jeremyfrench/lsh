/* sftp-server.c
 *
 * $Id$
 *
 * The server side of the sftp subsystem. */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 2001 Markus Friedl, Niels Möller, Pontus Sköld
 *
 * Also includes parts from GNU fileutils, Copyright by Free Software
 * Foundation, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA */

/* Some of this code is written by Markus Friedl, and licensed as follows,
 *
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
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
   
#include "buffer.h"
#include "sftp.h"

#include "filemode.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include <sys/stat.h>

#include <dirent.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>

#define SFTP_VERSION 3

#define FATAL(x) do { fputs("sftp-server: " x "\n", stderr); exit(EXIT_FAILURE); } while (0)

void sftp_attrib_from_stat( struct stat *st, struct sftp_attrib* a)
{
  a->permissions=st->st_mode;
  a->uid=st->st_uid;
  a->gid=st->st_gid;
  a->atime=st->st_atime;
  a->mtime=st->st_mtime;
  a->size=st->st_size;
  a->flags= ( SSH_FILEXFER_ATTR_SIZE ||
	      SSH_FILEXFER_ATTR_UIDGID ||
	      SSH_FILEXFER_ATTR_PERMISSIONS || 
	      SSH_FILEXFER_ATTR_ACMODTIME
	      );
}

static void
sftp_put_longname_mode(struct sftp_output *o, struct stat *st)
{
  /* A 10 character modestring and a space */
  UINT8 modes[MODE_STRING_LENGTH];

  filemodestring(st, modes);

  sftp_put_data(o, sizeof(modes), modes);
}

/* FIXME: Replace these dummy functions with the functions from
 * fileutil's lib/idcache.c. */
static const char *
getuser(uid_t uid)
{ return NULL; }

static const char *
getgroup(gid_t gid)
{ return NULL; }

static void
sftp_put_longname(struct sftp_output *o,
		  struct stat *st, UINT8* fname)
{
  /* NOTE: The current spec doesn't mandate utf8. */

  /* Where to store the length. */
  UINT32 length_index = sftp_put_reserve_length(o);
  const char *user_name;
  const char *group_name;
  time_t now, when;
  struct tm *when_local;
  const char *time_format;
  
  sftp_put_longname_mode(o, st);
  sftp_put_printf(o, " %3u ", (unsigned) st->st_nlink);

  user_name = getuser(st->st_uid);
  if (user_name)
    sftp_put_printf(o, "%-8.8s ", user_name);
  else
    sftp_put_printf(o, "%-8u ", (unsigned int) st->st_uid);

  group_name = getgroup(st->st_gid);
  if (group_name)
    sftp_put_printf(o, "%-8.8s ", group_name);
  else
    sftp_put_printf(o, "%-8u ", (unsigned) st->st_gid);

  /* FIXME: How to deal with long long sizes? */
  sftp_put_printf(o, "%8lu ", (unsigned long) st->st_size);

  now = time(NULL);
  when = st->st_mtime;

  when_local = localtime( &st->st_mtime );

  if ( (now > when + 6L * 30L * 24L * 60L * 60L)	/* Old. */
       || (now < when - 60L * 60L) )		/* In the future. */
    /* The file is fairly old or in the future.
       POSIX says the cutoff is 6 months old;
       approximate this by 6*30 days.
       Allow a 1 hour slop factor for what is considered "the future",
       to allow for NFS server/client clock disagreement.
       Show the year instead of the time of day.  */
    time_format = "%b %e  %Y";
  else
    time_format = "%b %e %H:%M";
      
  sftp_put_strftime(o, 12, time_format, when_local);

  sftp_put_printf(o, " %s", fname);

  sftp_put_final_length(o, length_index);
}

static void
sftp_put_filename(struct sftp_output *o,
		  struct stat *st,
		  const char *name)
{
  struct sftp_attrib a;
  
  sftp_attrib_from_stat( st, &a);
  sftp_put_string(o, strlen(name), name);
  sftp_put_longname(o, st, name);
  sftp_put_attrib(o, &a);
}

#define SFTP_MAX_HANDLES 200

struct sftp_handle
{
  enum sftp_handle_type
  { HANDLE_UNUSED = 0, HANDLE_FILE, HANDLE_DIR } type;

  union
  {
    int fd;
    DIR *dir;
  } u;
};

#if 0
/* A handle is simply an fd */
#define handle_t UINT32
#else
#define handle_t struct sftp_handle *
#endif

struct sftp_ctx
{
  struct sftp_input *i;
  struct sftp_output *o;
  
  struct sftp_handle handles[SFTP_MAX_HANDLES];
};

void
sftp_init(struct sftp_ctx *ctx, FILE *in, FILE *out)
{
  struct sftp_input *input;
  struct sftp_output *output;
  unsigned i;

  if (!(input = sftp_make_input(stdin)))
    FATAL("sftp_make_input failed");

  if (!(output = sftp_make_output(stdout)))
    FATAL("sftp_make_input failed");

  ctx->i = input;
  ctx->o = output;

  for (i = 0; i < SFTP_MAX_HANDLES; i++)
    ctx->handles[i].type = HANDLE_UNUSED;
}

int 
sftp_handle_used(struct sftp_ctx *ctx, handle_t handle)
{
  return (handle < SFTP_MAX_HANDLES)
    && (ctx->handles[handle].type != HANDLE_UNUSED);
}

void
sftp_register_handle(struct sftp_ctx *ctx,
		     UINT32 handle,
		     enum sftp_handle_type type)
{
  assert(handle < SFTP_MAX_HANDLES);
  assert(ctx->handles[handle].type == HANDLE_UNUSED);
  assert(type != HANDLE_UNUSED);

  ctx->handles[handle] = type;
}

int
sftp_get_handle(struct sftp_ctx *ctx, handle_t *handle)
{
  UINT32 length;
  UINT32 value;
  
  if ((sftp_get_uint32(ctx->i, &length))
      && (length == 4)
      && sftp_get_uint32(ctx->i, &value)
      && sftp_handle_used(ctx, value))
    {
      *handle = value;
      return 1;
    }
  return 0;
}

void
sftp_put_handle(struct sftp_ctx *ctx, handle_t handle)
{
  sftp_put_uint32(ctx->o, 4);
  sftp_put_uint32(ctx->o, handle);
}

/* NOTE: The status message should be expanded with a human-readable
 * message and a language tag. */
int
sftp_send_status(struct sftp_ctx *ctx, UINT32 status)
{
  sftp_set_msg(ctx->o, SSH_FXP_STATUS);
  sftp_put_uint32(ctx->o, status);
  return 1;
}

int
sftp_send_errno(struct sftp_ctx *ctx)
{
  UINT32 status;
  
  switch(errno)
    {
    case ENOENT:
      status = SSH_FX_NO_SUCH_FILE;
      break;
    case EACCES:
      status = SSH_FX_PERMISSION_DENIED;
      break;
    default:
      status = SSH_FX_FAILURE;
      break;
    }
  return sftp_send_status(ctx, status);
}

int
sftp_bad_message(struct sftp_ctx *ctx)
{
  sftp_send_status(ctx, SSH_FX_BAD_MESSAGE);
  return 0;
}

typedef int sftp_process_func(struct sftp_ctx *ctx);

static int
sftp_process_unsupported(struct sftp_ctx *ctx)
{
  return sftp_bad_message(ctx);
}

/* A filename must not contain any NUL-characters. */
static int
sftp_check_filename(UINT32 length, const UINT8 *data)
{
  return !memchr(data, 0, length);
}

static int
sftp_process_opendir(struct sftp_ctx *ctx)
{
  UINT32 length;
  UINT8 *name;
  DIR* dirhandle;

  if ( ! (name = sftp_get_string(ctx->i, &length))
      )
    return sftp_bad_message(ctx);

  if( (! sftp_check_filename(length, name)))
    {
      sftp_free_string(name);
      return sftp_send_status(ctx, SSH_FX_FAILURE);
    }
    
  /* Fixme; Perhaps we should have a sftp_mangle_fname? If not, we
     have to handle an empty filename here */

  dirhandle=opendir(length ? name : ".");

  sftp_free_string(name);
  
  if ( !dirhandle )
    return sftp_send_errno(ctx);

  /* Open successful */

  /* Fixme; we need to redo how handles work, perhaps a struct
     consisting of the type, an int (for an fd) and a DIR* (for a
     directory). I will look into this later (or we could skip using
     opendir/readdir/closedir, but I think that's not better */

  sftp_register_handle(ctx, dirhandle, HANDLE_DIR);
  sftp_put_handle(ctx, dirhandle);
}

static int
sftp_process_readdir(struct sftp_ctx *ctx)
{
  handle_t handle;
  struct dirent* direntry; 
  struct stat st;

  if ( !sftp_get_handle(ctx->i, &handle) ||
       ctx->handles[handle] != HANDLE_DIR
       )
    return sftp_bad_message(ctx);

  direntry=readdir(handle);

  /* Fixme; we need to redo how handles work, perhaps a struct
     consisting of the type, an int (for an fd) and a DIR* (for a
     directory). I will look into this later (or we could skip using
     opendir/readdir/closedir, but I think that's not better */

  if ( !direntry )
    return (errno ? sftp_send_errno(ctx)
	    : sftp_send_status(ctx, SSH_FX_EOF)); 

  /* Fixme; concat name */

  if( lstat(direntry->d_name, &st ) )
    return sftp_send_errno(ctx);

  /* Fixme; we don't have to, but maybe we should be nice and pass
     several at once? It might improve performance quite a lot (or it
     might not) 
     */

  /* Use count == 1 for now. */
  sftp_put_uint32(ctx->o, 1);

  sftp_put_filename(ctx->o, &st, direntry->d_name);

  sftp_set_msg(ctx->o, SSH_FXP_NAME );
  return 1;
}


static int
sftp_process_stat(struct sftp_ctx *ctx)
{
  struct stat st;
  struct sftp_attrib a;
  UINT32 length;
  UINT8 *name;

  if ( ! (name = sftp_get_string(ctx->i, &length))
      )
    return sftp_bad_message(ctx);

  if( (! sftp_check_filename(length, name))
      )
    return sftp_send_status(ctx, SSH_FX_FAILURE);   
    
  /* Fixme; Perhaps we should have a sftp_mangle_fname ? */


  /* Fixme; concat name */

  if ( stat(name, &st ) )
    return sftp_send_errno(ctx);

  sftp_attrib_from_stat( &st, &a);

  sftp_set_msg( ctx->o, SSH_FXP_ATTRS );
  sftp_put_attrib( ctx->o, &a);  

  return 1;
}

static int
sftp_process_lstat(struct sftp_ctx *ctx)
{
  struct stat st;
  struct sftp_attrib a;

  UINT32 length;
  UINT8 *name;

  if ( ! (name = sftp_get_string(ctx->i, &length))
      )
    return sftp_bad_message(ctx);

  if( (! sftp_check_filename(length, name))
      )
    return sftp_send_status(ctx, SSH_FX_FAILURE);   
    
  /* Fixme; Perhaps we should have a sftp_mangle_fname ? */


  /* Fixme; concat name */

  if ( lstat(name, &st ) )
    return sftp_send_errno(ctx);

  sftp_attrib_from_stat( &st, &a );
  sftp_set_msg( ctx->o, SSH_FXP_ATTRS );

  sftp_put_attrib( ctx->o, &a); 

  return 1;
}

static int
sftp_process_fstat(struct sftp_ctx *ctx)
{
  struct stat st;
  struct sftp_attrib a;
  handle_t handle;

  if ( sftp_get_handle(ctx->i, &handle) )
    if ( ctx->handles[handle] == HANDLE_FILE )
	{
	  if ( fstat(handle, &st ) )
	    return sftp_send_errno(ctx);
	  
	  sftp_attrib_from_stat(&st,&a);
	  sftp_set_msg( ctx->o, SSH_FXP_ATTRS );
	  
	  sftp_put_attrib( ctx->o, &a);
	  return 1;
	}

  return sftp_bad_message(ctx);
}


static int
sftp_process_fsetstat(struct sftp_ctx *ctx)
{
  struct sftp_attrib a;
  handle_t handle;

  if ( sftp_get_handle(ctx->i, &handle) &&
       sftp_get_attrib(ctx->i, &a)
       )
    if ( ! (ctx->handles[handle] == HANDLE_FILE ))
      return sftp_bad_message(ctx);

  /* Fixme; set stat */
	  
  if ( a.flags & SSH_FILEXFER_ATTR_UIDGID )
    if ( fchown( handle, a.uid, a.gid ) )
      return sftp_send_errno(ctx);
  
  if ( a.flags & SSH_FILEXFER_ATTR_SIZE )
    if( ftruncate( handle, a.size ) )
      return sftp_send_errno(ctx);
  
  if ( a.flags & SSH_FILEXFER_ATTR_PERMISSIONS )
    if( fchmod( handle, a.permissions ) ) 
                               /* Fixme; Perhaps we should mask it */
      return sftp_send_errno(ctx);
  
  if ( a.flags & SSH_FILEXFER_ATTR_EXTENDED ||
       a.flags & SSH_FILEXFER_ATTR_ACMODTIME ) /* Fixme; how do we? */
    return sftp_send_status(ctx, SSH_FX_OP_UNSUPPORTED );
  
  return sftp_send_status(ctx, SSH_FX_OK);        
}


static int
sftp_process_setstat(struct sftp_ctx *ctx)
{
  struct sftp_attrib a;

  UINT32 length;
  UINT8 *name;

  if ( (! (name = sftp_get_string(ctx->i, &length))) ||
       (!sftp_get_attrib(ctx->i, &a))
       )
    return sftp_bad_message(ctx);

  if( (! sftp_check_filename(length, name))
      )
    return sftp_send_status(ctx, SSH_FX_FAILURE);   
    
  /* Fixme; Perhaps we should have a sftp_mangle_fname ? */

  if ( a.flags & SSH_FILEXFER_ATTR_UIDGID )
    if ( chown( name, a.uid, a.gid ) )
      return sftp_send_errno(ctx);

  if ( a.flags & SSH_FILEXFER_ATTR_SIZE )
    if( truncate( name, a.size ) )
      return sftp_send_errno(ctx);

  if ( a.flags & SSH_FILEXFER_ATTR_PERMISSIONS )
    if( chmod( name, a.permissions ) ) /* Fixme; Perhaps we should mask it */
      return sftp_send_errno(ctx);

  if ( a.flags & SSH_FILEXFER_ATTR_EXTENDED ||
       a.flags & SSH_FILEXFER_ATTR_ACMODTIME ) /* Fixme; how do we? */
    return sftp_send_status(ctx, SSH_FX_OP_UNSUPPORTED );

  return sftp_send_status(ctx, SSH_FX_OK);  
}

static int
sftp_process_remove(struct sftp_ctx *ctx)
{
  UINT32 length;
  UINT8 *name;

  if ( ! (name = sftp_get_string(ctx->i, &length))
      )
    return sftp_bad_message(ctx);

  if( (! sftp_check_filename(length, name))
      )
    return sftp_send_status(ctx, SSH_FX_FAILURE);   
    
  /* Fixme; Perhaps we should have a sftp_mangle_fname ? */
  
  if( ! unlink(name) )
    return sftp_send_errno(ctx);
  else
    return sftp_send_status(ctx, SSH_FX_OK);   
}

static int
sftp_process_mkdir(struct sftp_ctx *ctx)
{
  UINT32 length;
  UINT8 *name;

  if ( ! (name = sftp_get_string(ctx->i, &length))
      )
    return sftp_bad_message(ctx);

  if( (! sftp_check_filename(length, name))
      )
    return sftp_send_status(ctx, SSH_FX_FAILURE);   
    
  /* Fixme; Perhaps we should have a sftp_mangle_fname? If not, we
     have to handle an empty filename here */
  
  if( ! mkdir(name, 0755) ) /* Fixme; default permissions ? */ 
    return sftp_send_errno(ctx);
  else
    return sftp_send_status(ctx, SSH_FX_OK);   
}

static int
sftp_process_rmdir(struct sftp_ctx *ctx)
{
  UINT32 length;
  UINT8 *name;

  if ( ! (name = sftp_get_string(ctx->i, &length))
      )
    return sftp_bad_message(ctx);

  if( (! sftp_check_filename(length, name))
      )
    return sftp_send_status(ctx, SSH_FX_FAILURE);   
    
  /* Fixme; Perhaps we should have a sftp_mangle_fname? If not, we
     need to handle an empty filename here */
  
  if( ! rmdir(name) )
    return sftp_send_errno(ctx);
  else
    return sftp_send_status(ctx, SSH_FX_OK);   
}

static int
sftp_process_realpath(struct sftp_ctx *ctx)
{
  UINT32 length;
  UINT8 *name;
  UINT8 *resolved;
  struct stat st;
  int path_max;

  if ( ! (name = sftp_get_string(ctx->i, &length))
      )
    return sftp_bad_message(ctx);

  if( (! sftp_check_filename(length, name))
      )
    return sftp_send_status(ctx, SSH_FX_FAILURE);   
    
  /* Fixme; Perhaps we should have a sftp_mangle_fname? If not, we
     need to handle an empty filename here */
  
  /* Code below from the manpage for realpath on my debian system */

#ifdef PATH_MAX
  path_max = PATH_MAX;
#else
  path_max = pathconf (path, _PC_PATH_MAX);
  if (path_max <= 0)
    path_max = 4096;
#endif

  resolved=alloca(path_max);
  
  if( ! realpath( name, resolved ) )
    return sftp_send_errno(ctx);
  
  if( lstat(resolved, &st ) )
    return sftp_send_errno(ctx);

  /* Fixme; Should it be supported to call realpath for non-existing
     files?  This code will break (as it tries to stat and will get
     ENOENT). The draft says we should return "just one name and dummy
     attributes", but I figure we might as well pass the real attribs
     */

  sftp_put_uint32(ctx->o, 1); /* Count */  
  sftp_put_filename(ctx->o, &st, resolved);
  sftp_set_msg( ctx->o, SSH_FXP_NAME );
  return 1;
}

static int
sftp_process_rename(struct sftp_ctx *ctx)
{
  UINT32 src_length;
  UINT8 *src_name;

  UINT32 dst_length;
  UINT8 *dst_name;

  if (! ( (src_name = sftp_get_string(ctx->i, &src_length)) &&
	  (dst_name = sftp_get_string(ctx->i, &dst_length)))
      )
    return sftp_bad_message(ctx);
    
  /* Fixme; Perhaps we should have a sftp_mangle_fname ? Otherwise,
     we must handle the case of an empty filename here
     */
  
  if( (! sftp_check_filename(src_length, src_name)) ||
      (! sftp_check_filename(dst_length, dst_name)) 
      )
    return sftp_send_status(ctx, SSH_FX_FAILURE);   
   
  if( ! rename(src_name, dst_name) )
    return sftp_send_errno(ctx);
  else
    return sftp_send_status(ctx, SSH_FX_OK);   
}


static int
sftp_process_open(struct sftp_ctx *ctx)
{
  UINT32 length;
  UINT8 *name;
  UINT32 pflags;
  struct sftp_attrib a;

  if ((name = sftp_get_string(ctx->i, &length))
      && sftp_get_uint32(ctx->i, &pflags)
      && sftp_get_attrib(ctx->i, &a))
    {
      /* Empty name is a synonym to ".", which isn't a file. */
      if (length && sftp_check_filename(length, name))
	{
	  int fd;
	  int mode;
	  struct stat sb;
	  
	  switch (pflags & (SSH_FXF_READ | SSH_FXF_WRITE))
	    {
	    case 0:
	      sftp_send_status(ctx, SSH_FX_FAILURE);
	      return 1;
	    case SSH_FXF_READ:
	      mode = O_RDONLY;
	      break;
	    case SSH_FXF_WRITE:
	      mode = O_WRONLY;
	      break;
	    case SSH_FXF_READ | SSH_FXF_WRITE:
	      mode = O_RDWR;
	      break;
	    default:
	      abort();
	    }
	  if (pflags & SSH_FXF_APPEND)
	    mode |= O_APPEND;

	  if (pflags & SSH_FXF_CREAT)
	    mode |= O_CREAT;
	  else if (pflags & SSH_FXF_EXCL)
	    /* We can't have EXCL without CREAT. */
	    sftp_send_status(ctx, SSH_FX_FAILURE);
	  
	  if (pflags & SSH_FXF_TRUNC)
	    mode |= O_TRUNC;
	  if (pflags & SSH_FXF_EXCL)
	    mode |= O_EXCL;

	  /* Look at the atributes. For now, we care only about the
	   * permission bits. */
	  if (a.flags & SSH_FILEXFER_ATTR_PERMISSIONS)
	    {
	      /* Use the client's permission bits with no umask filtering */
	      mode_t old = umask(0);
	      fd = open(name, mode, a.permissions);
	      umask(old);
	    }
	  else
	    /* Default flags, filtered through our umask */
	    fd = open(name, mode, 0666);

	  if (fd < 0)
	    return sftp_send_errno(ctx);

#if 0
	  if (a.flags & SSH_FILEXFER_ATTR_UIDGID)
	    if ( fchown(fd, a.uid, a.gid) )
	      return sftp_send_errno(ctx);
#endif    

	  if (fd > SFTP_MAX_HANDLES)
	    {
	      close(fd);
	      return sftp_send_status(ctx, SSH_FX_FAILURE);
	    }

	  if (fstat(fd, &sb) < 0)
	    {
	      close(fd);
	      return sftp_send_errno(ctx);
	    }

	  if (S_ISDIR(sb.st_mode))
	    {
	      close(fd);
	      return sftp_send_status(ctx, SSH_FX_NO_SUCH_FILE);
	    }

	  /* Open successful */
	  sftp_register_handle(ctx, fd, HANDLE_FILE);
	  sftp_put_handle(ctx, fd);
	  return 1;
	}
      else
	return sftp_send_status(ctx, SSH_FX_NO_SUCH_FILE);
    }
  else
    return sftp_bad_message(ctx);
}


static int
sftp_process_close(struct sftp_ctx *ctx)
{
  handle_t handle;

  if ( sftp_get_handle(ctx, &handle) )
    {
      if ( ctx->handles[handle] == HANDLE_FILE )
	{
	  if ( !close(handle) )
	    {
	      ctx->handles[handle] = HANDLE_UNUSED;
	      return sftp_send_status(ctx, SSH_FX_OK);
	    }
	  else	
	    return sftp_send_status(ctx, SSH_FX_FAILURE); 
	  /* Fixme: Should we do something on error ?
	   */
	}

      else if ( ctx->handles[handle] == HANDLE_DIR)
	{
	  if ( !closedir(handle) )
	    {
	      ctx->handles[handle] = HANDLE_UNUSED;
	      return sftp_send_status(ctx, SSH_FX_OK);
	    }
	  else	
	    return sftp_send_status(ctx, SSH_FX_FAILURE);
	}
    }
  else
    return sftp_bad_message(ctx); 
/* Fixme; Should we separate cases bad message 
   and illegal handle and return failure for 
   one and bad_message for the other?
   */
}

static int
sftp_process_read(struct sftp_ctx *ctx)
{
  handle_t handle;
  UINT64 offset;
  UINT32 len;
  int readbytes=0;
  static UINT8* readbuf=0; 
  static UINT32 curbuflen=0;

  if ( !sftp_get_handle(ctx, &handle) && 
       ctx->handles[handle] == HANDLE_FILE && 
       sftp_get_uint64(ctx->i, &offset) &&
       sftp_get_uint32(ctx->i, &len)  
       )
    return sftp_bad_message(ctx);

/* Fixme; Should we separate cases bad message
   and illegal handle and return failure 
   for one and bad_message for the other?
   */

  if ( lseek( handle, offset, SEEK_SET) == (off_t) -1 )
    return sftp_send_status(ctx, SSH_FX_FAILURE); 

  /* Fixme; 64-bit support works differently on solaris at least */

  if ( len )                              /* Check so we are to read at all */
    {
      if ( len > curbuflen )             /* Current buffer to small ? */
	{
	  if ( readbuf )                  
	    free( readbuf );             /* Free the existing buffer 
					    (Fixme; Perhaps explicitly set
					    readbuf to NULL, although the 
					    malloc means we shouldn't have to)
					    */


	  readbuf=malloc( len );           /* Allocate the new one */
	  
	  if ( !readbuf )
	    {
	      curbuflen=0;                   /* Failed malloc - we have no 
						buffer 
						*/

	      return sftp_send_status(ctx, SSH_FX_FAILURE); 

	    }
	  else
	    curbuflen=len;
	}

      readbytes=read( handle, readbuf, len );
      
      if ( readbytes == 0 )
	return sftp_send_status( ctx, SSH_FX_EOF ); 
      else if ( readbytes == -1 )
	return sftp_send_status( ctx, SSH_FX_FAILURE ); 
      
    }
 
  sftp_set_msg( ctx->o, SSH_FXP_DATA );
  sftp_put_string( ctx->o, readbytes, readbuf );
  return 1;
}

static int
sftp_process_write(struct sftp_ctx *ctx)
{
  handle_t handle;
  UINT64 offset;

  int writtenbytes=0;
  UINT8 *writebuf; 
  UINT32 length;


  if ( !sftp_get_handle(ctx, &handle) && 
       ctx->handles[handle] == HANDLE_FILE && 
       sftp_get_uint64(ctx->i, &offset) &&
       writebuf=sftp_get_string(ctx->i, &length)  
       )
    return sftp_bad_message(ctx);

/* Fixme; Should we separate cases bad message
   and illegal handle and return failure 
   for one and bad_message for the other?
   */

  if ( lseek( handle, offset, SEEK_SET) == (off_t) -1 )
    return sftp_send_status(ctx, SSH_FX_FAILURE); 

  /* Fixme; 64-bit support works differently on solaris at least */

  /* Nothing happens if length is 0 - hence we need no special test */
    
  if ( write( handle, writebuf, length ) != -1 )
    return sftp_send_status(ctx, SSH_FX_OK); 
  else
    return sftp_send_errno(ctx);
}


static void
sftp_process(sftp_process_func **dispatch,
	     struct sftp_ctx *ctx)
{
  UINT8 msg;
  UINT32 id;
  
  int ok;

  switch (sftp_read_packet(ctx->i))
    {
    case 1:
      break;
    case 0:
      exit(EXIT_FAILURE);
    case -1: /* EOF */
      exit(EXIT_SUCCESS);
    }
  
  /* All packets start with a msg byte and a 32-bit id. */
  if (!sftp_get_uint8(ctx->i, &msg))
    FATAL("Invalid packet.");

  if (!sftp_get_uint32(ctx->i, &id))
    FATAL("Invalid packet.");

  /* Every reply starts with the id, so copy it through */
  sftp_set_id(ctx->o, id);
    
  /* Calls FATAL on protocol errors. */
  ok = dispatch[msg](ctx);
    
  /* Every handler should result in at least one message */
  if (!sftp_write_packet(ctx->o))
    exit(EXIT_FAILURE);
  
  if (!ok)
    exit(EXIT_FAILURE);
}  

/* The handshake packets are special, because they don't include any
 * request id. */
int
sftp_handshake(struct sftp_ctx *ctx)
{
  UINT8 msg;
  UINT32 version;
  
  if (sftp_read_packet(ctx->i) <= 0)
    return 0;

  if (sftp_get_uint8(ctx->i, &msg)
      && (msg == SSH_FXP_INIT)
      && sftp_get_uint32(ctx->i, &version))
    {
      while (!sftp_get_eod(ctx->i))
	if (!sftp_skip_extension(ctx->i))
	  return 0;

      if (version < SFTP_VERSION)
	return 0;

      /* The VERSION message puts the version number where
       * the id is usually located. */

      sftp_set_msg(ctx->o, SSH_FXP_VERSION);
      sftp_set_id(ctx->o, SFTP_VERSION);

      return sftp_write_packet(ctx->o);
    }
  return 0;
}

int
main(int argc, char **argv)
{
  unsigned i;
  
  struct sftp_ctx ctx;
  sftp_process_func *dispatch[0x100];

  sftp_init(&ctx, stdin, stdout);

  if (!sftp_handshake(&ctx))
    return EXIT_FAILURE;
  
  for (i = 0; i<0x100; i++)
    dispatch[i] = sftp_process_unsupported;
  
  dispatch[SSH_FXP_OPEN] = sftp_process_open;
  dispatch[SSH_FXP_CLOSE] = sftp_process_close;
  dispatch[SSH_FXP_READ] = sftp_process_read;
  dispatch[SSH_FXP_WRITE] = sftp_process_write;
  dispatch[SSH_FXP_LSTAT] = sftp_process_lstat;
  dispatch[SSH_FXP_STAT] = sftp_process_stat;
  dispatch[SSH_FXP_FSTAT] = sftp_process_fstat;
  dispatch[SSH_FXP_SETSTAT] = sftp_process_setstat;
  dispatch[SSH_FXP_FSETSTAT] = sftp_process_fsetstat;  
  dispatch[SSH_FXP_MKDIR] = sftp_process_mkdir;
  dispatch[SSH_FXP_RMDIR] = sftp_process_rmdir;
  dispatch[SSH_FXP_REMOVE] = sftp_process_remove;
  dispatch[SSH_FXP_RENAME] = sftp_process_rename;
  dispatch[SSH_FXP_OPENDIR] = sftp_process_opendir;
  dispatch[SSH_FXP_READDIR] = sftp_process_readdir;
  dispatch[SSH_FXP_REALPATH] = sftp_process_realpath;

  for(;;)
    sftp_process(dispatch, &ctx);
}
