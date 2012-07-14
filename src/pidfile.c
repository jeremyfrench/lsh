/* pidfile.c
 *
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1999, 2002, 2003, 2004, 2005, 2011 Niels Möller
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02111-1301  USA
 */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>

#include <unistd.h>
#include <fcntl.h>

#include "pidfile.h"

#include "format.h"
#include "io.h"
#include "lsh_string.h"
#include "resource.h"
#include "werror.h"
#include "xalloc.h"

#include "pidfile.c.x"

/* GABA:
   (class
     (name pid_file_resource)
     (super resource)
     (vars
       (file string)))
*/

static void
do_kill_pid_file(struct resource *s)
{
  CAST(pid_file_resource, self, s);
  if (self->super.alive)
    {
      self->super.alive = 0;
      if (unlink(lsh_get_cstring(self->file)) < 0)
	werror("Unlinking pidfile `%S' failed: %e.\n", self->file, errno);
    }
}

/* Consumes file name */
struct resource *
make_pid_file_resource(struct lsh_string *file)
{
  const char *cname = lsh_get_cstring(file);
  int fd;

  assert (cname);

  /* Try to open the file atomically. This provides sufficient locking
   * on normal (non-NFS) file systems. */

  fd = open(cname, O_WRONLY | O_CREAT | O_EXCL, 0644);

  if (fd < 0)
    {
      if (errno != EEXIST)
	werror("Failed to open pid file '%S': %e.\n",
		 file, errno);
      else
	/* FIXME: We could try to detect and ignore stale pid files. */
	werror("Pid file '%S' already exists.\n", file);
      
      lsh_string_length(file);
      return NULL;
    }
  else
    {
      struct lsh_string *pid = ssh_format("%di", getpid());

      if (!write_raw(fd, STRING_LD(pid)))
	{
	  werror("Writing pidfile `%S' failed: %e\n",
		 file, errno);

	  /* Attempt unlinking file */
	  if (unlink(cname) < 0)
	    werror("Unlinking pid file '%S' failed: %e.\n",
		   file, errno);

	  close(fd);
	  
	  lsh_string_free(pid);
	  lsh_string_free(file);

	  return NULL;
	}
      else
	{      
	  NEW(pid_file_resource, self);
	  init_resource(&self->super, do_kill_pid_file);

	  self->file = file;

	  lsh_string_free(pid);
	  close(fd);
	  
	  return &self->super;
	}
    }
}
