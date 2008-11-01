/* seed_file.c
 *
 * Management of the seed file for the randomness generator. */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 2000, 2001, 2008 Niels Möller
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <errno.h>

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "seed_file.h"

#include "io.h"
#include "werror.h"

int
seed_file_lock(int fd, int wait)
{
  /* What's the most portable way of locking?

     According to linux' manpage for flock(2): "flock(2) does not lock
     files over NFS. Use fcntl(2) instead: that does work over NFS,
     given a sufficiently recent version of Linux and a server which
     supports locking."

     For now, we use fcntl, and hope it works over NFS. */

  struct flock fl;
  
  memset(&fl, 0, sizeof(fl));

  fl.l_type = F_WRLCK;
  fl.l_whence = SEEK_SET;
  fl.l_start = 0;
  fl.l_len = 0; /* Means entire file. */

  if (fcntl(fd, F_SETLK, &fl) != -1)
    return 1;

  if (wait)
    {
      werror("Waiting for seed file lock...\n");
      return (fcntl(fd, F_SETLKW, &fl) != -1);
    }
  return 0;
}

int
seed_file_unlock(int fd)
{
  struct flock fl;
  
  memset(&fl, 0, sizeof(fl));

  fl.l_type = F_UNLCK;
  fl.l_whence = SEEK_SET;
  fl.l_start = 0;
  fl.l_len = 0; /* Means entire file. */

  return (fcntl(fd, F_SETLK, &fl) == 0);  
}

int
seed_file_check_permissions(int fd, const struct lsh_string *filename)
{
  struct stat sbuf;
  if (fstat(fd, &sbuf) < 0)
    {
      werror("Failed to stat file `%S' %e\n",
	     filename, errno);

      return 0;
    }

  if (sbuf.st_uid != getuid())
    {
      werror("The file `%S' is owned by somebody else.\n", filename);

      return 0;
    }

  if (sbuf.st_mode & (S_IRWXG | S_IRWXO))
    {
      werror("Too permissive permissions on `%S'.\n", filename);
      return 0;
    }
  
  return 1;
}

int
seed_file_write(int fd, struct yarrow256_ctx *ctx)
{
  uint8_t buffer[YARROW256_SEED_FILE_SIZE];
  
  if (lseek(fd, 0, SEEK_SET) < 0)
    {
      werror("Seeking to beginning of seed file failed!? %e\n", errno);
      return 0;
    }

  yarrow256_random (ctx, sizeof(buffer), buffer);
  if (!write_raw(fd, sizeof(buffer), buffer))
    {
      werror("Overwriting seed file failed: %e\n", errno);
      return 0;
    }

  return 1;
}
