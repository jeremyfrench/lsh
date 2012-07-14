/* unix_random_user.c
 *
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 2008 Niels Möller
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

#include <errno.h>
#include <string.h>

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "randomness.h"

#include "environ.h"
#include "format.h"
#include "interact.h"
#include "lsh_string.h"
#include "werror.h"

int
random_init_user(const char *home)
{
  struct lsh_string *file_name;
  const char *env_name;
  int res;

  env_name = getenv(ENV_SEED_FILE);
  if (env_name)
    file_name = make_string(env_name);
  else
    {
      struct stat sbuf;

      if (!home)
	{
	  werror("Please set HOME in your environment.\n");
	  return 0;
	}

      file_name = ssh_format("%lz/.lsh/yarrow-seed-file", home);
      if (stat(lsh_get_cstring(file_name), &sbuf) < 0
	  && errno == ENOENT)
	{
	  /* Create seed file. */
	  werror("Seedfile for pseudo-randomness generator '%S' does not exist.\n"
		 "It should be created by running the lsh-make-seed program.\n",
		 file_name);
	  if (interact_yes_or_no(ssh_format("Create seed file now? "), 0))
	    {
	      const char *program;
	      int pid;
	      pid = fork();
	      if (pid < 0)
		werror("fork failed: %e.\n", errno);
	      else if (pid)
		{
		  /* Parent */
		  int status;
		  if (waitpid(pid, &status, 0) == -1)
		    werror("waitpid failed: %e.\n", errno);
		  else if (WIFSIGNALED(status))
		    werror("lsh-make-seed terminated by signal %z\n",
			   STRSIGNAL(WTERMSIG(status)));
		  else if (WIFEXITED(status) && WEXITSTATUS(status))
		    werror("lsh-make-seed exited with status code %i",
			   WEXITSTATUS(status));
		}
	      else
		{
		  /* Child process */
		  GET_FILE_ENV(program, LSH_MAKE_SEED);
		  execl(program, program, NULL);
		  werror("exec of %z failed: %e.\n");
		  _exit(EXIT_FAILURE);
		}
	    }
	}
    }

  res = random_init(file_name);
  
  lsh_string_free(file_name);

  return res;
}
