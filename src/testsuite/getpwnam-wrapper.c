/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 2010 Niels Möller
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <pwd.h>

#include "environ.h"

/* Construct a passwd entry for testing. */
struct passwd *
getpwnam(const char *name)
{
  /* To be returned. */
  static char buf[500];
  static struct passwd passwd;

  passwd.pw_uid = getuid();
  passwd.pw_gid = getgid();
  passwd.pw_gecos = "Test user";
  passwd.pw_dir = "/";
  passwd.pw_shell = "/bin/sh";
  
  if (strcmp (name, "testuser") == 0)
    {
      const char *config_dir;
      FILE *f;
      int res;
      char *s;

      config_dir = getenv("GETWPWNAM_WRAPPER_DIR");
      if (!config_dir)
	return NULL;

      res = snprintf(buf, sizeof(buf), "%s/test-passwd", config_dir);

      /* Detect both variants of reporting truncation. */
      if (res < 0 || res >= sizeof(buf))
	return NULL;

      f = fopen (buf, "r");
      if (!f)
	return NULL;

      s = fgets (buf, sizeof(buf), f);
      fclose (f);

      if (!s)
	return NULL;

      s = strchr (buf, '\n');
      if (s)
	*s = 0;

      s = crypt (buf, "az");
      strcpy (buf, s);

      passwd.pw_name = "testuser";
      passwd.pw_passwd = buf;

      return &passwd;
    }
  else if (strcmp (name, "no-passwd-testuser") == 0)
    {
      passwd.pw_name = "no-passwd-testuser";
      passwd.pw_passwd = "NP";

      return &passwd;
    }
  else if (strcmp (name, "disabled-testuser") == 0)
    {
      passwd.pw_name = "disabled-testuser";
      passwd.pw_passwd = "*x";

      return &passwd;
    }
  else if (strcmp (name, "empty-passwd-testuser") == 0)
    {
      passwd.pw_name = "empty-passwd-testuser";
      passwd.pw_passwd = "";

      return &passwd;
    }

  return NULL;
}
