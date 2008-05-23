/* xauth.c
 *
 * Xauth parsing.
 *
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 2001, 2008 Niels Möller
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

#include <X11/X.h>
#if HAVE_X11_XAUTH_H
#include <X11/Xauth.h>
#endif

#include <unistd.h>
#include <netinet/in.h>

#include "xauth.h"

#include "format.h"
#include "lsh_string.h"
#include "werror.h"

/* FIXME: Merge in parse_display in client_x11.c. */
int
xauth_lookup(struct sockaddr *sa,
             unsigned number_length,
             const char *number,
             struct lsh_string **name,
             struct lsh_string **data)
{
#if HAVE_LIBXAU

  int res = 0;
  unsigned family;

  const char *address;
  unsigned address_length;
  
  /* FIXME: Use xgethostname */
#define HOST_MAX 200
  char host[HOST_MAX];
  
  const char *filename = XauFileName();
  Xauth *xa;

  if (!filename)
    return 0;

  switch(sa->sa_family)
    {
    case AF_UNIX:
      if (gethostname(host, sizeof(host) - 1) < 0)
	return 0;
      address = host;
      address_length = strlen(host);
      family = FamilyLocal;
      break;

    case AF_INET:
      {
	struct sockaddr_in *s = (struct sockaddr_in *) sa;
	
	address = (char *) &s->sin_addr;
	address_length = 4;
	family = FamilyInternet;
	break;
      }

#if WITH_IPV6
    case AF_INET6:
      {
	struct sockaddr_in6 *s = (struct sockaddr_in6 *) sa;
	
	address = (char *) &s->sin6_addr;
	address_length = 16;
	family = FamilyInternet6;
	break;
      }
#endif
    default:
      return 0;
    }

  /* 5 retries, 1 second each */
  if (XauLockAuth(filename, 5, 1, 0) != LOCK_SUCCESS)
    return 0;

  /* NOTE: The man page doesn't list the last two arguments,
     name_length and name. From the source, it seems that a zero
     name_length means match any name. */
  xa = XauGetAuthByAddr(family, address_length, address,
			number_length, number, 0, "");
  if (xa)
    {
      debug("xauth: family: %i\n", xa->family);
      debug("       address: %ps\n", xa->address_length, xa->address);
      debug("       display: %s\n", xa->number_length, xa->number);
      debug("       name: %s\n", xa->name_length, xa->name);
      debug("       data length: %i\n", xa->data_length);

      *name = ssh_format("%ls", xa->name_length, xa->name);
      *data = ssh_format("%ls", xa->data_length, xa->data);

      XauDisposeAuth(xa);
      res = 1;
    }
  else
    res = 0;

  XauUnlockAuth(filename);
  return res;
#else /* !HAVE_LIBXAU */
  return 0;
#endif /* !HAVE_LIBXAU */
}
