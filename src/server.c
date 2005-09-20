/* server.c
 *
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998 Niels Möller
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <errno.h>

#include <unistd.h>
#include <fcntl.h>

#include "server.h"

#include "atoms.h"
#include "io.h"
#include "lsh_string.h"
#include "sexp.h"
#include "spki.h"
#include "werror.h"


/* Read server's private key */

static void
add_key(struct alist *keys,
        struct keypair *key)
{
  if (ALIST_GET(keys, key->type))
    werror("Multiple host keys for algorithm %a\n", key->type);
  ALIST_SET(keys, key->type, &key->super);
}

int
read_host_key(const char *file,
              struct alist *signature_algorithms,
              struct alist *keys)
{
  int fd = open(file, O_RDONLY);
  struct lsh_string *contents;
  struct signer *s;
  struct verifier *v;
  
  int algorithm_name;

  if (fd < 0)
    {
      werror("Failed to open `%z' for reading %e\n", file, errno);
      return 0;
    }
  
  contents = io_read_file_raw(fd, 5000);
  if (!contents)
    {
      werror("Failed to read host key file `%z': %e\n", file, errno);
      close(fd);
      return 0;
    }
  close(fd);

  s = spki_make_signer(signature_algorithms,
		       contents,
		       &algorithm_name);
  lsh_string_free(contents);
  
  if (!s)
    {
      werror("Invalid host key\n");
      return 0;
    }

  v = SIGNER_GET_VERIFIER(s);
  assert(v);

  switch (algorithm_name)
    {
    case ATOM_DSA:
      add_key(keys,
              make_keypair(ATOM_SSH_DSS, PUBLIC_KEY(v), s));
      break;

    case ATOM_RSA_PKCS1:
    case ATOM_RSA_PKCS1_SHA1:
      add_key(keys,
              make_keypair(ATOM_SSH_RSA, PUBLIC_KEY(v), s));
      break;

    default:
      werror("read_host_key: Unexpected algorithm %a.\n", algorithm_name);
    }
  return 1;
}
