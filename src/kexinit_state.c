/* kexinit_state.c
 *
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 2005 Niels Möller
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

#include "kexinit.h"

#define GABA_DEFINE
# include "kexinit.h.x"
#undef GABA_DEFINE

void
init_kexinit_state(struct kexinit_state *self)
{
  self->state = KEX_STATE_INIT;
  self->version[0] = self->version[1] = NULL;
  self->kexinit[0] = self->kexinit[1] = NULL;
  self->literal_kexinit[0] = self->literal_kexinit[1] = NULL;
  self->hostkey_algorithm = 0;
  self->algorithm_list = NULL;
}

void
reset_kexinit_state(struct kexinit_state *self)
{
  self->state = KEX_STATE_INIT;
  self->kexinit[0] = self->kexinit[1] = NULL;

  lsh_string_free(self->literal_kexinit[0]);
  lsh_string_free(self->literal_kexinit[1]);
  self->literal_kexinit[0] = self->literal_kexinit[1] = NULL;
  
  self->hostkey_algorithm = 0;
  self->algorithm_list = NULL;
}
