/* tty.c
 *
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998, 1999, 2008, Niels Möller, Balázs Scheidler
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

#include <fcntl.h>
#include <unistd.h>

#include <sys/ioctl.h>

#include "nettle/macros.h"

#include "tty.h"

#include "format.h"
#include "parse.h"
#include "lsh_string.h"
#include "ssh.h"
#include "werror.h"
#include "xalloc.h"

/* NOTE: tty_decode_term_mode is used only on the server side, and
   tty_encode_term_mode is used only on the client side. They use the
   same tables. It would make some sense to put the tables and the two
   functions in three different files, to avoid linking in the
   unnecessary one, but it's easier to keep it all together. */

#if WITH_PTY_SUPPORT

static const short int termios_cc_index[] = 
{
#ifdef VINTR
  VINTR, 
#else
  -1,
#endif
#ifdef VQUIT
  VQUIT, 
#else
  -1,
#endif
#ifdef VINTR
  VERASE, 
#else
  -1,
#endif
#ifdef VKILL
  VKILL, 
#else
  -1,
#endif
#ifdef VEOF
  VEOF, 
#else
  -1,
#endif
#ifdef VEOL
  VEOL, 
#else
  -1,
#endif
#ifdef VEOL2
  VEOL2, 
#else
  -1,
#endif
#ifdef VSTART
  VSTART, 
#else
  -1,
#endif
#ifdef VSTOP
  VSTOP, 
#else
  -1,
#endif
#ifdef VSUSP
  VSUSP, 
#else
  -1,
#endif
#ifdef VDSUSP
  VDSUSP, 
#else
  -1,
#endif
#ifdef VREPRINT
  VREPRINT, 
#else
  -1,
#endif
#ifdef VWERASE
  VWERASE, 
#else
  -1,
#endif
#ifdef VLNEXT
  VLNEXT, 
#else
  -1,
#endif
#ifdef VFLUSH
  VFLUSH, 
#else
  -1,
#endif
#ifdef VSWTCH
  VSWTCH, 
#else
  -1,
#endif
#ifdef VSTATUS
  VSTATUS, 
#else
  -1,
#endif
#ifdef VDISCARD
  VDISCARD 
#else
  -1,
#endif
};

static const unsigned termios_iflags[] = {
#ifdef IGNPAR
  IGNPAR,
#else
  0,
#endif
#ifdef PARMRK
  PARMRK,
#else
  0,
#endif
#ifdef INPCK
  INPCK,
#else
  0,
#endif
#ifdef ISTRIP
  ISTRIP,
#else
  0,
#endif
#ifdef INLCR
  INLCR,
#else
  0,
#endif
#ifdef IGNCR
  IGNCR,
#else
  0,
#endif
#ifdef ICRNL
  ICRNL,
#else
  0,
#endif
#ifdef IUCLC
  IUCLC,
#else
  0,
#endif
#ifdef IXON
  IXON,
#else
  0,
#endif
#ifdef IXANY
  IXANY,
#else
  0,
#endif
#ifdef IXOFF
  IXOFF,
#else
  0,
#endif
#ifdef IMAXBEL
  IMAXBEL
#else
  0
#endif
};

static const unsigned termios_oflags[] = {
#ifdef OPOST
  OPOST,
#else
  0,
#endif    
#ifdef OLCUC
  OLCUC,
#else
  0,
#endif    
#ifdef ONLCR
  ONLCR,
#else
  0,
#endif    
#ifdef OCRNL
  OCRNL,
#else
  0,
#endif    
#ifdef ONOCR
  ONOCR,
#else
  0,
#endif    
#ifdef ONLRET
  ONLRET
#else
  0
#endif    
};

static const unsigned termios_cflags[] = {
#ifdef CS7
  CS7,
#else
  0,
#endif    
#ifdef CS8
  CS8,
#else
  0,
#endif    
#ifdef PARENB
  PARENB,
#else
  0,
#endif    
#ifdef PARODD
  PARODD
#else
  0
#endif    
};

static int termios_lflags[] = {
#ifdef ISIG
  ISIG,
#else
  0,
#endif
#ifdef ICANON
  ICANON,
#else
  0,
#endif
#ifdef XCASE
  XCASE,
#else
  0,
#endif
#ifdef ECHO
  ECHO,
#else
  0,
#endif
#ifdef ECHOE
  ECHOE,
#else
  0,
#endif
#ifdef ECHOK
  ECHOK,
#else
  0,
#endif
#ifdef ECHONL
  ECHONL,
#else
  0,
#endif
#ifdef NOFLSH
  NOFLSH,
#else
  0,
#endif
#ifdef TOSTOP
  TOSTOP,
#else
  0,
#endif
#ifdef IEXTEN
  IEXTEN,
#else
  0,
#endif
#ifdef ECHOCTL
  ECHOCTL,
#else
  0,
#endif
#ifdef ECHOKE
  ECHOKE,
#else
  0,
#endif
#ifdef PENDIN
  PENDIN
#else
  0,
#endif
};

#define SIZE(x) (sizeof((x)) / sizeof((x)[0]))

/* FIXME: TTY_?SPEED not handled */

#define ENCODE_FLAGS(cc, bits, offset) do {			\
  debug("tty_encode_term_mode: termios bits %xi (offset %i)\n",	\
	(bits), (offset));					\
  for (i=0; i<SIZE(cc); i++)					\
    if (cc[i])							\
      {								\
	uint32_t r;						\
	if (p + 5 > length)					\
	  goto fail;						\
								\
	r = ((bits) & (cc)[i]) ? 1 : 0;				\
	lsh_string_putc(new, p++, i+(offset));			\
	lsh_string_write_uint32(new, p, r);			\
	p += 4;							\
      }								\
} while(0)
     
struct lsh_string *
tty_encode_term_mode(const struct termios *ios)
{
  unsigned int i;
  struct lsh_string *new;
  uint32_t p = 0;
  const uint32_t length = 650;
  new = lsh_string_alloc(length);

  for (i=0; i<SIZE(termios_cc_index); i++)
    {
      if (termios_cc_index[i] != -1)
	{
	  if (p + 5 > length)
	    goto fail;

	  lsh_string_putc(new, p++, i+1);
	  lsh_string_write_uint32(new, p, ios->c_cc[termios_cc_index[i]]);
	  p += 4;
	}
    }
  ENCODE_FLAGS(termios_iflags, ios->c_iflag, 30);
  ENCODE_FLAGS(termios_lflags, ios->c_lflag, 50);
  ENCODE_FLAGS(termios_oflags, ios->c_oflag, 70);
  ENCODE_FLAGS(termios_cflags, ios->c_cflag, 90);

  if (p + 1 > length)
    goto fail;

  lsh_string_putc(new, p++, 0);
  lsh_string_trunc(new, p);
  
  return new;

fail:
  lsh_string_free(new);
  return NULL;
}

#define TTY_DECODE_FLAG(target, flag, table, index)	\
do {							\
  int _mask;						\
  if ((index) < SIZE(table)				\
      && ((_mask = (table)[index]) > 0))		\
    {							\
      if (flag)						\
	(target) |= _mask;				\
      else						\
	(target) &= ~_mask;				\
    }							\
} while(0)
      
/* Interpret ssh:s terminal description */
int
tty_decode_term_mode(struct termios *ios, uint32_t t_len, const uint8_t *t_modes)
{
  struct simple_buffer buffer;
  
  simple_buffer_init(&buffer, t_len, t_modes);
  
  for (;;)
    {
      unsigned opcode;
      uint32_t param;
      
      if (!parse_uint8(&buffer, &opcode))
	return 0;
	
      if ( (opcode == SSH_TTY_OP_END)
	   || (opcode >= SSH_TTY_OP_RESERVED))
	break;

      if (!parse_uint32(&buffer, &param))
	return 0;

      if (opcode < 30)
	{
	  unsigned flag_index = opcode - 1;
	      
	  if (flag_index < SIZE(termios_cc_index))
	    {
	      int index = termios_cc_index[flag_index];
	      if (index >= 0)
		ios->c_cc[index] = param;
	    }
	}
      else if (opcode < 50)
	TTY_DECODE_FLAG(ios->c_iflag, param, termios_iflags, opcode - 30);
      else if (opcode < 70)
	TTY_DECODE_FLAG(ios->c_lflag, param, termios_lflags, opcode - 50);
      else if (opcode < 90)
	TTY_DECODE_FLAG(ios->c_oflag, param, termios_oflags, opcode - 70);
      else if (opcode < 128)
	TTY_DECODE_FLAG(ios->c_cflag, param, termios_cflags, opcode - 90);
      else
	{
	  switch(opcode)
	    {
	    case SSH_TTY_OP_ISPEED:
	    case SSH_TTY_OP_OSPEED:
	      /* FIXME: set input/output speed there's no point
	       * in setting the speed of a pseudo tty IMHO */
	      /* The speed of the user's terminal could be
	       * useful for programs like emacs that try to
	       * optimize the redraw algorithm (slower
	       * terminals gets partial updates. But that is
	       * pretty useless as long as 9600 bps is
	       * considered fast... */
	      break;
	    default:
	      werror("Unsupported terminal mode: %i\n", opcode);
	    }
	}
    }
  return 1;
}

#endif /* WITH_PTY_SUPPORT */
