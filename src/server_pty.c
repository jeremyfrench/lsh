/* server_pty.h
 *
 * $Id$
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1998, 1999, Niels Möller, Balazs Scheidler
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

#include "server_pty.h"
#include "xalloc.h"

#include "parse.h"
#include "connection.h"
#include "channel.h"
#include "werror.h"

#include "ssh.h"

#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>  /* FIXME: for snprintf, maybe use a custom snprintf? Bazsi */

#define CLASS_DEFINE
#include "server_pty.h.x"
#undef CLASS_DEFINE

static void do_kill_pty_info(struct resource *r)
{
  CAST(pty_info, closure, r);

  if (closure->alive)
    {
      closure->alive = 0;
      if (close(closure->master) < 0)
	werror("do_kill_pty_info: closing master failed (errno = %d): %s\n",
	       errno, strerror(errno));
      if (close(closure->slave) < 0)
	werror("do_kill_pty_info: closing slave failed (errno = %d): %s\n",
	       errno, strerror(errno));
    }
}

struct pty_info *make_pty_info(void)
{
  NEW(pty_info, pty);

  pty->super.alive = 0;
  pty->super.kill = do_kill_pty_info;

  return pty;
}

#if HAVE_OPENPTY

int pty_allocate(struct pty_info *pty)
{
  return openpty(&pty->fd_master, &pty->fd_slave, NULL, NULL, NULL) == 0 ?
         1 : 0;
}

#elif PTY_BSD_SCHEME

#define PTY_BSD_SCHEME_MASTER "/dev/pty%c%c"
#define PTY_BSD_SCHEME_SLAVE  "/dev/tty%c%c"

int pty_allocate(struct pty_info *pty)
{
  char first[] = PTY_BSD_SCHEME_FIRST_CHARS;
  char second[] = PTY_BSD_SCHEME_SECOND_CHARS;
  char master[MAX_TTY_NAME], slave[MAX_TTY_NAME];
  unsigned int i, j;
  int saved_errno;

  for (i = 0; i < sizeof(first); i++)
    {
      for (j = 0; j < sizeof(second); j++) 
        {
	  snprintf(master, sizeof(master),
		   PTY_BSD_SCHEME_MASTER, first[i], second[j]);
			
	  pty->master = open(master, O_RDWR | O_NOCTTY);
	  if (pty->master != -1) 
	    {
	      /* master succesfully opened */
	      snprintf(slave, sizeof(slave),
		       PTY_BSD_SCHEME_SLAVE, first[i], second[j]);
				
	      pty->slave = open(slave, O_RDWR | O_NOCTTY);
	      if (pty->slave == -1) 
	        {
		  saved_errno = errno;
		  close(pty->master);
		  pty->master = -1;
		  errno = saved_errno;
		  return 0;
	        }
	      
              return 1;
	    }
        }
    }
  return 0;
}

#endif

static int cc_ndx[];
static int cc_iflags[];
static int cc_oflags[];
static int cc_lflags[];
static int cc_cflags[];

#define TTY_SET_VALUE(target, param, table, index)	\
do {							\
  int _value;						\
  if ((index) < (sizeof(table) / sizeof((table)[0]))	\
      && ((_value = (table)[index]) >= 0))		\
    target[_value] = param;				\
} while(0)

#define TTY_SET_FLAG(target, flag, table, index)	\
do {							\
  int _mask;						\
  if ((index) < (sizeof(table) / sizeof((table)[0]))	\
      && ((_mask = (table)[index]) >= 0))		\
    {							\
      if (flag)						\
	(target) |= _mask;				\
      else						\
	(target) &= ~_mask;				\
    }							\
} while(0)
      
/* Interpret ssh:s terminal description */
void tty_interpret_term_modes(struct termios *ios, UINT32 t_len, UINT8 *t_modes)
{
  struct simple_buffer buffer;
  
  done = 0;
  simple_buffer_init(&buffer, t_len, t_modes);
  
  for (;;)
    {
      int opcode;
      
      if (parse_uint8(&buffer, &opcode))
	{
	  UINT32 param;

	  if ( (opcode == SSH_TTY_OP_END)
	       || (opcode > SSH_TTY_OP_RESERVED))
	    break;

	  /* FIXME: I believe that the argument is an 8-bit octet. Is
	   * this correct? */
	  if (parse_uint32(&buffer, &param))
	    {
	      /* FIXME: This code might be simplified a little. I
	       * think some table lookups (mapping each opcode to some
	       * "action class", including ranges to check as well as
	       * further tables... Something like 

	      struct action = at[opcode];
	      switch (action->type)
		{
		case ACTION_FLAG:
		  ...
	      */
	      if (opcode < 30) 
		TTY_SET_VALUE(ios->c_cc, param, cc_ndx, opcode - 1);
	      else if (opcode < 50)
		TTY_SET_FLAG(ios->c_iflag, param, cc_iflags, opcode - 30);
	      else if (opcode < 75)
		TTY_SET_FLAG(ios->c_lflag, param, cc_lflags, opcode - 50);
	      else if (opcode < 90)
		TTY_SET_FLAG(ios->c_oflag, param, cc_oflags, opcode - 70);
	      else if (opcode < 128)
		TTY_SET_FLAG(ios->c_cflag, param, cc_cflags, opcode - 90);
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
		      /* NOTE: How are baudrates represented? an uint8
		       * is not large enough for an integer bps-rate.
		       * So I would guess that some (particular
		       * representation of) the Bn constants of
		       * termios.h/termbits.h are used. */
		      break;
		    default:
		      werror("Unsupported terminal mode: %d\n", opcode);
                }
            }
        }
      else
        done = 1;
    }
}

static int cc_ndx[] = 
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

static int cc_iflags[] = {
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

static int cc_oflags[] = {
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

static int cc_cflags[] = {
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

static int cc_lflags[] = {
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
