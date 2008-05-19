/* unix_interact.c
 *
 * Interact with the user. Implements the fairly abstract interface in
 * interact.h.
 *
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 1999, 2008 Niels Möller
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

#include <assert.h>
#include <errno.h>
#include <string.h>

#include <signal.h>

#include <fcntl.h>
#include <termios.h>
#if HAVE_UNISTD_H
# include <unistd.h>
#endif

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include "interact.h"

#include "format.h"
#include "io.h"
#include "lsh_string.h"
#include "resource.h"
#include "tty.h"
#include "werror.h"
#include "xalloc.h"

#include "unix_interact.c.x"

static int tty_fd = -1;
static const char *askpass_program = NULL;
static struct termios original_mode;
static struct termios raw_mode;

#define IS_TTY() ((tty_fd) >= 0)

#define GET_ATTR(ios) (tcgetattr(tty_fd, (ios)))
#define SET_ATTR(ios) (tcsetattr(tty_fd, TCSADRAIN, (ios)))

/* On SIGTSTP, we record the tty mode and the stdio flags, and restore
   the tty to the original mode. */
static void
stop_handler(int signum)
{
  struct termios mode;
  int stdin_flags;
  int stdout_flags;
  int stderr_flags;
  
  assert(signum == SIGTSTP);

  stdin_flags = fcntl(STDIN_FILENO, F_GETFL);
  stdout_flags = fcntl(STDOUT_FILENO, F_GETFL);
  stderr_flags = fcntl(STDERR_FILENO, F_GETFL);

  if (tty_fd >= 0)
    {
      GET_ATTR(&mode);
      SET_ATTR(&original_mode);
    }

  kill(getpid(), SIGSTOP);

  if (tty_fd >= 0)
    SET_ATTR(&mode);

  if (stdin_flags >= 0)
    fcntl(STDIN_FILENO, F_SETFL, stdin_flags);

  if (stdout_flags >= 0)
    fcntl(STDOUT_FILENO, F_SETFL, stdout_flags);

  if (stderr_flags >= 0)
    fcntl(STDERR_FILENO, F_SETFL, stderr_flags);
}

static void
restore_tty(void)
{
  SET_ATTR(&original_mode);
}

int
unix_interact_init(int prepare_raw_mode)
{
  tty_fd = open("/dev/tty", O_RDWR);
  if (IS_TTY())
    {
      io_set_close_on_exec(tty_fd);

      if (prepare_raw_mode)
	{
	  if (GET_ATTR(&original_mode) == -1)
	    {
	      werror("interact_init: tty_getattr failed %e\n", errno);
	      return 0;
	    }
	  else
	    {
	      struct sigaction stop;

	      memset(&stop, 0, sizeof(stop));
	      stop.sa_handler = stop_handler;

	      if (sigaction(SIGTSTP, &stop, NULL) < 0)
		{
		  werror("interact_init: Failed to install SIGTSTP handler %e\n", errno);
		  return 0;
		}
	      raw_mode = original_mode;
	  
	      /* The flags part definition is from the linux cfmakeraw man
	       * page. */
	      raw_mode.c_iflag &= ~(IGNBRK|BRKINT|PARMRK|ISTRIP|INLCR|IGNCR|ICRNL|IXON);
	      raw_mode.c_oflag &= ~OPOST;
	      raw_mode.c_lflag &= ~(ECHO|ECHONL|ICANON|ISIG|IEXTEN);

	      raw_mode.c_cflag &= ~(CSIZE|PARENB);
	      raw_mode.c_cflag |= CS8;

	      /* Modify VMIN and VTIME, to save some bandwidth and make
	       * traffic analysis of interactive sessions a little harder.
	       * (These use the same fields as VEOF and VEOL)*/
	      raw_mode.c_cc[VMIN] = 3;
	      /* Inter-character timer, in units of 0.1s */
	      raw_mode.c_cc[VTIME] = 2;

	      if (atexit(restore_tty) < 0)
		{
		  werror("interact_init: atexit failed.\n");
		  return 0;
		}
	    }
	}
    }
  return 1;
}

int
interact_is_tty(void)
{
  return tty_fd >= 0;
}

void
interact_set_askpass(const char *askpass)
{
  askpass_program = askpass;
}

/* Depends on the tty being line buffered. FIXME: Doesn't distinguish
   between errors, empty input, and EOF. */
static uint32_t
read_line(uint32_t size, uint8_t *buffer)
{
  uint32_t i = 0;

  while (i < size)
    {
      int res = read(tty_fd, buffer + i, size - i);
      if (!res)
	/* User pressed EOF (^D) */
	return i;
      else if (res < 0)
	switch(errno)
	  {
	  case EAGAIN:
	  case EINTR:
	    break;
	  default:
	    /* I/O error */
	    werror("unix_interact.c: read_line, %e\n", errno);
	    return 0;
	  }
      else
	{
	  uint32_t j;
	  for (j = 0; j < (unsigned) res; j++, i++)
	    if (buffer[i] == '\n')
	      return i;
	}
    }
  /* We have filled our buffer already; continue reading until end of line */
#define BUFSIZE 512
  for (;;)
    {
      uint8_t b[BUFSIZE];
      int res = read(tty_fd, b, BUFSIZE);
      if (!res)
	/* EOF */
	return size;
      else if (res < 0)
	switch(errno)
	  {
	  case EAGAIN:
	  case EINTR:
	    break;
	  default:
	    /* I/O error */
	    werror("tty_read_line %e\n", errno);
	    return 0;
	  }
      else
	{
	  uint32_t j;
	  for (j = 0; j < (unsigned) res; j++)
	    if (b[j] == '\n')
	      return size;
	}
    }
#undef BUFSIZE
}

int
interact_yes_or_no(const struct lsh_string *prompt, int def, int free)
{
#define TTY_BUFSIZE 10

  if (!IS_TTY())
    {
      if (free)
	lsh_string_free(prompt);
      return def;
    }
  else
    for (;;)
      {
	uint8_t buffer[TTY_BUFSIZE];
	int res;
      
	res = write_raw(tty_fd, STRING_LD(prompt));

	if (free)
	  lsh_string_free(prompt);

	if (!res)
	  return def;

	if (!read_line(sizeof(buffer), buffer))
	  return def;

	switch (buffer[0])
	  {
	  case 'y':
	  case 'Y':
	    return 1;
	  case 'n':
	  case 'N':
	    return 0;
	  default:
	    /* Try again. */
	    ;
	  }
      }
#undef TTY_BUFSIZE
}

/* FIXME: Rewrite to operate on tty_fd? */
static struct lsh_string *
read_password(const struct lsh_string *prompt)
{
  if (askpass_program)
    {
      const char *argv[3];
      
      int null = open("/dev/null", O_RDONLY);
      
      if (null < 0)
	{
	  werror("Failed to open /dev/null!\n");
	  
	  return NULL;
	}
      
      argv[0] = askpass_program;
      argv[1] = lsh_get_cstring(prompt);

      if (!argv[1])
	{
	  close(null);

	  return NULL;
	}
      argv[2] = NULL;

      trace("unix_interact.c: spawning askpass program `%z'\n",
	    askpass_program);

      return lsh_popen_read(askpass_program, argv, null, 100);
    }
  else
    {
      /* NOTE: Ignores max_length; instead getpass's limit applies. */
  
      char *password;
      const char *cprompt;

      if (!IS_TTY())
	return NULL;

      cprompt = lsh_get_cstring(prompt);      
      if (!cprompt)
	return NULL;

      /* NOTE: This function uses a static buffer. */
      password = getpass(cprompt);

      if (!password)
	return NULL;
  
      return make_string(password);
    }
}

struct lsh_string *
interact_read_password(const struct lsh_string *prompt)
{
  struct lsh_string *passwd = read_password(prompt);
  lsh_string_free(prompt);

  return passwd;
}

/* The prompts are typically not trusted, but it's the callers
   responsibility to sanity check them. */
int
interact_dialog(const struct interact_dialog *dialog)
{
#define DIALOG_BUFSIZE 150
  unsigned i;

  if (!IS_TTY())
    return 0;

  if (!write_raw(tty_fd, STRING_LD(dialog->instruction)))
    return 0;

  for (i = 0; i < dialog->nprompt; i++)
    {
      struct lsh_string *prompt = dialog->prompt[i];
      if (dialog->echo[i])
	{
	  uint8_t buffer[DIALOG_BUFSIZE];
	  uint32_t length;
	  
	  if (!write_raw(tty_fd, STRING_LD(prompt)))
	    return 0;
	  length = read_line(sizeof(buffer), buffer);
	  if (!length)
	    return 0;
	  
	  dialog->response[i] = ssh_format("%ls", length, buffer);
	}
      else
	{
	  if (!(dialog->response[i] = read_password(prompt)))
	    return 0;
	}
    }
  return 1;
}

int
interact_set_mode(int raw)
{
  int res;

  if (raw)
    res = SET_ATTR(&raw_mode);
  else
    res = SET_ATTR(&original_mode);

  return res != -1;
}

int
interact_get_window_size(struct winsize *dims)
{
  return ioctl(tty_fd, TIOCGWINSZ, dims) != -1;
}

/* GABA:
   (class
     (name winch_handler)
     (super lsh_callback)
     (vars
       (callback object window_change_callback)))
*/

static void
do_winch_handler(struct lsh_callback *s)
{
  CAST(winch_handler, self, s);
  struct winsize dims;

  if (interact_get_window_size(&dims))
    self->callback->f(self->callback, &dims);
}

static struct lsh_callback *
make_winch_handler(struct window_change_callback *callback)
{
  NEW(winch_handler, self);
  self->super.f = do_winch_handler;
  self->callback = callback;

  return &self->super;  
}

struct resource *
interact_on_window_change(struct window_change_callback *callback)
{
  return io_signal_handler(SIGWINCH, make_winch_handler(callback));
}

/* NOTE: It would be somewhat cleaner to call tty_encode_term_mode
   here, but returning the termios structure and leaving the
   conversion makes this file more self-contained, avoiding a link
   dependency on tty.o. */
const struct termios *
interact_get_terminal_mode(void)
{
  return &original_mode;
}
