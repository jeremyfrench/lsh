/* unix_random.c
 *
 * $Id$
 *
 * Randomness polling on unix, using ideas from Peter Gutmann's
 * cryptlib. */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 2000 Niels Möller
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

#include "randomness.h"
#include "reaper.h"

#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>

enum poll_status { POLL_NO_POLL, POLL_RUNNING, POLL_FINISHED, POLL_FAILED };

/* GABA:
   (class
     (name unix_random)
     (super random_poll)
     (vars
       ;; For the slow poll
       (reaper object reap)
       (poll_uid . uid_t)
       (pid . pid_t)
       (status . "enum poll_status")
       ; NOTE: This fd is not known to the gc. 
       (fd . int)
     
       ;; For the fast poll, count number of slow polls per second.
       (previous_time . time_t)
       (time_count . unsigned)))
*/

/* GABA:
   (class
     (name unix_random_callback)
     (super exit_callback)
     (vars
       (ctx object unix_random)))
*/

static void
do_unix_random_callback(struct exit_callback *s,
			int signalled, int core, int value)
{
  CAST(unix_random_callback, self, s);
  self->ctx->status = (signalled || value)
    ? POLL_FAILED
    : POLL_FINISHED;
}

static struct exit_callback *
make_unix_random_callback(struct unix_random *ctx)
{
  NEW(unix_random_callback, self);
  self->super.exit = do_unix_random_callback;
  self->ctx = ctx;

  return &self->super;
}

#define UNIX_RANDOM_POLL_SIZE 20

/* This structure ought to fit in a pipe buffer (so that we can
 * waitpid() the process before reading its stdout). */

struct unix_random_poll_result
{
  UINT32 count;
  UINT8 data[UNIX_RANDOM_POLL_SIZE];
};

#define UNIX_RANDOM_SOURCE_SCALE 8192
struct unix_random_source
{
  const char *path;
  const char *arg; /* For now, use at most one argument. */
  int has_alternative;

  unsigned rounding; /* Add this before rounding */
  /* Bits of entropy per UNIX_RANDOM_SOURCE_SCALE bytes of output. */
  unsigned quality;
};

/* Lots of output expected; round downwards. */
#define WLARGE(x) 0, x
/* Small but significant output expected; round upwards */
#define WSMALL(x) (UNIX_RANDOM_SOURCE_SCALE - 1), x

static const struct unix_random_source random_sources[] =
{
  { "/bin/vmstat", "-s", 		WSMALL(30), 1 },
  { "/usr/bin/vmstat", "-s", 		WSMALL(30), 0 },
  { "/bin/vmstat", "-c", 		WSMALL(30), 1 },
  { "/usr/bin/vmstat", "-c", 		WSMALL(30), 0 },
  { "/usr/bin/pfstat", NULL, 		WSMALL(20), 0 },
  { "/bin/vmstat", "-i", 		WSMALL(20), 1 },
  { "/usr/bin/vmstat", "-i", 		WSMALL(20), 0 },
  { "/usr/ucb/netstat", "-s", 	WLARGE(20), 1 },
  { "/usr/bin/netstat", "-s", 	WLARGE(20), 1 },
  { "/usr/sbin/netstat", "-s", 	WLARGE(20), 1 },
  { "/bin/netstat", "-s", 		WLARGE(20), 1 },
  { "/usr/etc/netstat", "-s", 	WLARGE(20), 0 },
  { "/usr/bin/nfsstat", NULL, 	WLARGE(20), 0 },
  { "/usr/ucb/netstat", "-m", 	WSMALL(10), 1 },
  { "/usr/bin/netstat", "-m", 	WSMALL(10), 1 },
  { "/usr/sbin/netstat", "-m", 	WSMALL(10), 1 },
  { "/bin/netstat", "-m", 		WSMALL(10), 1 },
  { "/usr/etc/netstat", "-m", 	WSMALL(10), 0 },
  { "/usr/ucb/netstat", "-in", 	WSMALL(10), 1 },
  { "/usr/bin/netstat", "-in", 	WSMALL(10), 1 },
  { "/usr/sbin/netstat", "-in", 	WSMALL(10), 1 },
  { "/bin/netstat", "-in", 		WSMALL(10), 1 },
  { "/usr/etc/netstat", "-in", 	WSMALL(10), 0 },
#if 0
  { "/usr/sbin/snmp_request", "localhost public get 1.3.6.1.2.1.7.1.0", 	WSMALL(10), 0 }, /* UDP in */
  { "/usr/sbin/snmp_request", "localhost public get 1.3.6.1.2.1.7.4.0", 	WSMALL(10), 0 }, /* UDP out */
  { "/usr/sbin/snmp_request", "localhost public get 1.3.6.1.2.1.4.3.0", 	WSMALL(10), 0 }, /* IP ? */
  { "/usr/sbin/snmp_request", "localhost public get 1.3.6.1.2.1.6.10.0", 	WSMALL(10), 0 }, /* TCP ? */
  { "/usr/sbin/snmp_request", "localhost public get 1.3.6.1.2.1.6.11.0", 	WSMALL(10), 0 }, /* TCP ? */
  { "/usr/sbin/snmp_request", "localhost public get 1.3.6.1.2.1.6.13.0", 	WSMALL(10), 0 }, /* TCP ? */
#endif
  { "/usr/bin/mpstat", NULL, 		WLARGE(10), 0 },
  { "/usr/bin/w", NULL, 		WLARGE(10), 1 },
  { "/usr/bsd/w", NULL, 		WLARGE(10), 0 },
  { "/usr/bin/df", NULL, 		WLARGE(10), 1 },
  { "/bin/df", NULL, 			WLARGE(10), 0 },
  { "/usr/sbin/portstat", NULL, 	WLARGE(10), 0 },
  { "/usr/bin/iostat", NULL, 		WLARGE(0), 0 },
  { "/usr/bin/uptime", NULL, 		WLARGE(0), 1 },
  { "/usr/bsd/uptime", NULL, 		WLARGE(0), 0 },
  { "/bin/vmstat", "-f", 		WLARGE(0), 1 },
  { "/usr/bin/vmstat", "-f", 		WLARGE(0), 0 },
  { "/bin/vmstat", NULL, 		WLARGE(0), 1 },
  { "/usr/bin/vmstat", NULL, 		WLARGE(0), 0 },
  { "/usr/ucb/netstat", "-n", 	WLARGE(5), 1 },
  { "/usr/bin/netstat", "-n", 	WLARGE(5), 1 },
  { "/usr/sbin/netstat", "-n", 	WLARGE(5) , 1 },
  { "/bin/netstat", "-n", 		WLARGE(5) , 1 },
  { "/usr/etc/netstat", "-n", 	WLARGE(5) , 0 },
#if defined( __sgi ) || defined( __hpux )
  { "/bin/ps", "-el", 		WLARGE(3), 1 },
#endif /* __sgi || __hpux */
  { "/usr/ucb/ps", "aux", 		WLARGE(3), 1 },
  { "/usr/bin/ps", "aux", 		WLARGE(3), 1 },
  { "/bin/ps", "aux", 		WLARGE(3), 0 },
  { "/usr/bin/ipcs", "-a", 		WLARGE(5), 1 },
  { "/bin/ipcs", "-a", 		WLARGE(5), 0 },
  /* Unreliable source, depends on system usage */
  { "/etc/pstat", "-p", 		WLARGE(5), 1 },
  { "/bin/pstat", "-p", 		WLARGE(5), 0 },
  { "/etc/pstat", "-S", 		WLARGE(2), 1 },
  { "/bin/pstat", "-S", 		WLARGE(2), 0 },
  { "/etc/pstat", "-v", 		WLARGE(2), 1 },
  { "/bin/pstat", "-v", 		WLARGE(2), 0 },
  { "/etc/pstat", "-x", 		WLARGE(2), 1 },
  { "/bin/pstat", "-x", 		WLARGE(2), 0 },
  { "/etc/pstat", "-t", 		WLARGE(1), 1 },
  { "/bin/pstat", "-t", 		WLARGE(1), 0 },
  /* pstat is your friend */
  { "/usr/bin/last", "-n 50", 	WLARGE(3), 1 },
#ifdef __sgi
  { "/usr/bsd/last", "-50", 		WLARGE(3), 0 },
#endif /* __sgi */
#ifdef __hpux
  { "/etc/last", "-50", 		WLARGE(3), 0 },
#endif /* __hpux */
  { "/usr/bsd/last", "-n 50", 	WLARGE(3), 0 },
  { "/usr/local/bin/lsof", "-lnwP", 	WLARGE(3), 0 },
  /* Output is very system and version-dependent */
#if 0
  { "/usr/sbin/snmp_request", "localhost public get 1.3.6.1.2.1.5.1.0", 	WLARGE(1), 0 }, /* ICMP ? */
  { "/usr/sbin/snmp_request", "localhost public get 1.3.6.1.2.1.5.3.0", 	WLARGE(1), 0 }, /* ICMP ? */
#endif
  { "/etc/arp", "-a", 		WLARGE(1), 1 },
  { "/usr/etc/arp", "-a", 		WLARGE(1), 1 },
  { "/usr/bin/arp", "-a", 		WLARGE(1), 1 },
  { "/usr/sbin/arp", "-a", 		WLARGE(1), 0 },
  { "/usr/sbin/ripquery", "-nw 1 127.0.0.1", 	WLARGE(1 ), 0 },
  { "/bin/lpstat", "-t", 		WLARGE(1), 1 },
  { "/usr/bin/lpstat", "-t", 		WLARGE(1), 1 },
  { "/usr/ucb/lpstat", "-t", 		WLARGE(1), 0 },
#if 0
  { "/usr/bin/tcpdump", "-c 5 -efvvx",WLARGE(10), 0 },
  /* This is very environment-dependant.  If
     network traffic is low, it'll probably time
     out before delivering 5 packets, which is OK
     because it'll probably be fixed stuff like
     ARP anyway */
  { "/usr/sbin/advfsstat", "-b usr_domain", 	WLARGE(0), 0 },
  { "/usr/sbin/advfsstat", "-l 2 usr_domain", 	WLARGE(5), 0 },
  { "/usr/sbin/advfsstat", "-p usr_domain", 	WLARGE(0), 0 },
  /* This is a complex and screwball program.  Some
     systems have things like rX_dmn, x = integer,
     for RAID systems, but the statistics are
     pretty dodgy */

  /* The following aren't enabled since they're somewhat slow and not very
     unpredictable, however they give an indication of the sort of sources
     you can use (for example the finger might be more useful on a
     firewalled internal network) */
  { "/usr/bin/finger", "@ml.media.mit.edu", 	WLARGE(9), 0 },
  { "/usr/local/bin/wget", "-O - http://lavarand.sgi.com/block.html", 	WLARGE(9 ), 0 },
  { "/bin/cat", "/usr/spool/mqueue/syslog", 	WLARGE(9), 0 },
#endif /* 0 */
  { NULL, NULL, 0, 0 }
};

#undef WSMALL
#undef WLARGE

struct unix_random_source_state
{
  const struct unix_random_source *source;
  pid_t pid;       /* Running process. */
  int fd;
  unsigned length; /* Amount of data read so far. */
};

static int
spawn_source_process(unsigned *index,
		     struct unix_random_source_state *state)
{
  unsigned i;
  for (i = *index; random_sources[i].path; )
    {
      int output[2];
      pid_t pid;
      
      if (access(random_sources[i].path, X_OK) < 0)
	{
	  debug("spawn_source_process: Can't execute '%z': %z\n",
		random_sources[i].path, STRERROR(errno));
	  i++;
	}
      else
	break;
    }

  if (!lsh_make_pipe(output))
    {
      werror("spawn_source_process: Can't create pipe (errno = %i): %z\n",
	     errno, STRERROR(errno));
      return 0;
    }
  
  state->source = random_sources + i;
  
  if (!random_sources[i].has_alternative)
    i++;
  else
    /* Skip alternatives */
    while (random_sources[i].has_alternative)
      i++;
  
  *index = i;
  
  pid = fork();
  switch(pid)
    {
    default:
      /* Parent */
      close (output[1]);
      state->fd = output[0];
      io_set_close_on_exec(self->fd);
      state->amount = 0;
      return 1;
      
    case -1:
      /* Error */
      return 0;
    case 0:
      /* Child */
      if (dup2(output[1], STDOUT_FILENO))
	{
	  werror("spawn_source_process: dup2 for stdout failed (errno = %i): %z\n",
		 errno, STRERROR(errno));
	  _exit(EXIT_FAILURE);
	}
      close (output[0]);
      close (output[1]);
      
      /* Works also if state->source.arg == NULL */
      execl(state->source.path, state->source.arg, NULL);
      
      werror("spawn_source_process: execl '%z' failed (errno = %i): %z\n",
	     state->source.path, errno, STRERROR(errno));
      
      _exit(EXIT_FAILURE);
    }
}

     
/* Spawn this number of processes. */
#define UNIX_RANDOM_POLL_PROCESSES 10


static void
background_poll(struct unix_random_poll_result *result)
{
  struct unix_random_source_state state[UNIX_RANDOM_POLL_PROCESSES];
  unsigned running = 0;
  unsigned i = 0;
  
  for (running = 0; running<UNIX_RANDOM_POLL_PROCESSES; running++)
    {
    }
  
  
}

static void
start_background_poll(struct unix_random *self)
{
  pid_t pid;
  int output[2];
  int null;
  
  assert(self->status == POLL_NO_POLL);
  
  if (!lsh_make_pipe(output))
    {
      werror("Failed to create pipe for background randomness poll.\n");
      return;
    }

  null = open("/dev/null", O_RDONLY);
  if (dup2(null, STDIN_FILENO) < 0)
    werror("start_background_poll: dup2 for stdin failed (errno = %i): %z\n",
	   errno, STRERROR(errno));

  close(null);
  
  pid = fork();  
  switch(pid)
    {
    default:
      /* Parent */
      close(output[1]);
      self->fd = output[0];
      io_set_close_on_exec(self->fd);
      
      REAP(self->reaper, pid, make_unix_random_callback(self));
      self->status = POLL_RUNNING;
      return;

    case -1:
      /* Error */
      werror("Failed to fork background randomness poll (errno = %i): %z\n",
	     errno, STRERROR(errno));
      return;
      
    case 0:
      /* Child */
      {
	struct unix_random_poll_result result;
	
	close(output[0]);
	io_set_close_on_exec(output[1]);
	
	/* Change uid */
	if (!getuid())
	  setuid(self->poll_uid);
	
	if (!getuid())
	  _exit(1);

	background_poll(&result);
	if (!write_raw(output[1], sizeof(result), (UINT8 *) &result))
	  _exit(0);

	_exit(2);
      }
    }
}

static void
wait_background_poll(struct unix_random *self)
{
  int status;
  pid_t child;
  
  assert(self->state == POLL_RUNNING);
  self->state = POLL_FAILED;
  
  if (waitpid(self->pid, &status, 0) == self->pid)
    {
      if (WIFEXITED(status) && !WEXITSTATUS(status))
	self->status = POLL_FINISHED;
    }

  REAP(self->reaper, self->pid, NULL);  
}


static unsigned
finish_background_poll(struct unix_random *self, struct hash_instance *hash)
{
  unsigned count;

  switch(self->status)
    {
    case POLL_FINISHED:
      {
	struct unix_random_poll_result result;
	const struct exception *e;
	
	e = read_raw(self->fd, sizeof(result), (UINT8 *) &result);
	
	if (e)
	  werror("Failed to read result from background randomness poll.\n");
	else
	  {
	    HASH_UPDATE(hash, UNIX_RANDOM_POLL_SIZE, result.data);
	    count = result.count;
	  }
	break;
      }
    case POLL_FAILED:
      werror("Background randomness poll failed.\n");
      count = 0;
      break;

    case POLL_NO_POLL:
      return 0;
      
    default:
      fatal("finish_background_poll: Internal error.\n");
    }
  close(self->fd);
  self->status = POLL_NO_POLL;

  return count;
}  

static unsigned
do_unix_random_slow(struct random_poll *s, struct hash_instance *hash)
{
  CAST(unix_random, self, s);
  unsigned count;
  
  if (self->status == POLL_NO_POLL)
    start_background_poll(self);

  if (self->status == POLL_RUNNING)
    wait_background_poll(self);

  count = finish_background_poll(self, hash);

  count += use_seed_file(hash);
  count += use_procfs(hash);

  return count;
}

#define HASH_OBJECT(hash, x) HASH_UPDATE((h), sizeof(x), (UINT8 *) &(x))

static unsigned
do_unix_random_fast(struct random_poll *s, struct hash_instance *hash)
{
  unsigned count = 0;

#if HAVE_GETRUSAGE
  {
    struct rusage rusage;
    if (getrusage(RUSAGE_SELF, &rusage) < 0)
      fatal("do_unix_random_fast: getrusage() failed: (errno = %i) %z\n",
	    errno, STRERROR(errno));
    
    HASH_OBJECT(hash, rusage);
    count += 1;
  }
#endif /* HAVE_GETRUSAGE */
#if HAVE_GETTIMEOFDAY
  {
    struct timeval tv;
    if (gettimeofday(&tv, NULL) < 0)
      fatal("do_unix_random_fast: gettimeofday failed(errno = %i) %z\n",
	    errno, STRERROR(errno));

    HASH_OBJECT(hash, tv);
  }
#endif /* HAVE_GETTIMEOFDAY */

  {
    /* Fallback that is useful if nothing else works. Count the number
     * of slow polls between time() ticks, and count one bit of
     * entropy if we have more than 2 calls or more than two seconds
     * between calls. */
    
    time_t now = time(NULL);
    self->time_count++;
    if (now != self->previous_time)
      {
	if ( (self->time_count > 2) || ((now - self->previous_time) > 2))
	  count++;
	
	HASH_OBJECT(hash, now);
	HASH_OBJECT(self->time_count);
	
	self->time_count = 0;
	self->previous_time = now;
      }
  }

  return count;
}

