/* lsh-make-seed.c
 *
 * Creates an initial yarrow seed file
 *
 * $id:$
 */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 2001 Niels Möller
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

#include "format.h"
#include "version.h"
#include "werror.h"
#include "xalloc.h"

#include "nettle/yarrow.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#if WITH_ZLIB

#if HAVE_ZLIB_H
#include <zlib.h>
#endif

/* FIXME: Duplicated in zlib.c */

/* zlib memory functions */
static void *
zlib_alloc(void *opaque UNUSED, unsigned int items, unsigned int size)
{
  return lsh_space_alloc(items * size);
}

static void
zlib_free(void *opaque UNUSED, void *address)
{
  lsh_space_free(address);
}

#endif /* WITH_ZLIB */

#include "lsh-make-seed.c.x"

/* Option parsing */

const char *argp_program_version
= "lsh-make-seed-" VERSION;

const char *argp_program_bug_address = BUG_ADDRESS;

/* GABA:
   (class
     (name lsh_make_seed_options)
     (vars
       (filename string)
       (force . int)))
*/

static struct lsh_make_seed_options *
make_options(void)
{
  NEW(lsh_make_seed_options, self);

  self->filename = NULL;
  self->force = 0;
  
  return self;
}

static const struct argp_option
main_options[] =
{
  /* Name, key, arg-name, flags, doc, group */
  { "output-file", 'o', "Filename", 0, "Default is ~/.lsh/seed-file", 0 },
  { "force", 'f', NULL, 0, "Overwrite any existing seed file.", 0 },
  { NULL, 0, NULL, 0, NULL, 0 }
};
  
static const struct argp_child
main_argp_children[] =
{
  { &werror_argp, 0, "", 0 },
  { NULL, 0, NULL, 0}
};

static error_t
main_argp_parser(int key, char *arg, struct argp_state *state)
{
  CAST(lsh_make_seed_options, self, state->input);

  switch(key)
    {
    default:
      return ARGP_ERR_UNKNOWN;

    case ARGP_KEY_INIT:
      state->child_inputs[0] = NULL;
      break;

    case ARGP_KEY_END:
      if (!self->filename)
	{
	  char *home = getenv("HOME");
	  struct lsh_string *s;
	  
	  if (!home)
	    {
	      argp_failure(state, EXIT_FAILURE, 0, "$HOME not set.");
	      return EINVAL;
	    }
	  else
	    {
	      s = ssh_format("%lz/.lsh", home);
	      if (mkdir(lsh_get_cstring(s), 0755) < 0)
		{
		  if (errno != EEXIST)
		    argp_failure(state, EXIT_FAILURE, errno, "Creating directory %s failed.", s->data);
		}
	      lsh_string_free(s);
	      self->filename = ssh_format("%lz/.lsh/identity", home);
	    }
	}
      break;
      
    case 'o':
      self->filename = make_string(arg);
      break;

    case 'f':
      self->force = 1;
    }
  
  return 0;
}

static const struct argp
main_argp =
{ main_options, main_argp_parser, 
  NULL,
  "Creates an initial random seed file for the YARROW pseudorandomness"
  "generator used by lsh.",
  main_argp_children,
  NULL, NULL
};


/* The sources we use. */
enum source_type
  {
    /* Data from /dev/random, if available */
    SOURCE_DEV_RANDOM,
    /* Data from /dev/mem, if we have permissions */
    SOURCE_DEV_MEM,
    /* Output from miscellaneous commands */
    SOURCE_SYSTEM,
    /* As a last resort, ask the user to type on the keyboard. */
    SOURCE_USER,

    /* Number of sources */
    NSOURCES
  };

#define DEVRANDOM_SIZE 40

static void
get_dev_random(struct yarrow256_ctx *ctx, enum source_type source)
{
  static const char *names[] = { "/dev/random", "/dev/urandom", NULL };

  int fd = -1;
  unsigned i;
  int res;
  
  char buffer[DEVRANDOM_SIZE];

  for (i = 0; names[i]; i++)
    {
      fd = open("/dev/random", O_RDONLY);
      if (fd >= 0)
	break;
    }

  if (fd < 0)
    return;

  verbose("Reading %z...\n", names[i]);

  do
    { res = read(fd, buffer, DEVRANDOM_SIZE); }
  while ( (res < 0) && (errno == EINTR));
  
  if (res < 0)
    werror("Reading from %z failed (errno = %i): %z\n",
	   names[i], errno, STRERROR(errno));

  else if (res > 0)
    {
      /* Count 4 bits of entropy for each byte. */
      verbose("Read %i bytes from /dev/random.\n",
              res);
      yarrow256_update(ctx, source, res * 4, res, buffer);
    }
  else
    werror("unix_random.c: No data available on %z\n",
	   names[i]);
  
  close(fd);
}

#define BUF_SIZE 16384

#if WITH_ZLIB
static int
update_zlib(struct yarrow256_ctx *ctx, enum source_type source,
            z_stream *z, int flush,
            unsigned length, uint8_t *buf)
{
  /* Maximum expansion is 0.1% + 12 bytes. We use 1% + 12, to be
   * conservative.
   *
   * FIXME: These figures are documented for the entire stream,
   * does they really apply to all segments? */
  
  uint8_t out[BUF_SIZE + BUF_SIZE / 100 + 12];

  unsigned compressed;
  int rc;
  
  z->next_in = buf;
  z->avail_in = length;
  z->next_out = out;
  z->avail_out = sizeof(out);
  
  if ((rc = deflate(z, flush)) != Z_OK)
    {
      werror("deflate failed: %z\n",
             z->msg ? z->msg : "No error(?)");
      werror("rc = %i, flush = %i, avail_in = %i, avail_out = %i\n",
             rc, flush, z->avail_in, z->avail_out);
      return 0;
    }

  compressed = z->next_out - out;
          
  yarrow256_update(ctx, source, compressed / 1024, compressed, out);

  return 1;
}
#endif /* WITH_ZLIB */

static void
get_dev_mem(struct yarrow256_ctx *ctx, enum source_type source)
{
  /* /dev/mem provides access to physical memory, if we
   * have enough privileges.
   *
   * Count 1 bit of entropy compressed KB, or per 10 KB uncompressed.
   */

  int fd = open("/dev/mem", O_RDONLY);
  
  if (fd < 0)
    {
      if (!getuid() || (errno != EPERM))
        werror("Couldn't open /dev/mem (errno = %i): %z\n",
               errno, STRERROR(errno));
    }
  else
    {
      char buf[BUF_SIZE];
      size_t total_read = 0;

#if WITH_ZLIB
      z_stream z;

      z.zalloc = zlib_alloc;
      z.zfree = zlib_free;
      
      if (deflateInit(&z, Z_DEFAULT_COMPRESSION) != Z_OK)
        {
          werror("deflateInit failed: %z\n",
                 z.msg ? z.msg : "No error(?)");
          close(fd);

          return;
        }
#endif /* WITH_ZLIB */

      werror("Reading /dev/mem...\n");
      for (;;)
        {
          int res;
          do
            res = read(fd, buf, BUF_SIZE);
          while ( (res < 0) && (errno != EINTR));

          if (!res)
            break;
          if (res < 0)
            {
              werror("Reading /dev/mem failed (errno = %i): %z\n",
                     errno, STRERROR(errno));
              break;
            }

          total_read += res;
#if WITH_ZLIB
          if (!update_zlib(ctx, source,
                           &z, 0,
                           res, buf))
            break;
          
#else /* !WITH_ZLIB */
          yarrow256_update(ctx, source, res / 10240, res, buf);
#endif /* !WITH_ZLIB */
        }
#if WITH_ZLIB

      update_zlib(ctx, source,
                  &z, Z_FINISH,
                  0, buf);

      verbose("Read %i MB from /dev/mem, %i MB after compression.\n",
              total_read >> 20, z.total_out >> 20);
      
      deflateEnd(&z);

#else /* !WITH_ZLIB */
      verbose("Read %i MB from /dev/mem.\n",
              total_read >> 20);
      
#endif /* !WITH_ZLIB */

      close(fd);
    }
}

static void
get_system(struct yarrow256_ctx *ctx, enum source_type source)
{
  /* List of commands based on Peter Gutmann's cryptlib,
   * misc/rndunix.c. <URL:
   * http://www.cs.auckland.ac.nz/~pgut001/cryptlib/> */

  werror("Reading system state...\n");
#if 0
  static struct RI {
	const char *path;		/* Path to check for existence of source */
	const char *arg;		/* Args for source */
	const int usefulness;	/* Usefulness of source */
	FILE *pipe;				/* Pipe to source as FILE * */
	int pipeFD;				/* Pipe to source as FD */
	pid_t pid;				/* pid of child for waitpid() */
	int length;				/* Quantity of output produced */
	const BOOLEAN hasAlternative;	/* Whether source has alt.location */
	} dataSources[] = {
	{ "/bin/vmstat", "-s", SC( -3 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/bin/vmstat", "-s", SC( -3 ), NULL, 0, 0, 0, FALSE },
	{ "/bin/vmstat", "-c", SC( -3 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/bin/vmstat", "-c", SC( -3 ), NULL, 0, 0, 0, FALSE },
	{ "/usr/bin/pfstat", NULL, SC( -2 ), NULL, 0, 0, 0, FALSE },
	{ "/bin/vmstat", "-i", SC( -2 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/bin/vmstat", "-i", SC( -2 ), NULL, 0, 0, 0, FALSE },
	{ "/usr/ucb/netstat", "-s", SC( 2 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/bin/netstat", "-s", SC( 2 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/sbin/netstat", "-s", SC( 2 ), NULL, 0, 0, 0, TRUE },
	{ "/bin/netstat", "-s", SC( 2 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/etc/netstat", "-s", SC( 2 ), NULL, 0, 0, 0, FALSE },
	{ "/usr/bin/nfsstat", NULL, SC( 2 ), NULL, 0, 0, 0, FALSE },
	{ "/usr/ucb/netstat", "-m", SC( -1 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/bin/netstat", "-m", SC( -1 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/sbin/netstat", "-m", SC( -1 ), NULL, 0, 0, 0, TRUE },
	{ "/bin/netstat", "-m", SC( -1 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/etc/netstat", "-m", SC( -1 ), NULL, 0, 0, 0, FALSE },
	{ "/usr/ucb/netstat", "-in", SC( -1 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/bin/netstat", "-in", SC( -1 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/sbin/netstat", "-in", SC( -1 ), NULL, 0, 0, 0, TRUE },
	{ "/bin/netstat", "-in", SC( -1 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/etc/netstat", "-in", SC( -1 ), NULL, 0, 0, 0, FALSE },
	{ "/usr/sbin/ntptrace", "-r2 -t1 -nv", SC( -1 ), NULL, 0, 0, 0, FALSE },
	{ "/usr/sbin/snmp_request", "localhost public get 1.3.6.1.2.1.7.1.0", SC( -1 ), NULL, 0, 0, 0, FALSE }, /* UDP in */
	{ "/usr/sbin/snmp_request", "localhost public get 1.3.6.1.2.1.7.4.0", SC( -1 ), NULL, 0, 0, 0, FALSE }, /* UDP out */
	{ "/usr/sbin/snmp_request", "localhost public get 1.3.6.1.2.1.4.3.0", SC( -1 ), NULL, 0, 0, 0, FALSE }, /* IP ? */
	{ "/usr/sbin/snmp_request", "localhost public get 1.3.6.1.2.1.6.10.0", SC( -1 ), NULL, 0, 0, 0, FALSE }, /* TCP ? */
	{ "/usr/sbin/snmp_request", "localhost public get 1.3.6.1.2.1.6.11.0", SC( -1 ), NULL, 0, 0, 0, FALSE }, /* TCP ? */
	{ "/usr/sbin/snmp_request", "localhost public get 1.3.6.1.2.1.6.13.0", SC( -1 ), NULL, 0, 0, 0, FALSE }, /* TCP ? */
	{ "/usr/bin/mpstat", NULL, SC( 1 ), NULL, 0, 0, 0, FALSE },
	{ "/usr/bin/w", NULL, SC( 1 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/bsd/w", NULL, SC( 1 ), NULL, 0, 0, 0, FALSE },
	{ "/usr/bin/df", NULL, SC( 1 ), NULL, 0, 0, 0, TRUE },
	{ "/bin/df", NULL, SC( 1 ), NULL, 0, 0, 0, FALSE },
	{ "/usr/sbin/portstat", NULL, SC( 1 ), NULL, 0, 0, 0, FALSE },
	{ "/usr/bin/iostat", NULL, SC( SC_0 ), NULL, 0, 0, 0, FALSE },
	{ "/usr/bin/uptime", NULL, SC( SC_0 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/bsd/uptime", NULL, SC( SC_0 ), NULL, 0, 0, 0, FALSE },
	{ "/bin/vmstat", "-f", SC( SC_0 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/bin/vmstat", "-f", SC( SC_0 ), NULL, 0, 0, 0, FALSE },
	{ "/bin/vmstat", NULL, SC( SC_0 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/bin/vmstat", NULL, SC( SC_0 ), NULL, 0, 0, 0, FALSE },
	{ "/usr/ucb/netstat", "-n", SC( 0.5 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/bin/netstat", "-n", SC( 0.5 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/sbin/netstat", "-n", SC( 0.5) , NULL, 0, 0, 0, TRUE },
	{ "/bin/netstat", "-n", SC( 0.5) , NULL, 0, 0, 0, TRUE },
	{ "/usr/etc/netstat", "-n", SC( 0.5) , NULL, 0, 0, 0, FALSE },
#if defined( __sgi ) || defined( __hpux )
	{ "/bin/ps", "-el", SC( 0.3 ), NULL, 0, 0, 0, TRUE },
#endif /* __sgi || __hpux */
	{ "/usr/ucb/ps", "aux", SC( 0.3 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/bin/ps", "aux", SC( 0.3 ), NULL, 0, 0, 0, TRUE },
	{ "/bin/ps", "aux", SC( 0.3 ), NULL, 0, 0, 0, FALSE },
	{ "/usr/bin/ipcs", "-a", SC( 0.5 ), NULL, 0, 0, 0, TRUE },
	{ "/bin/ipcs", "-a", SC( 0.5 ), NULL, 0, 0, 0, FALSE },
							/* Unreliable source, depends on system usage */
	{ "/etc/pstat", "-p", SC( 0.5 ), NULL, 0, 0, 0, TRUE },
	{ "/bin/pstat", "-p", SC( 0.5 ), NULL, 0, 0, 0, FALSE },
	{ "/etc/pstat", "-S", SC( 0.2 ), NULL, 0, 0, 0, TRUE },
	{ "/bin/pstat", "-S", SC( 0.2 ), NULL, 0, 0, 0, FALSE },
	{ "/etc/pstat", "-v", SC( 0.2 ), NULL, 0, 0, 0, TRUE },
	{ "/bin/pstat", "-v", SC( 0.2 ), NULL, 0, 0, 0, FALSE },
	{ "/etc/pstat", "-x", SC( 0.2 ), NULL, 0, 0, 0, TRUE },
	{ "/bin/pstat", "-x", SC( 0.2 ), NULL, 0, 0, 0, FALSE },
	{ "/etc/pstat", "-t", SC( 0.1 ), NULL, 0, 0, 0, TRUE },
	{ "/bin/pstat", "-t", SC( 0.1 ), NULL, 0, 0, 0, FALSE },
							/* pstat is your friend */
	{ "/usr/bin/last", "-n 50", SC( 0.3 ), NULL, 0, 0, 0, TRUE },
#ifdef __sgi
	{ "/usr/bsd/last", "-50", SC( 0.3 ), NULL, 0, 0, 0, FALSE },
#endif /* __sgi */
#ifdef __hpux
	{ "/etc/last", "-50", SC( 0.3 ), NULL, 0, 0, 0, FALSE },
#endif /* __hpux */
	{ "/usr/bsd/last", "-n 50", SC( 0.3 ), NULL, 0, 0, 0, FALSE },
#ifdef sun
	{ "/usr/bin/showrev", "-a", SC( 0.1 ), NULL, 0, 0, 0, FALSE },
	{ "/usr/sbin/swap", "-l", SC( SC_0 ), NULL, 0, 0, 0, FALSE },
	{ "/usr/sbin/prtconf", "-v", SC( SC_0 ), NULL, 0, 0, 0, FALSE },
#endif /* sun */
	{ "/usr/sbin/psrinfo", NULL, SC( SC_0 ), NULL, 0, 0, 0, FALSE },
	{ "/usr/local/bin/lsof", "-lnwP", SC( 0.3 ), NULL, 0, 0, 0, FALSE },
							/* Output is very system and version-dependent */
	{ "/usr/sbin/snmp_request", "localhost public get 1.3.6.1.2.1.5.1.0", SC( 0.1 ), NULL, 0, 0, 0, FALSE }, /* ICMP ? */
	{ "/usr/sbin/snmp_request", "localhost public get 1.3.6.1.2.1.5.3.0", SC( 0.1 ), NULL, 0, 0, 0, FALSE }, /* ICMP ? */
	{ "/etc/arp", "-a", SC( 0.1 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/etc/arp", "-a", SC( 0.1 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/bin/arp", "-a", SC( 0.1 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/sbin/arp", "-a", SC( 0.1 ), NULL, 0, 0, 0, FALSE },
	{ "/usr/sbin/ripquery", "-nw 1 127.0.0.1", SC( 0.1 ), NULL, 0, 0, 0, FALSE },
	{ "/bin/lpstat", "-t", SC( 0.1 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/bin/lpstat", "-t", SC( 0.1 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/ucb/lpstat", "-t", SC( 0.1 ), NULL, 0, 0, 0, FALSE },
	{ "/usr/bin/tcpdump", "-c 5 -efvvx", SC( 1 ), NULL, 0, 0, 0, FALSE },
							/* This is very environment-dependant.  If
							   network traffic is low, it'll probably time
							   out before delivering 5 packets, which is OK
							   because it'll probably be fixed stuff like
							   ARP anyway */
	{ "/usr/sbin/advfsstat", "-b usr_domain", SC( SC_0 ), NULL, 0, 0, 0, FALSE },
	{ "/usr/sbin/advfsstat", "-l 2 usr_domain", SC( 0.5 ), NULL, 0, 0, 0, FALSE },
	{ "/usr/sbin/advfsstat", "-p usr_domain", SC( SC_0 ), NULL, 0, 0, 0, FALSE },
							/* This is a complex and screwball program.  Some
							   systems have things like rX_dmn, x = integer,
							   for RAID systems, but the statistics are
							   pretty dodgy */
#if 0
	/* The following aren't enabled since they're somewhat slow and not very
	   unpredictable, however they give an indication of the sort of sources
	   you can use (for example the finger might be more useful on a
	   firewalled internal network) */
	{ "/usr/bin/finger", "@ml.media.mit.edu", SC( 0.9 ), NULL, 0, 0, 0, FALSE },
	{ "/usr/local/bin/wget", "-O - http://lavarand.sgi.com/block.html", SC( 0.9 ), NULL, 0, 0, 0, FALSE },
	{ "/bin/cat", "/usr/spool/mqueue/syslog", SC( 0.9 ), NULL, 0, 0, 0, FALSE },
#endif /* 0 */
	{ NULL, NULL, 0, NULL, 0, 0, 0, FALSE } };
  
#endif
}

static void
get_interact(struct yarrow256_ctx *ctx, enum source_type source)
{
  werror("Please type some random data.\n");
}

int
main(int argc, char **argv)
{
  struct lsh_make_seed_options *options = make_options();
  int fd;

  struct yarrow256_ctx yarrow;
  struct yarrow_source sources[NSOURCES];

  argp_parse(&main_argp, argc, argv, 0, NULL, options);

  yarrow256_init(&yarrow, NSOURCES, sources);

  get_dev_random(&yarrow, SOURCE_DEV_RANDOM);
  get_dev_mem(&yarrow, SOURCE_DEV_MEM);
  get_system(&yarrow, SOURCE_SYSTEM);

  if (!yarrow256_is_seeded(&yarrow))
    {
      /* Get the number of additional sources that need to get above
       * the reseed threshold before a reseed happens. */
      if (yarrow256_needed_sources(&yarrow) > 1)
        {
          werror("Couldn't get enough randomness from the environment.\n");
          return EXIT_FAILURE;
        }
      get_interact(&yarrow, SOURCE_USER);
    }
  return EXIT_SUCCESS;
}
