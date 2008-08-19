/* unix_random.c
 *
 * Randomness polling on unix, using yarrow and ideas from Peter
 * Gutmann's cryptlib. */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 2000, 2001, 2008 Niels Möller
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

#include <fcntl.h>

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <sys/types.h>
#include <sys/time.h> /* Must be included before sys/resource.h */
#include <sys/resource.h>

#include "nettle/yarrow.h"

#include "randomness.h"

#include "crypto.h"
#include "environ.h"
#include "format.h"
#include "io.h"
#include "lsh_string.h"
#include "seed_file.h"
#include "xalloc.h"
#include "werror.h"

/* Global state */
static int seed_file_fd;
static struct yarrow256_ctx yarrow;
static struct yarrow_source sources[RANDOM_NSOURCES];

static int random_initialized = 0;

/* For the SOURCE_TRIVIA, count the number of invocations per second */
static time_t trivia_previous_time = 0;
static unsigned trivia_time_count = 0;

/* For SOURCE_DEVICE */
static int device_fd;
static time_t device_last_read = 0;


static struct lsh_string *
read_seed_file(int fd)
{
  struct lsh_string *seed;
  
  if (lseek(fd, 0, SEEK_SET) < 0)
    {
      werror("Seeking to beginning of seed file failed!? %e\n", errno);
      return NULL;
    }

  seed = io_read_file_raw(fd, YARROW256_SEED_FILE_SIZE + 1);
  if (!seed)
    werror("Couldn't read seed file %e\n", errno);
  return seed;
}

static int
read_initial_seed_file(struct yarrow256_ctx *ctx)
{
  struct lsh_string *seed = read_seed_file(seed_file_fd);

  if (!seed)
    return 0;
  
  if (lsh_string_length(seed) < YARROW256_SEED_FILE_SIZE)
    {
      werror("Seed file too short\n");
      lsh_string_free(seed);
      return 0;
    }
  
  yarrow256_seed(ctx, STRING_LD(seed));
  lsh_string_free(seed);

  assert(yarrow256_is_seeded(ctx));

  return 1;
}

static void
update_seed_file(void)
{
  verbose("Overwriting seed file.\n");

  if (!seed_file_lock(seed_file_fd, 0))
    {
      werror("Failed to lock seed file, so not overwriting it now.\n");
    }
  else
    {
      struct lsh_string *s = read_seed_file(seed_file_fd);
      
      seed_file_write(seed_file_fd, &yarrow);
      seed_file_unlock(seed_file_fd);

      /* Mix in the old seed file, it might have picked up
       * some randomness. */

      /* FIXME: Ideally, this should be mixed in *before* generating
	 the new seed file. To mix using yarrow, yarrow256_fast_reseed must be
	 made non-static. Or, alternatively, we could manually xor
	 the new seed file on top of the old one. */
      if (s)
	{
	  yarrow256_update(&yarrow, RANDOM_SOURCE_NEW_SEED,
			   0, STRING_LD(s));
	  lsh_string_free(s);
	}
    }
}

static int
trivia_source(void)
{
  struct {
    struct timeval now;
#if HAVE_GETRUSAGE
    struct rusage rusage;
#endif
    unsigned count;
    pid_t pid;
  } event;
  
  unsigned entropy = 0;

  if (gettimeofday(&event.now, NULL) < 0)
    fatal("gettimeofday failed %e\n", errno);
#if HAVE_GETRUSAGE
  if (getrusage(RUSAGE_SELF, &event.rusage) < 0)
    fatal("getrusage failed %e\n", errno);
#endif

  event.count = trivia_time_count++;

  if (event.now.tv_sec != trivia_previous_time)
    {
      /* Count one bit of entropy if we either have more than two
       * invocations in one second, or more than two seconds
       * between invocations. */
      if (trivia_time_count > 2
	  || (event.now.tv_sec - trivia_previous_time) > 2)
	entropy++;

      trivia_time_count = 0;
    }

  trivia_previous_time = event.now.tv_sec;
  event.pid = getpid();

  return yarrow256_update(&yarrow, RANDOM_SOURCE_TRIVIA, entropy,
			  sizeof(event), (const uint8_t *) &event);
}

#define DEVICE_READ_SIZE 10
static int
device_source(void)
{
  time_t now = time(NULL);

  if (device_fd > 0
      && (now - device_last_read) > 60)
    {
      /* More than a minute since we last read the device */
      uint8_t buf[DEVICE_READ_SIZE];
      uint32_t done;

      /* FIXME: Use lsh_string_read instead? */
      for (done = 0; done < sizeof(buf) ;)
	{
	  int res;
	  do
	    res = read(device_fd, buf + done, sizeof(buf) - done);
	  while (res < 0 && errno == EINTR);

	  if (res < 0)
	    {
	      werror("Failed to read /dev/urandom %e\n", errno);
	      return 0;
	    }
	  else if (res == 0)
	    {
	      werror("Failed to read /dev/urandom: end of file\n");
	      return 0;
	    }

	  done += res;
	}
      device_last_read = now;
      
      return yarrow256_update(&yarrow, RANDOM_SOURCE_DEVICE,
			      10, /* Estimate 10 bits of entropy */
			      sizeof(buf), buf);
    }
  return 0;
}
#undef DEVICE_READ_SIZE

void
random_generate(uint32_t length,
		uint8_t *dst)
{
  int trivia_reseed;
  int device_reseed;

  assert(random_initialized);

  trivia_reseed = trivia_source();
  device_reseed = device_source();

  if (trivia_reseed || device_reseed)
    update_seed_file();

  /* Ok, generate some output */
  yarrow256_random(&yarrow, length, dst);
}

void
random_add(enum random_source_type type,
	   uint32_t length,
	   const uint8_t *data)
{
  unsigned entropy;

  assert(type >= 0 && type < RANDOM_NSOURCES);

  switch(type)
    {
    case RANDOM_SOURCE_SECRET:
      /* Count one bit of entropy per character in a password or
       * key */
      entropy = length;
      break;
    case RANDOM_SOURCE_REMOTE:
      /* Count one bit of entropy if we have two bytes of padding. */
      entropy = (length >= 2);
      break;

    default:
      fatal("Internal error\n");
    }

  if (yarrow256_update(&yarrow, type,
		       entropy,
		       length, data))
    update_seed_file();
}

int
random_init(const struct lsh_string *seed_file_name)
{
  trace("random_init\n");

  yarrow256_init(&yarrow, RANDOM_NSOURCES, sources);
    
  verbose("Reading seed-file `%S'\n", seed_file_name);

  seed_file_fd = open(lsh_get_cstring(seed_file_name), O_RDWR);
  if (seed_file_fd < 0)
    {
      werror("No seed file. Please create one by running\n");
      werror("lsh-make-seed -o \"%S\".\n", seed_file_name);

      return 0;
    }

  io_set_close_on_exec(seed_file_fd);
  
  if (!seed_file_check_permissions(seed_file_fd, seed_file_name))
    {
      close(seed_file_fd);
      seed_file_fd = -1;
      return 0;
    }

  trace("random_init, locking seed file...\n");
  if (!seed_file_lock(seed_file_fd, 1))
    {
      werror("Could not lock seed-file `%S'\n", seed_file_name);
      return 0;
    }

  trace("random_init, seed file locked successfully.\n");

  trace("random_init, reading seed file...\n");
    
  if (!read_initial_seed_file(&yarrow))
    {
      seed_file_unlock(seed_file_fd);
      return 0;
    }

  trace("random_init, seed file read successfully.\n");

  assert(yarrow256_is_seeded(&yarrow));

  /* Initialize sources. */
  trivia_time_count = 0;
  trivia_previous_time = 0;

  device_fd = open("/dev/urandom", O_RDONLY);
  if (device_fd >= 0)
    io_set_close_on_exec(device_fd);

  device_last_read = 0;
  
  device_source();
  trivia_source();

  /* Mix that data in before generating any output. */
  yarrow256_force_reseed(&yarrow);

  /* Overwrite seed file. */
  if (!seed_file_write(seed_file_fd, &yarrow))
    {
      seed_file_unlock(seed_file_fd);
      return 0;
    }

  seed_file_unlock(seed_file_fd);

  random_initialized = 1;

  return 1;
}

int
random_init_system(void)
{
  struct lsh_string *file_name;
  const char *env_name;
  int res;
  
  env_name = getenv(ENV_SEED_FILE);

  file_name = make_string(env_name ? env_name
			  : "/var/spool/lsh/yarrow-seed-file");

  res = random_init(file_name);
  
  lsh_string_free(file_name);

  return res;
}

/* Wrapper for using lsh's randomness generator with nettle
 * functions. */
void
lsh_random(void *x UNUSED, unsigned length, uint8_t *data)
{
  random_generate(length, data);
}
