/* unix_user.c
 *
 * User-related functions on UN*X
 *
 * $Id$
 */

#include "server_userauth.h"

#include "format.h"
#include "werror.h"
#include "xalloc.h"

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <time.h>

#include <sys/stat.h>
#include <unistd.h>

#if HAVE_CRYPT_H
# include <crypt.h>
#endif
#include <pwd.h>
#include <grp.h>

#if HAVE_SHADOW_H
#include <shadow.h>
#endif

#include "unix_user.c.x"


/* GABA:
   (class
     (name unix_user)
     (super user)
     (vars
       (gid simple gid_t)
       
       ; These strings include a terminating NUL-character, for 
       ; compatibility with library and system calls. This applies also
       ; to the inherited name attribute.

       (passwd string)  ; Crypted passwd
       (home string)
       (shell string))) */

/* NOTE: Calls functions using the *ugly* convention of returning
 * pointers to static buffers. */
static int
do_verify_password(struct user *s,
		   struct lsh_string *password,
		   int free)
{
  CAST(unix_user, user, s);
  char *salt;
  
  if (!user->passwd || (user->passwd->length < 2) )
    {
      /* FIXME: How are accounts without passwords handled? */
      if (free)
	lsh_string_free(password);

      return 0;
    }

  /* Convert password to a NULL-terminated string */
  password = make_cstring(password, free);

  if (!password)
    return 0;
  
  salt = user->passwd->data;

  if (strcmp(crypt(password->data, salt), user->passwd->data))
    {
      /* Passwd doesn't match */
      lsh_string_free(password);
      return 0;
    }

  lsh_string_free(password);
  return 1;
}

/* NOTE: No arbitrary file names are passed to this function, so we don't have
 * to check for things like "../../some/secret/file" */
static int
do_file_exists(struct user *u,
	       struct lsh_string *name,
	       int free)
{
  CAST(unix_user, user, u);
  struct lsh_string *path;
  struct stat st;
  
  if (!user->home)
    {
      if (free)
	lsh_string_free(name);
      return 0;
    }
  
  path = ssh_format(free ? "%lS/%lfS%c" : "%lS/%lS%c",
		    user->home, name, 0);

  if (stat(path->data, &st) == 0)
    {
      lsh_string_free(path);
      return 1;
    }
  lsh_string_free(path);
  return 0;
}

/* Change to user's home directory. FIXME: If the server is running
 * as the same user, perhaps it's better to use $HOME? */

static int
do_chdir_home(struct user *u)
{
  CAST(unix_user, user, u);

  if (!user->home)
    {
      if (chdir("/") < 0)
	{
	  werror("Strange: home directory was NULL, and chdir(\"/\") failed: %z\n",
		 STRERROR(errno));
	  return 0;
	}
    }
  else if (chdir(user->home->data) < 0)
    {
      werror("chdir to %S failed (using / instead): %z\n",
	     user->home, 
	     STRERROR(errno));
      if (chdir("/") < 0)
	{
	  werror("chdir(\"/\") failed: %z\n", STRERROR(errno));
	  return 0;
	}
    }
  return 1;  
}

static int
change_uid(struct unix_user *user)
{
  /* NOTE: Error handling is crucial here. If we do something
   * wrong, the server will think that the user is logged in
   * under his or her user id, while in fact the process is
   * still running as root. */
  if (initgroups(user->super.name->data, user->gid) < 0)
    {
      werror("initgroups failed: %z\n", STRERROR(errno));
      return 0;
    }
  if (setgid(user->gid) < 0)
    {
      werror("setgid failed: %z\n", STRERROR(errno));
      return 0;
    }
  if (setuid(user->super.uid) < 0)
    {
      werror("setuid failed: %z\n", STRERROR(errno));
      return 0;
    }
  return 1;
}

static int
do_fork_process(struct user *u, pid_t *pid)
{
  CAST(unix_user, user, u);
  pid_t child;
  
  /* Don't start any processes unless the user has a login shell. */
  if (!user->shell)
    return 0;
  
  child = fork();

  switch(child)
    {
    case -1: 
      werror("fork() failed: %z\n", STRERROR(errno));
      return 0;

    case 0: /* Child */
      if (getuid() != user->super.uid)
	if (!change_uid(user))
	  {
	    werror("Changing uid failed!\n");
	    _exit(EXIT_FAILURE);
	  }
      
      *pid = 0;
      return 1;
      
    default: /* Parent */
      *pid = child;
      return 1;
    }
}

#define USE_LOGIN_DASH_CONVENTION 1

static char *
format_env_pair(const char *name, struct lsh_string *value)
{
  return ssh_format("%lz=%lS%c", name, value, 0)->data;
}

static char *
format_env_pair_c(const char *name, const char *value)
{
  return ssh_format("%lz=%lz%c", name, value, 0)->data;
}

static void
do_exec_shell(struct user *u, int login,
	      char **argv,
	      unsigned env_length,
	      const struct env_value *env)
{
  CAST(unix_user, user, u);
  char **envp;
  char *tz = getenv("TZ");
  unsigned i, j;
  
  assert(user->shell);
  
  /* Make up an initial environment */
  debug("do_exec_shell: Setting up environment.\n");
  
  /* We need place for the caller's values, 
   *
   * SHELL, HOME, USER, LOGNAME, TZ, PATH
   *
   * and a terminating NULL */

#define MAX_ENV 6

  envp = alloca(sizeof(char *) * (env_length + MAX_ENV + 1));

  i = 0;
  envp[i++] = format_env_pair("SHELL", user->shell);

  if (user->home)
    envp[i++] = format_env_pair("HOME", user->home);

  /* FIXME: The value of $PATH should not be hard-coded */
  envp[i++] = "PATH=/bin:/usr/bin";
  envp[i++] = format_env_pair("USER", user->super.name);
  envp[i++] = format_env_pair("LOGNAME", user->super.name);

  if (tz)
    envp[i++] = format_env_pair_c("TZ", tz);

  assert(i < MAX_ENV);
#undef MAX_ENV

  for (j = 0; j<env_length; j++)
    envp[i++] = format_env_pair(env[j].name, env[j].value);

  envp[i] = NULL;

  debug("do_exec_shell: Environment:\n");
  for (i=0; envp[i]; i++)
    debug("    '%z'\n", env[i]);

#if USE_LOGIN_DASH_CONVENTION
  if (login)
    {
      /* Fixup argv[0], so that it starts with a dash */
      char *p;

      debug("do_exec_shell: fixing up name of shell...\n");
      
      argv[0] = alloca(user->shell->length + 2);

      /* Make sure that the shell's name begins with a -. */
      p = strrchr (user->shell->data, '/');
      if (!p)
	p = user->shell->data;
      else
	p ++;
	      
      argv[0][0] = '-';
      strncpy (argv[0] + 1, p, user->shell->length);
    }
  else
#endif /* USE_LOGIN_DASH_CONVENTION */
    argv[0] = user->shell->data;

  debug("do_exec_shell: argv[0] = '%z'.\n", argv[0]);
  
  execve(user->shell->data, argv, envp);
}

static struct user *
make_unix_user(struct lsh_string *name,
	       uid_t uid, gid_t gid,
	       const char *passwd,
	       const char *home,
	       const char *shell)
{
  NEW(unix_user, user);
  
  assert(name && !name->data[name->length]);

  user->super.name = name;
  user->super.verify_password = do_verify_password;
  user->super.file_exists = do_file_exists;
  user->super.chdir_home = do_chdir_home;
  user->super.fork_process = do_fork_process;
  user->super.exec_shell = do_exec_shell;
  
  user->super.uid = uid;
  user->gid = gid;

  /* Treat empty strings as NULL. */

#define TERMINATE(s) (((s) && *(s)) ? format_cstring((s)) : NULL)
  user->passwd = TERMINATE(passwd);
  user->home = TERMINATE(home);
  user->shell = TERMINATE(shell);
#undef TERMINATE
  
  return &user->super;
}
			    
/* GABA:
   (class
     (name unix_user_db)
     (super user_db)
     (vars
       (allow_root . int)))
*/


/* NOTE: Calls functions using the disgusting convention of returning
 * pointers to static buffers. */

/* This method filters out accounts that are known to be disabled
 * (i.e. root, or shadow style expiration). However, it may still
 * return some disabled accounts.
 *
 * An account that is disabled in /etc/passwd should have a value for
 * the login shell that prevents login; replacing the passwd field
 * only doesn't prevent login using publickey authentication. */
static struct user *
do_lookup_user(struct user_db *s,
	       struct lsh_string *name, int free)
{
  CAST(unix_user_db, self, s);
  
  struct passwd *passwd;
  
  name = make_cstring(name, free);
  
  if (!name)
    return NULL;
  
  if ((passwd = getpwnam(name->data))
      /* Check for root login */
      && (passwd->pw_uid || self->allow_root))
    {      
      char *crypted;
  
#if HAVE_GETSPNAM
      /* FIXME: What's the most portable way to test for shadow passwords?
       * A single character in the passwd field should cover most variants. */
      if (passwd->pw_passwd && (strlen(passwd->pw_passwd) == 1))
	{
	  struct spwd *shadowpwd;

	  /* Current day number since January 1, 1970.
	   *
	   * FIXME: Which timezone is used in the /etc/shadow file? */
	  long now = time(NULL) / (3600 * 24);
	  
	  if (!(shadowpwd = getspnam(name->data)))
	    goto fail;

	  /* FIXME: I'm assuming that zero means there's no expiry
	   * date. */
	  if (shadowpwd->sp_expire && (now > shadowpwd->sp_expire))
	    {
	      werror("Access denied for user '%pS', account expired.\n", name);
	      goto fail;
	    }
	  		     
	  /* FIXME: I'm assuming that zero means that there is no
	   * restriction on password age. */
	  if (shadowpwd->sp_max &&
	      (now > (shadowpwd->sp_lstchg +  shadowpwd->sp_max)))
	    {
	      werror("Access denied for user '%pS', password too old.\n", name);
	      goto fail;
	    }

	  /* FIXME: We could look at sp_warn and figure out if it is
	   * appropriate to send an SSH_MSG_USERAUTH_PASSWD_CHANGEREQ
	   * message. */

	  crypted = shadowpwd->sp_pwdp;
	}
      else
#endif /* HAVE_GETSPNAM */
	crypted = passwd->pw_passwd;
  
      return make_unix_user(name,
			    passwd->pw_uid, passwd->pw_gid,
			    crypted,
			    passwd->pw_dir, passwd->pw_shell);
    }
  else
    {
    fail:
      lsh_string_free(name);
      return NULL;
    }
}

struct user_db *
make_unix_user_db(int allow_root)
{
  NEW(unix_user_db, self);

  self->super.lookup = do_lookup_user;
  self->allow_root = allow_root;

  return &self->super;
}
