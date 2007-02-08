#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
/* On Solaris, needed for the memset in the expansion of FD_ZERO */
#include <string.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

volatile sig_atomic_t got_sigchld;
int sig_pipe[2];
pid_t child_pid;

static void
handle_sigchld (int signo)
{
  const char x = 'x';
  int res;

  got_sigchld = 1;

  do
    res = write (sig_pipe[1], &x, 1);
  while (res < 0 && errno == EINTR);
}

static void
propagate_signal (int signo)
{
  kill(child_pid, signo);
}

static int
install_signal_handler (void)
{
  got_sigchld = 0;
  int flags;
  
  if (pipe (sig_pipe) < 0)
    {
      fprintf (stderr, "pipe failed: errno = %d\n", errno);
      return 0;
    }

  flags = fcntl (sig_pipe[0], F_GETFD);
  if (flags < 0)
    {
      fprintf (stderr, "fcntl F_GETFD failed: errno = %d\n", errno);
      return 0;
    }
  if (fcntl (sig_pipe[0], F_SETFD, flags | 1) < 0)
    {
      fprintf (stderr, "fcntl F_SETFD failed: errno = %d\n", errno);
      return 0;
    }

  flags = fcntl (sig_pipe[1], F_GETFD);
  if (flags < 0)
    {
      fprintf (stderr, "fcntl F_GETFD failed: errno = %d\n", errno);
      return 0;
    }
  if (fcntl (sig_pipe[1], F_SETFD, flags | 1) < 0)
    {
      fprintf (stderr, "fcntl F_SETFD failed: errno = %d\n", errno);
      return 0;
    }

  /* Make the writer side non-blocking, just in case */
  flags = fcntl (sig_pipe[1], F_GETFL);
  if (flags < 0)
    {
      fprintf (stderr, "fcntl F_GETFL failed: errno = %d\n", errno);
      return 0;
    }
  if (fcntl (sig_pipe[1], F_SETFL, flags | O_NONBLOCK) < 0)
    {
      fprintf (stderr, "fcntl F_SETFL failed: errno = %d\n", errno);
      return 0;
    }

  if (signal (SIGCHLD, handle_sigchld) == SIG_ERR)
    {
      fprintf (stderr, "signal failed: errno = %d\n", errno);
      return 0;
    }
    
  return 1;
}

/* Returns -1 on error, 0 on timeout, 1 on success */ 
static int
wait_for_signal (int timeout)
{
  struct timeval tv;
  struct timeval *tvp;
  fd_set set;
  int res;

  FD_ZERO (&set);

  FD_SET (sig_pipe[0], &set);

  if (timeout > 0)
    {
      tvp = &tv;
      tv.tv_sec = timeout;
      tv.tv_usec = 0;
    }
  else
    tvp = NULL;

  do
    res = select (sig_pipe[0] + 1, &set, NULL, NULL, tvp);
  while (res < 0 && errno == EINTR);

  if (res < 0)
    {
      fprintf (stderr, "select failed: errno = %d\n", errno);
      return -1;
    }
  return res;
}

int
main (int argc, char **argv)
{
  int timeout = 0;
  int c;
  pid_t exit_pid;
  int res;
  int status;
  int sync_pipe[2];
  char buf;

  while ( (c = getopt (argc, argv, "t:")) != -1)
    {
      switch (c)
	{
	case 't':
	  timeout = atoi(optarg);
	  if (timeout < 0)
	    {
	      fprintf(stderr, "Invalid timeout.\n");
	      return EXIT_FAILURE;
	    }
	  break;
	case '?':
	usage:
	  fprintf(stderr, "Usage: %s [-t TIMEOUT] COMMAND ARGS...\n"
		  "Timeout is in seconds.\n", argv[0]);
	  return EXIT_FAILURE;

	default:
	  abort();
	}
    }

  argc -= optind;
  argv += optind;
  
  if (argc < 1)
    goto usage;

  if (!install_signal_handler())
    return EXIT_FAILURE;

  if (pipe (sync_pipe) < 0)
    {
      fprintf (stderr, "pipe failed: errno = %d\n", errno);
      return EXIT_FAILURE;
    }
  child_pid = fork ();
  if (child_pid < 0)
    {
      /* strerror is not quite portable */
      fprintf (stderr, "fork failed: errno = %d\n", errno);
      return EXIT_FAILURE;
    }
  if (!child_pid)
    {
      /* Child */
      close(sync_pipe[0]);
      if (setpgid (0, 0) < 0)
	{
	  fprintf (stderr, "setpgid failed (child): errno = %d\n", errno);
	  return EXIT_FAILURE;
	}
      /* Signals to parent that we changed out process group */
      close(sync_pipe[1]);
      execvp (argv[0], argv);
      fprintf (stderr, "exec failed (child): errno = %d\n", errno);
      _exit(EXIT_FAILURE);
    }

  /* Parent */
  close(sync_pipe[1]);
  do
    res = read (sync_pipe[0], &buf, 1);
  while (res < 0 && errno == EINTR);
  if (res < 0)
    fprintf (stderr, "read failed: errno = %d\n", errno);

  close(sync_pipe[0]);

  /* FIXME: Use sigaction instead? */
  signal (SIGTERM, propagate_signal);
  signal (SIGINT, propagate_signal);

  res = wait_for_signal (timeout);

  /* Do all signalling before waiting on the child process. That way,
     the pid (and hence the pgid) can't be recycled. Does kill return
     an error if we try to send a signal to a zombie? */
  if (res == 0)
    {
      /* Timeout */
      fprintf (stderr, "Process timed out. Killing it...\n");
      if (kill (child_pid, SIGTERM) < 0)
	fprintf (stderr, "kill failed: errno = %d\n", errno);
    }
  
  if (res >= 0)
    {
      /* Give grand children processes a little time to finish */
      int t = 10;
      do
	t = sleep (t);
      while (t > 0);
    }

  /* Kill any remains of the process group */
  if (kill (-child_pid, SIGTERM) < 0 && errno != ESRCH)
    fprintf (stderr, "kill of process group failed: errno = %d\n", errno);

  signal (SIGTERM, SIG_DFL);
  signal (SIGINT, SIG_DFL);

  do
    exit_pid = waitpid (child_pid, &status, 0);
  while (exit_pid < 0 && errno == EINTR);

  if (exit_pid < 0)
    {
      fprintf (stderr, "waitpid failed: errno = %d\n", errno);
      return EXIT_FAILURE;
    }

  if (exit_pid != child_pid)
    {
      fprintf (stderr, "unexpected child %d exited\n", (int) exit_pid);
      return EXIT_FAILURE;
    }

  if (WIFEXITED (status))
    /* Normal exit */
    return WEXITSTATUS (status);

  if (WIFSIGNALED (status))
    {
      fprintf (stderr, "process terminated by signal %d\n", WTERMSIG (status));
      return EXIT_FAILURE;
    }

  /* What other cases are there??? */
  fprintf (stderr, "process terminated in some unrecognized way\n");
  return EXIT_FAILURE;
}
