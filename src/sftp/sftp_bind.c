/*
 * @(#) $Id$
 *
 * sftp_bind.c - bindings for sftp.c
 *
 * Portions of code taken from the sftp test client from 
 * the sftp server of lsh by Niels M�ller and myself.
 *
 */

/* lsftp, an implementation of the sftp protocol
 *
 * Copyright (C) 2001 Pontus Sk�ld
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

#include "sftp_bind.h"

static FILE* to_transport;
static FILE* from_transport;

static int transport_pid = 0;

static int sftp_callbacks = 256;
static int lsftp_callbacks = 256;

static int fd_to_transport = -1;
static int fd_from_transport = -1;

static struct sftp_callback* sftp_cbs = NULL;
static struct lsftp_callback* lsftp_cbs = NULL;

static int lsftp_cb_index(int id);
static int lsftp_remove_lsftp_cb(int id);

static struct sftp_input* in;
static struct sftp_output* out;

int buggy_server_treshold = 0;

const char *status_codes_text[9] = { 
  "Ok" , 
  "End of file", 
  "No such file", 
  "Permission denied",
  "Failure (no more applicable error message)",
  "Bad message",
  "No connection",
  "Connection lost",
  "Operation unsupported"
};

static const char* curpath = NULL;

static void
sighandler( int signum )
{
  if( SIGCHLD == signum )
    {
      void *err;
      int status;
      int pid;

      /* A child of ours has died */
      pid = waitpid( transport_pid, &status, WNOHANG );
      
      if( pid == transport_pid ) /* Our transporter died? */
	{
	  printf( "Child died!\n" );
	  transport_pid = 0;

	  if( WIFEXITED(status ) )
	    printf( "Exited with status %d\n", WEXITSTATUS(status));

	  if( WIFSIGNALED(status ) )
	    printf( "Signaled with %d\n", WTERMSIG(status));


	  }

      err = signal( SIGCHLD, sighandler );
      
      if( SIG_ERR == err ) /* Inform if there was an error, but do nothing */
	perror( "signal failed: ");
    }
  
}

int lsftp_open_connection(char** argv, int argc)
{
  /* [0] for reading, [1] for writing */
  int stdin_pipe[2];
  int stdout_pipe[2];
  int pid;

  if( transport_pid  ) /* Already assigned a */
    {
      printf( "You already have a connection, please close it first\n" );
      return 0;
    }

  if (pipe(stdin_pipe) < 0)
    FATAL("Creating stdin_pipe failed.");
  
  if (pipe(stdout_pipe) < 0)
    FATAL("Creating stdout_pipe failed.");

#ifdef USING_CYGWIN
  setmode( stdin_pipe[0], O_BINARY );
  setmode( stdin_pipe[1], O_BINARY );

  setmode( stdout_pipe[0], O_BINARY );
  setmode( stdout_pipe[1], O_BINARY );
#endif

  switch( ( pid = fork() ) )
    {
    case -1:
      FATAL("fork failed.");
    default: /* Parent */
      {
	FILE *i;
	FILE *o;
	void* err;

	close(stdin_pipe[0]); /* Close those ends of the pipe we won't use */
	close(stdout_pipe[1]);
	
	i = fdopen(stdout_pipe[0], "r");
	if (!i)
	  FATAL("fdopen stdout_pipe failed.");
	
	o = fdopen(stdin_pipe[1], "w");
	if (!o)
	  FATAL("fdopen stdin_pipe failed.");

	from_transport = i;
	to_transport = o;
	
	fd_from_transport = stdout_pipe[0];
	fd_to_transport = stdin_pipe[1];

	transport_pid = pid; /* Save pid */

	err = signal( SIGCHLD, sighandler );

	if( SIG_ERR == err ) /* Inform if there was an error, but do nothing */
	  perror( "signal failed: ");

	return 0;
      }
    case 0: /* Child */
      {
	int k = 0;
	int j = 0;
	int i;

	char tmp[PATH_MAX];	
	char* lsh_name=NULL;
	char** new_argv=NULL;
	const char* before_string;
	const char* after_string;
	const char* cur_string;

	/* Check how many arguments we send to the secsh client */

	/* First before what's given */

	before_string = mgetenv( BEFORE_ARGS_ENV );

	if( !before_string )   /* No such variable? */
	  before_string = DEFAULT_BEFORE_ARGS;


	cur_string = before_string;
	
	while( (
		cur_string =  
		lsftp_s_strtok( 
			       cur_string,        /* Old startat */
			       " \r\n\t",         /* Separators */
			       tmp,               /* Store in */
			       PATH_MAX           /* Storage length */
			       )
		)
	       ) 
	  k++;
	
	/* And also after */

	after_string = mgetenv( AFTER_ARGS_ENV );

	if( !after_string )
	  after_string = DEFAULT_AFTER_ARGS;

	
	 cur_string = after_string;
	 
	 while( (
		 cur_string =  
		  lsftp_s_strtok( 
				 cur_string,        /* Old startat */
				 " \r\n\t",         /* Separators */
				 tmp,               /* Store in */
				 PATH_MAX           /* Storage length */
				 )
		 )
		) 
	   k++;
	
	 
	new_argv = malloc( ( argc + k + 1 ) * sizeof( char* ) ); /* k new
								    arguments,
								    finishing
								    NULL. */
	
	if ( !new_argv )
	  FATAL("Malloc failed ");


	cur_string = before_string;
	
	while( (
		cur_string =  
		lsftp_s_strtok( 
			       cur_string,        /* Old startat */
			       " \r\n\t",         /* Separators */
			       tmp,               /* Store in */
			       PATH_MAX           /* Storage length */
			       )
		)
	       ) 
	  /* Make a copy of the string and pass it as an argument */
	  new_argv[ ++j ] = strdup(tmp);          
     	
	i = 1;                             /* argv[0] doesn't interest us */
	
	for ( ; argv[i] && ( i < argc ); i++)     /* Copy argv */
	  new_argv[i + j] = argv[i];
	
	new_argv[i + j] = NULL;
	
	cur_string = after_string;
	
	j += i;
	
	while( (
		cur_string =  
		lsftp_s_strtok( 
			       cur_string,        /* Old startat */
			       " \r\n\t",         /* Separators */
			       tmp,               /* Store in */
			       PATH_MAX           /* Storage length */
			       )
		)
	       ) 
	  /* Make a copy of the string and pass it as an argument */
	  new_argv[ j++ ] = strdup(tmp);
	
	new_argv[ j++ ] = 0;  
      
	
	if (dup2(stdin_pipe[0], STDIN_FILENO) < 0)
	  FATAL("dup2 for stdin failed.");
	if (dup2(stdout_pipe[1], STDOUT_FILENO) < 0)
	  FATAL("dup2 for stdout failed.");
	
	close(stdin_pipe[0]);
	close(stdin_pipe[1]);
	close(stdout_pipe[0]);
	close(stdout_pipe[1]);
      
	lsh_name = mgetenv( LSH_PROGENV ); /* Use a specific program? */

	new_argv[0]=lsh_name;

	if ( lsh_name ) /* No such enviroment variable? */
	  {
	    execvp( lsh_name, new_argv ); /* Start whatever */    
	    fprintf( 
		    stderr, "Failed to start %s: %s\n", 
		    new_argv[0], 
		    strerror( errno )
		    );
	  }



#ifdef TRANSPORT_PROG                    /* Set at compile time? */

	new_argv[0]=TRANSPORT_PROG;

	if ( TRANSPORT_PROG ) /* No such enviroment variable? */
	  {
	    execvp( TRANSPORT_PROG, new_argv ); /* Start whatever */    
	    fprintf( 
		    stderr, "Failed to start %s: %s\n", 
		    new_argv[0], 
		    strerror( errno )
		    );
	  }
#endif     /* TRANSPORT_PROG */
	
	/* Either LSH_PROG wasn't set or it couldn't be exec'd. Try the others */

	new_argv[0]=LSH_GATEWAY; 
	
	execvp( LSH_GATEWAY, new_argv ); /* Start lshg -C sftp whatever */
	fprintf( 
		stderr, "Failed to start %s: %s\n", 
		new_argv[0], 
		strerror( errno )
		);
	
	new_argv[0]=LSH_CLIENT; 
	execvp( LSH_CLIENT, new_argv ); /* Start */
	
	fprintf( 
		stderr, "Failed to start %s: %s\n", 
		new_argv[0], 
		strerror( errno )
		);

	fprintf( stderr, 
		 "Could not start a suitable SecSH client, please set " 
		 LSH_PROGENV 
		 ".\n"
		 );
	
	FATAL( "Could not start a suitable secsh client." );
      }
    }

  return 0;
}

int lsftp_connected()
{
  return transport_pid;
}

int lsftp_close_connection()
{
  /*
   * Close connections - read what we can and when send 
   * s
   */

  int i;
  int status;

  if( !lsftp_connected() ) /* Called when already disconnected? */
    return -1;


  signal( SIGCHLD, SIG_DFL ); /* Restore original signal handler before quitting */

  i = fclose( to_transport ); /* Close outgoing */

  /* FIXME: Read what we can here */
  /* FIXME: Should we report any errors here? */

  i = i || fclose( from_transport );

  if( -1 != kill( transport_pid, SIGTERM ) ) /* Signal sent OK? */
    {
      alarm( KILL_WAIT ); /* FIXME: Change signal handler? */
      i = wait( &status );

      if( -1 == i )
	if( -1 != kill( transport_pid, SIGHUP ) )
	  {
	    alarm( KILL_WAIT );
	    i = wait( &status );

	    if( -1 == i )
	      if( -1 != kill( transport_pid, SIGKILL ) )       /* DIE! */
		{ 
		  alarm( KILL_WAIT );
		  i = wait( &status );
		}
	  }
    }

  alarm( 0 ); /* Cancel any alarm */

  transport_pid = 0; /* Make invalid */
  to_transport = 0;
  from_transport = 0;

  /* FIXME: Free memory used by sftp_input in and sftp_output out? */

  return i;
}


int lsftp_sftp_init()
{
  lsftp_sftp_cb_init( 256 );
  lsftp_lsftp_cb_init( 256 );

  return 0;

}

int lsftp_handshake()
{
  int failed;

  in = sftp_make_input( from_transport ); 
  out = sftp_make_output( to_transport );

  failed = sftp_handshake( in, out );

  /* FIXME: Some bytes are lost by handshaking */

  if( failed )
    {
      int readok = 1;

      fprintf( stderr, "Handshake failed\nSecSH client says:\n" );

      while( readok )
	{
	  char x;
	  readok = fread( &x, 1, 1, from_transport ); /* Try to read one byte */
	  fprintf( stderr, "%c", x);
	}

      printf( "Handshake failed. Please consider setting\n" 
	     BEFORE_ARGS_ENV 
	     " and "
	     AFTER_ARGS_ENV
	     ".\n"
	     );

      return -1;
    }

  return 0;
}

#if 0
/* Not used ??? */
static int
lsftp_wait_not_eof(void)
{
  clearerr( from_transport );
  while( feof( from_transport ) )
    sleep(1);

  return 0;
}
#endif

static int
lsftp_handle_packet(void)
{
  int i, j;
  UINT8 msg = 0 ;
  UINT32 id = 0;

  /* Hrrm, peek at id somehow */

  if( sftp_get_uint8( in, &msg ) < 1 )
    printf( "Bad read!\n" );
  if( sftp_get_uint32( in, &id ) <1 )
    printf( "Bad read!\n" );


/*         printf( "Id: %d\n", id );    */
/*       printf( "Msg: %d\n", msg ); */

  for( i = 0; i < sftp_callbacks; i++ )
    if( 
       id &&                         /* We never send the id zero */ 
       ( sftp_cbs[i].id == id )
       )
      {
	/* FIXME: Keep a separate copy of the new state, in case the
	 * callback function doesn't like next == state. It would be
	 * better if all did.*/
	struct sftp_callback state;

	/* Do callback */
	sftp_cbs[i].nextfun(&state, msg, id, in, out, &sftp_cbs[i]);
	sftp_cbs[i] = state; /* Replace old callback with the new one */

/*  	printf( "Returned from packet nextfun\n "); */

	if( ! state.id ) /* No next callback? */
	  {
	    int op_id = state.op_id;
	      
	    for( j = 0; j < lsftp_callbacks; j++ )
	      if( lsftp_cbs[j].op_id == op_id )
		{
		  int i;

/*  		  printf( "Doing lsftp callback\n "); */
		  /* Do callback */
		  i = lsftp_cbs[j].nextfun(&state, &lsftp_cbs[j]); 

		  /* Free any memory used */
		  if( lsftp_cbs[j].a )
		    free( lsftp_cbs[j].a );
 
		  if( lsftp_cbs[j].local )
		    free( (void *) lsftp_cbs[j].local );
 
		  if( lsftp_cbs[j].remote )
		    free( (void *) lsftp_cbs[j].remote );

		  if( lsftp_cbs[j].command )
		    free( (void *) lsftp_cbs[j].command );
		    		    
		  lsftp_cbs[j].op_id = 0; /* Remove id so it can be reused */
		  lsftp_cbs[j].st = 0;
		  lsftp_cbs[j].a = 0;
		  lsftp_cbs[j].local = 0;
		  lsftp_cbs[j].remote = 0;
		  lsftp_cbs[j].command = 0;
		  lsftp_cbs[j].memory = 0;
		  lsftp_cbs[j].opt1 = 0;
		  lsftp_cbs[j].opt2 = 0;

		  return i;
		}
	  }
      }
  
/*    printf( "Returning from packet handler\n "); */
  return 0; /* No callback found, ignored */
}

static int
lsftp_safe_to_write(void)
{
  int success = 1;

  if( !lsftp_connected() )   /* Bail out if not connected */
    {
      printf( "Disconnected error!\n" );
      return -1;
    }
  
  if( buggy_server_treshold )
      while( lsftp_active_cbs() > buggy_server_treshold )
	lsftp_callback();
    
  while( success && lsftp_want_to_write() )
    success = sftp_write_packet( out );
    
  if( 1 > success )
    printf( "Writing packet failed, gave %d\n", success );

  return 0;
}


int
lsftp_want_to_write(void)
{
  /*
   * Return non-zero if we want to write 
   */

  if( !lsftp_connected() )   /* Bail out if not connected */
    return 0;                /* We don't want to write */

  return sftp_packet_size( out );
}

int
lsftp_callback(void)
{
  int n;
  fd_set rfds;
  fd_set wfds;
  int success;
  static int tocount = 0;
  int write_desired = lsftp_want_to_write();

  struct timeval tv;
  int retval;

  if( !lsftp_connected() )   /* Bail out if not connected */
    {
      printf( "Disconnected error!\n" );
      return -1;
    }

  FD_ZERO( &rfds );
  FD_ZERO( &wfds );

  /* Anything from lsh would be interesting */

  if( write_desired )   /* Although writes have higher priority */
    FD_SET( fd_to_transport, &wfds );
  else
    FD_SET( fd_from_transport, &rfds );

  tv.tv_sec = 2;
  tv.tv_usec = 0;

  if( write_desired )  /* Calculate n in select call */
    n = fd_to_transport + 1;
  else
    n = fd_from_transport + 1;
  
  retval = select(n, &rfds, &wfds, NULL, &tv);
  
  if( !write_desired &&
      FD_ISSET( fd_from_transport, &rfds ) 
      )
    tocount = 0;
  else
    tocount++;

  if( FD_ISSET( fd_from_transport, &rfds ) ||
      4 == tocount )  /* FIXME: Do this better */
    {
      success = sftp_read_packet( in );
      
      /*        printf( "Read packet with status %d\n", success );  */
      
      if( success > 0 )
	{
	  if( 4 == tocount )
	    printf( "There's something rotten in the state (select failed incorrectly)\n" );
      
	  lsftp_handle_packet();
	}

      tocount = 0;
    }
    
  if( FD_ISSET( fd_to_transport, &wfds ) )
    if( sftp_packet_size( out ) )
      {
	tocount = 0;
	success = sftp_write_packet( out );
/*  	printf( "Wrote packet with status %d\n", success );  */
	
	if( 1 > success )
	  printf( "Writing packet failed, gave %d\n", success );

      }
  /* FIXME: On failure? */

  return 0;
}

void
lsftp_perror(const char* msg, int err)
{
  printf( "%s: %s\n", msg, strerror( err ) );
}

void
lsftp_report_error(const struct sftp_callback *s,
		   const struct lsftp_callback *l)
{
  if( s->bad_status )
    {
      if( l->remote )
	printf( "%s: %s\n", l->remote, status_codes_text[s->bad_status] );
      else
	printf( "%s\n", status_codes_text[s->bad_status] );
      return;
    }

  if( s->retval )
    {
      if( l->remote )
	printf( "%s: %s (received by %d) \n", l->remote, status_codes_text[s->retval], s->last );
      else
	printf( "%s\n", status_codes_text[s->retval] );
    }
}



int lsftp_fd_read_net()
{
  if( !lsftp_connected() )   /* Bail out if not connected */
    return 0;

  return fd_from_transport;
}

int lsftp_fd_write_net()
{
  if( !lsftp_connected() )   /* Bail out if not connected */
    return 0;

  return fd_to_transport;
}

static int
lsftp_unique_id(void)
{
  static int id=1;

  id++;
  return id;
}

static int
lsftp_free_lsftp_cb(void)
{
  int j;
              
  for( j = 0; j < lsftp_callbacks; j++ )
    if( ! lsftp_cbs[j].op_id  ) /* Callback is free? */
      return j;

  return -1;
}

static int
lsftp_free_sftp_cb(void)
{
  int j;
              
  for( j = 0; j < sftp_callbacks; j++ )
    if( ! sftp_cbs[j].id  ) /* Callback is free? */
      return j;

  return -1;
}

int lsftp_active_cbs()
{
  int j;
  int active = 0;

  for( j = 0; j < lsftp_callbacks; j++ )
    if( lsftp_cbs[j].op_id  ) /* Callback is free? */
      active++;

  for( j = 0; j < sftp_callbacks; j++ )
    if( sftp_cbs[j].id  ) /* Callback is free? */
      active++;

  return active;
}

int
lsftp_do_get(const char *local, const char *remote,
	     const char *command, int cont)
{
  int id;
  int index;
  const char *tmp;
  struct sftp_callback s;

  id = lsftp_install_lsftp_cb( lsftp_handle_get );
  index = lsftp_cb_index( id );

  if( id &&
      ( id != -1 ) && 
      ( index != -1 )
      )
    {
      int freeflag = 1;
      tmp = lsftp_qualify_path( remote );

      if( !tmp )   /* Problem with qualifying the name? */
	{
	  freeflag = 0;
	  tmp = remote;
	}

      /* Leave informational message */

      lsftp_cbs[index].local = strdup( local ); 
      lsftp_cbs[index].remote = strdup( tmp ); 
      lsftp_cbs[index].command = strdup( command );

      lsftp_safe_to_write();   /* Wait for any unsent packet to go away */

      sftp_get_file_init(&s, id, in, out,
			 tmp, strlen( tmp ), 
			 local, strlen( local),
			 cont);
      
      if( freeflag )
	free( (void *) tmp );

      if( s.nextfun )
	lsftp_install_sftp_cb( &s );
      else
	{
	  lsftp_perror( local, s.localerrno );
	  lsftp_remove_lsftp_cb( id );
	  return -1;
	}
    }
  return id;
}

int
lsftp_handle_get(struct sftp_callback *s,
		 const struct lsftp_callback *l)
{
  if(
      s->retval != SSH_FX_EOF &&   /* We should have an EOF status, but may have OK */
      s->retval != SSH_FX_OK
     ) 
    lsftp_report_error( s, l );

  if( s->localerr )
    lsftp_perror( l->local, s->localerrno );

  return s->retval;
}


int lsftp_cb_list()
{
  int j, jobs;

  jobs = 0;

  for( j = 0; j < lsftp_callbacks; j++ )
    if( lsftp_cbs[j].op_id && lsftp_cbs[j].command ) /* Found callback */
      {
	printf( "%d %s\n", lsftp_cbs[j].op_id,  lsftp_cbs[j].command );
	jobs++;
      }

  if( !jobs )
    printf( "No active jobs!\n" );
  return 0;
}

int lsftp_cb_status( int jobid )
{
  int index = lsftp_cb_index( jobid );
  int found = 0;
  int j;

  if( -1 != index )  /* Found matching? */
    {    
      printf( "Information for lsftp callback %d\n", lsftp_cbs[index].op_id );

      if( lsftp_cbs[index].command )
	printf( "Command: %s\n", lsftp_cbs[index].command );

      if( lsftp_cbs[index].local )
	printf( "Local file: %s\n", lsftp_cbs[index].local );

      if( lsftp_cbs[index].remote )
	printf( "Remote: %s\n", lsftp_cbs[index].remote );

      printf( "\n" );
      found++;
    }



  for( j = 0; j < sftp_callbacks; j++ )
    if( sftp_cbs[j].op_id == jobid ) /* Related to this id? */
      {
	printf( "Information for sftp callback %d\n", sftp_cbs[j].id );
	printf( "Corresponding lsftp id %d\n", sftp_cbs[j].op_id );
	/* Doesn't handle off_t bigger than long */
	printf( "Fileposition %lx\n", (long) sftp_cbs[j].filepos );
	printf( "File descriptor %d\n", sftp_cbs[j].fd );
	printf( "Return value %d\n", sftp_cbs[j].retval );
	printf( "Last callback %d\n", sftp_cbs[j].last );
	printf( "Bad status %d\n", sftp_cbs[j].bad_status );
	printf( "Callback that got bad %d\n", sftp_cbs[j].last_bad );
	printf( "Local error (return value) %d\n", sftp_cbs[j].localerr );
	printf( "Local error (errno) %d\n", sftp_cbs[j].localerrno );

	if( sftp_cbs[j].handlelen && sftp_cbs[j].handle )
	  printf( "Handle string %p (%d bytes long)\n", 
		  sftp_cbs[j].handle, 
		  sftp_cbs[j].handlelen );

	printf( "\n" );

	found++;
      }

  if( !found )
    printf( "No info for given id\n" );

  return 0;
}

static int
lsftp_cb_index(int id)
{
  int j;
              
  for( j = 0; j < lsftp_callbacks; j++ )
    if( lsftp_cbs[j].op_id == id  ) /* Found callback */
      return j;

  return -1;
}


int
lsftp_install_lsftp_cb(lsftp_callback_func nextfun)
{
  int i = -1;
  int id = lsftp_unique_id();

  struct lsftp_callback lcb;
  
  i = lsftp_free_lsftp_cb();
  
  lcb.a = 0;
  lcb.st = 0;
  lcb.local = 0;
  lcb.command = 0;
  lcb.remote = 0;
  lcb.op_id = id;
  lcb.opt1 = 0;
  lcb.opt2 = 0;

  lcb.nextfun = nextfun;

  if( i == -1 )
    return 0;

  lsftp_cbs[i] = lcb;
  
  return id;
}


int lsftp_await_command( int id )
{
  int active = 1;
  
/*    printf( "Waiting for finish of command with id %d\n", id ); */

/*      lsftp_cb_status( id );  */

  while( active )
    {
      int i;
      int j;

      i = lsftp_callback();                /* Checks itself with select */

      if( -1 == i ) /* Failure? */
	return -1;

      active = 0;

      for( j = 0; j < lsftp_callbacks; j++ )
	if( lsftp_cbs[j].op_id == id && lsftp_cbs[j].nextfun) 
	  /* Callback for this id? */
	  active++;
	        
      for( j = 0; j < sftp_callbacks; j++ )
	if( sftp_cbs[j].op_id  == id && sftp_cbs[j].nextfun) 
	  active++;      
    }
  
  return active;
}









int lsftp_lsftp_cb_init( int new_lsftp_callbacks )
{
  int i = 0;
  void* newmem;
  struct lsftp_callback nullcb;

  nullcb.nextfun = 0;
  nullcb.op_id = 0;
  nullcb.local = 0;
  nullcb.remote = 0;
  nullcb.command = 0;
  nullcb.st = 0;
  nullcb.a = 0;
  nullcb.memory = 0;


  if( lsftp_cbs )
    i = lsftp_compact_lsftp_cbs();

  if( i > new_lsftp_callbacks ) /* Too few callbacks to fit existing */
    return -1;

  newmem = realloc( sftp_cbs, sizeof( struct sftp_callback ) * new_lsftp_callbacks );

  if( !newmem ) /* realloc failed? */
    {
      perror( "realloc failed" );
      return -2;
    }

  lsftp_cbs = newmem;
  lsftp_callbacks = new_lsftp_callbacks;

  for( ; i < lsftp_callbacks; i++ )
    lsftp_cbs[i] = nullcb;

  return 0;
}

void lsftp_lsftp_cb_uninit()
{
  if( !lsftp_cbs )
    return;

  free( lsftp_cbs );

  lsftp_cbs = 0;
  lsftp_callbacks = 0;
  
  return;
}

int lsftp_compact_lsftp_cbs()
{
  /* Compacts the sftp-callbacks to the beginning, and return the number of callbacks */

  int index = 0;
  int used = 0;

  if( !lsftp_cbs )
    return 0;

  while( index < lsftp_callbacks )
    {
      if( 
	 lsftp_cbs[index].op_id &&          /* Used callback */
	 lsftp_cbs[index].nextfun 
	)
	{
	  if( index > used )                /* That should be moved? */
	    lsftp_cbs[used++] =  lsftp_cbs[index];
	  else
	    /* FIXME: What's intended here? */
	    used;                           /* Don't move, just count */
	}
      index++;
    }

  return used;
}






int lsftp_sftp_cb_init( int new_sftp_callbacks )
{
  int i = 0;
  void* newmem;

  if( sftp_cbs )
    i = lsftp_compact_sftp_cbs();

  if( i > new_sftp_callbacks ) /* Too few callbacks to fit existing */
    return -1;

  newmem = realloc( sftp_cbs, sizeof( struct sftp_callback ) * new_sftp_callbacks );

  if( !newmem ) /* realloc failed? */
    {
      perror( "realloc failed" );
      return -2;
    }

  sftp_callbacks = new_sftp_callbacks;
  sftp_cbs = newmem;

  for( ; i < sftp_callbacks; i++ )
    sftp_null_state(&sftp_cbs[i]);


  return 0;
}


void lsftp_sftp_cb_uninit()
{
  if( !sftp_cbs )
    return;

  free( sftp_cbs );

  sftp_cbs = 0;
  sftp_callbacks = 0;
  
  return;
}




int lsftp_compact_sftp_cbs()
{
  /* Compacts the sftp-callbacks to the beginning, and return the number of callbacks */

  int index = 0;
  int used = 0;

  if( !sftp_cbs )
    return 0;

  while( index < sftp_callbacks )
    {
      if( 
	 sftp_cbs[index].id &&          /* Used callback */
	 sftp_cbs[index].nextfun
	)
	{
	  if( index > used )            /* That should be moved? */
	    sftp_cbs[used++] =  sftp_cbs[index];
	  else
	    /* FIXME: What's intended here? */
	    used;                        /* Don't move, just count */
	}
      index++;
    }

  return used;
}


/* FIXME: It would be better with a function that allocates and
 * returns a struct sftp_callback *. */

int
lsftp_install_sftp_cb(struct sftp_callback *s)
{
  int i = -1;

  i = lsftp_free_sftp_cb();

  if( i == -1 )
    return 0;

  sftp_cbs[i] = *s;

  return 1;
}


#if 0
/* Not used??? */
static int
lsftp_remove_sftp_cb(UINT32 id)
{
  int j, flag=0;

  for( j = 0; j < sftp_callbacks; j++ )
    if( sftp_cbs[j].id == id  ) /* Callback is free? */
      {
	sftp_cbs[j].id = 0;
	flag++;
      }

  return flag;
}
#endif


static int
lsftp_remove_lsftp_cb(int id)
{
  int j, flag;

  for( j = 0, flag = 0; j < lsftp_callbacks; j++ )
    if( lsftp_cbs[j].op_id == id  ) /* Callback is free? */
      {
	lsftp_cbs[j].op_id = 0;
      	flag++;
      }

  return flag;
}


char* lsftp_pwd()
{
  if( curpath ) /* Path set?*/
    return strdup( curpath );

  return strdup("");
}

int
lsftp_do_cd(const char *dir)
{
  const char* real = 0;
  int id;

  if( !dir ) /* dir == NULL? */
    return lsftp_do_cd( "" );  /* Assume we want to go home  */

  if( '/' == dir[0] ||     /* First charater / => absoulte path (or no path set) */
      !curpath ||
      !curpath[0])  
    {                 
      free( (void *) curpath );   /* Free memory used by old curpath */
      curpath = strdup( dir );    /* strdup new path */
    }    
  else
    {
      /* Here we only go if we have a curpath and the new path is relative */

      char* tmp;

      if( !dir[0] )        /* Empty path? Special case, reset path */
	{
	  tmp = malloc( 1 );
	  
	  if( tmp )
	    tmp[0] = 0;         /* Null terminate */
	}
      else
	{
	  /* Two strings with a / to separate them */

	  char* tmp1;

	  tmp = 0;

	  tmp1 = lsftp_concat( curpath, "/" );    /* curpath/ */
	  
	  if( tmp1 )
	    tmp = lsftp_concat( tmp1, dir );       /* Add new path */

	  if( !tmp )
	    perror( "string fiddling failed" );

	  free( tmp1 );
	}
      
      free( (void *) curpath );
      curpath = tmp;
      
    }
  
  if( !curpath ) /* Setting Path failed? */
    return -1;



  /* We now have a path, try to make it absolute */

  id = lsftp_do_realpath( curpath, &real );
  
  if( id > 0)          /* Not a failure? */
    lsftp_await_command( id );      
    
  if( real )         /* If we received an answer */
    {
      free( (void *) curpath );
      curpath = real;
    }

  return 0;
}

const char *
lsftp_unqualify_path(const char *path )
{
  /*
   * Returns the part that was passed to lsftp_qualify_path 
   * does NOT malloc a new string
   */

  const char* tmp;

  if( !path ) /* No path given? */
    return 0;

  if( !curpath || /* No path set or empty path */
      !curpath[0] 
      )
    return path;      /* We just gave it the path */

  /* FIXME: Breaks if someone gives curpath explicitly */

  tmp = lsftp_skip_common( path, curpath );

  if( !tmp )
    return 0;

  while( *tmp && 
	 '/' == *tmp
	 )
    tmp++;
  
  return tmp;
}

char *
lsftp_qualify_path(const char *path)
{
  /* Given a filename, converts it to something to send to the other
   * side (no operation on absoulte paths, adds pwd/ to relative paths
   */

  if( '/' == path[0] ||
      !curpath ||
      !curpath[0]
      )
    {
      /* Absolute path, no curpath given ever (or reset) */
      char* s = strdup( path );

      if( !s ) /* FIXME: What to do? */
	;

      return s;
    }
  else
    {
      /* Here we only go if we have a curpath */
      

      char* tmp1;
      char* tmp2;
      
      tmp1 = lsftp_concat( curpath, "/" );

      if( tmp1 ) /* Don't do this if it failed */
	tmp2 = lsftp_concat( tmp1, path );
      else
	/* FIXME: What to do here? */
	tmp2 = NULL;
      return tmp2;
    }

  /* Should newer get here */

  return 0;
}

int
lsftp_do_put(const char *local, const char *remote,
	     const char *command, int cont)
{
  int id;
  int index;
  const char* tmp;
  struct sftp_callback s;

  id = lsftp_install_lsftp_cb( lsftp_handle_put );
  index = lsftp_cb_index( id );

  if( id && id != -1 && index != -1)
    {
      int freeflag = 1;

      tmp = lsftp_qualify_path( remote );

      if( !tmp )   /* Problem with qualifying the name? */
	{
	  freeflag = 0;
	  tmp = remote;
	}

      lsftp_cbs[index].local = strdup( local ); 
      lsftp_cbs[index].remote = strdup( tmp ); 
      lsftp_cbs[index].command = strdup( command );

      lsftp_safe_to_write();   /* Wait for any unsent packet to go away */

      sftp_put_file_init(&s, id, in, out, 
			 tmp, strlen( tmp ), 
			 local, strlen( local), 
			 cont);
      
      if( freeflag )
	free( (void *) tmp );

      if( s.nextfun )
	lsftp_install_sftp_cb( &s );
      else
	{
	  lsftp_perror( local, s.localerrno );
	  lsftp_remove_lsftp_cb( id );
	  return -1;
	}
    }

  return id;
}


int
lsftp_handle_put(struct sftp_callback *s,
		 const struct lsftp_callback *l)
{
  if( s->retval != SSH_FX_OK )
    lsftp_report_error( s, l );

  if( s->localerr )
    lsftp_perror( l->local, s->localerrno );

  return s->retval;
}

int
lsftp_do_ls(const char* dir, const char* command, int longlist, int all)
{
  /* Do ls for glob, now accepts a more, but will only return the last id */

  /* FIXME: What to return if there are no id:s? */
  int id = 0;
  int index;
  const char *tmp;
  const char **glob;
  const char **orgglob;
  const char *ptr;
  char *dglob = NULL;
  const char *fnameg = NULL;
  int i = 0;

  struct sftp_callback s;

  if( !dir )    /* No path/glob given? */
    return -1;

  dglob = strdup( dir );
  
  if( !dglob ) /* failed? Don't try to repair, just bail out */
    return -1;

  i = strlen( dglob );  /* Get length */
  
  while(   /* Find rightmost slash */
	( 0 <= i ) && 
	( '/' != dglob[i] )
	 )
    i--;

/*   printf( "i is %d\n", i ); */

  if( i != -1 ) /* Slash found? */
    if( i )        /* Not the first charater? */
      dglob[i] = 0; /* Anything left of the last slash is handled now, to the right is left for lsftp_handle_ls */
    else
      dglob[1] = 0; /* Keep slash */
  else
    dglob[0] = 0; /* No slash - empty dglob */
  

  if( -1 != i )
    fnameg = strdup( dir + i + 1); /* Get the local part of the glob */
  else
    fnameg = strdup( dir );        /* Only local glob */
  
  glob = lsftp_dc_r_startglob( dglob, 0, 1 ); /* Not sloppy, leave incorrect ones */
  orgglob = glob;

  if( !strlen( fnameg ) ) /* Empty filename glob? */
    {
      char* gtmp = strdup( "*" ); /* Replace with a star */
      
      if( gtmp )
	{
	  free( (void *) fnameg );
	  fnameg = gtmp;	  
	}
    }

/*   printf( "dglob is %s\n", dglob ); */

  while( (ptr = *glob++) ) 
    {
/*       printf( "ptr is %s, fnameg is %s\n", ptr, fnameg ); */

      id = lsftp_install_lsftp_cb( lsftp_handle_ls );
      index = lsftp_cb_index( id );
      
      if( id && id != -1 && index != -1 ) /* Everything ok? */
	{
	  tmp = lsftp_qualify_path( ptr );

	  /* Leave informational message */
	  
	  if( tmp )
	    lsftp_cbs[index].remote = strdup( tmp ); 
	  else
	    lsftp_cbs[index].remote = 0; 
	  
	  lsftp_cbs[index].command = strdup( command ); 
	  lsftp_cbs[index].opt1 = all; 
	  lsftp_cbs[index].opt2 = longlist; 
	  
	  if( fnameg )
	    lsftp_cbs[index].memory = strdup( fnameg );
	  else
	    lsftp_cbs[index].memory = 0;

	  
	  if( !strlen(tmp) )
	    {
	      /* Empty path, should work, but misbehaves. Replace with . */
	      free( (void *) tmp );
	      
	      tmp = strdup( "." );
	    }
	  
     	  lsftp_safe_to_write();   /* Wait for any unsent packet to go away */
	  
	  sftp_ls_init(&s, id, in, out,
		       tmp, 
		       strlen( tmp ) );
	  
	  free( (void *) tmp );
	  
	  if( s.nextfun )
	    lsftp_install_sftp_cb( &s );
	  else
	    {
	      lsftp_perror( dir, s.localerrno );
	      lsftp_remove_lsftp_cb( id );
	      id = -1;
	    }
	}
    }

/*   printf( "Done with glob results\n" ); */

  lsftp_dc_endglob( orgglob );
  
  free( dglob );
  free( (void *) fnameg );

  return id; 
}

/* FIXME: Use void ** arguments? */
static int
string_comparer(char **s1, char **s2)
{
#ifdef HAVE_STRCOLL 
  return strcoll( *s1,*s2 );
#else
  return strcmp( *s1, *s2 );
#endif
}


int
lsftp_handle_ls(struct sftp_callback *s,
		const struct lsftp_callback *l)
{
  char* prefix = strdup( l->remote );

  int all = l->opt1;
  int longlist = l->opt2;
  char** namestrings = 0;
  char** longstrings = 0;

  int allocated = 0;
  int allocstepsize = 100;
  int used = 0;

/*    printf( "Entered handle ls\n" ); */

  namestrings = malloc( allocstepsize * sizeof( char* ) );

  if( !namestrings ) /* Failed to allocate memory */
    {
      perror( "malloc failed" );
      printf( "Files will be displayed one per line, out of order.\n" );
    }
  else
    allocated += allocstepsize;

  if( longlist )
    {
      longstrings = malloc( allocstepsize * sizeof( char* ) );
  
      if( !longstrings ) /* Failed to allocate memory */
	{
	  perror( "malloc failed" );
	  printf( "Files will be displayed one per line, out of order.\n" );

	  if( namestrings )
	    {
	      free( namestrings );
	      namestrings = 0;
	      allocated = 0;
	    }
	}
    }
  
  
  if( s->retval != SSH_FX_OK &&
      s->retval != SSH_FX_EOF 
      )  /* We should have EOF or OK status */
	lsftp_report_error( s, l );

  if( s->localerr ) /* Highly unlikely, but report it if we have a local error */
    lsftp_perror( l->local, s->localerrno );


  sftp_toggle_mem( &s->mem ); /* Reset counter so we can read */
  
  if( prefix ) /* Dup succeded */
    {
      int len;

      len = strlen( prefix );

      if( len &&                  /* If needed, add trailing slash */
	  '/' != prefix[len-1] 
	  )
	{
	  char* tmp = lsftp_concat( prefix, "/" );

	  if( tmp )
	    {
	      free( prefix );
	      prefix = tmp;
	    }
	}
    }

  while( 1 )
    {
      UINT32 slen = 1;
      UINT32 *p;
      
      void* lenptr;
      UINT8* fname;
      UINT32 fnamelen;
      UINT8* longname;
      UINT32 longnamelen;
      void* attrib;
      UINT32 attriblen;
      struct sftp_attrib* a;
      char* prefixed_fname;

      lenptr = sftp_retrieve( &s->mem, 4, &slen); /* Get string length */ 
      
      if( slen != 4 )
	break;
      
      p = lenptr;         /* Explicit cast to lessen warnings */
      slen = *p;          /* Read as UINT32 (no conversion needed) */
      sftp_free_string( lenptr );
      fname = sftp_retrieve( &s->mem, slen, &fnamelen); /* Get string */
      
      /* Get filename string */ 
      lenptr = sftp_retrieve( &s->mem, 4, &slen);

      if( slen != 4 )
	break;

      p = lenptr;       /* Explicit cast to lessen warnings */
      slen = *p;     /* Read as UINT32 (no conversion needed) */
      sftp_free_string( lenptr );
      longname = sftp_retrieve( &s->mem, slen, &longnamelen); /* Get string */
      
      
      lenptr = sftp_retrieve( &s->mem, 4, &slen); 
      if( slen != 4 )
	break;

      p = lenptr;                /* Explicit cast to lessen warnings */
      slen = *p;                                    /* Read as UINT32 (no conversion needed) */
      sftp_free_string( lenptr );
      
      /* Get attrib */
      attrib = sftp_retrieve( &s->mem, slen, &attriblen); 
      a = attrib;       /* Explicit cast to lessen warnings */

      prefixed_fname = lsftp_concat( prefix, fname );
      lsftp_dc_notice( prefixed_fname, a );

      if(  /* We're using namestrings and we need to fix more room? */
	 namestrings &&
	 ( used <= allocated )
	 )
	{
	  char** newnamestrings = realloc( namestrings, sizeof( char* ) * ( allocated + allocstepsize ) );
	  char** newlongstrings = 0;

	  if( longlist )
	    newlongstrings = realloc( longstrings, sizeof( char* ) * ( allocated + allocstepsize ) );

	  if( !newnamestrings ||  /* realloc failed for either? */
	      (longlist && ! newlongstrings)
	      )
	    {
	      int l;
	      perror( "realloc failed" );

	      /* The old memory is untouched, we just print what we have (out of order) and when free it. */
	      
	      for( l=0; l < used; l++ )
		{
		  if( longlist )
		    {
		      printf( "%s\n", longstrings[l] );
		      free( longstrings[l] );
		    }
		  else
		    printf( "%s\n", namestrings[l] );

		  free( namestrings[l] );
		}

	      free( namestrings );
	      free( longstrings );

	      namestrings = 0;
	      longstrings = 0;
	    }
	  else
	    {
	      allocated += allocstepsize;
	      namestrings = newnamestrings;
	      longstrings = newlongstrings;
	    }
	}

      if( ( l->memory &&                              /* Filepart glob given? */ 
	    lsftp_dc_glob_matches(                   /* That matches */
				  fname, 
				  l->memory,
				  all
				  )
	    ) ||                                     /* or... */
	  !l->memory                                  /* No glob given*/
	  )

	if( !namestrings ) /* No place to store information in */
	  {
	    if( longlist )         /* Long info? */
	      printf( "%s\n", longname );                /* Print it */
	    else
	      {
		if( (a->flags & SSH_FILEXFER_ATTR_PERMISSIONS ) &&  /* Ehrrm... */
		    (a->permissions & S_IFDIR )                   /* Directory? */
		    )
		  printf( "%s/\n", fname );                /* Print it */
		else
		  printf( "%s\n", fname );                /* Print it */
		
	      }
	  }
	else
	  { /* Don't print now, do that later */
	    char* tmp = 0;
	    
	    if( (a->flags & SSH_FILEXFER_ATTR_PERMISSIONS ) &&  /* Ehrrm... */
		(a->permissions & S_IFDIR ) )                   /* Directory? */
	      tmp = lsftp_concat( fname, "/" ); /* Add a trailing slash for directories */
	    else
	      tmp = strdup( fname );

	    /* Nothing to do if concat or strdup failed */

	    namestrings[used++] = tmp;
	    
	    if( longlist )
	      longstrings[used-1] = strdup( longname );
	  }

      free( prefixed_fname );
      sftp_free_string( longname );
      sftp_free_string( fname );
      sftp_free_string( attrib );
    }
  
  
  if( namestrings )
    if( !longlist )
      {
	/* Start by sorting the argument in the list */

	int i;
	int numcols = 4;
	/* FIXME: Unused? */
	int screenwidth = 80;
	int* colwidths = 0;

	qsort( namestrings, used, sizeof( char* ), string_comparer );
	
	colwidths = malloc( numcols * sizeof( int ) );

	if( !colwidths )
	  {
	    perror( "malloc failed. Listing files one per line");
	    for( i = 0; i < used; i++ )
	      printf( "%s\n", namestrings[i] );
	  } 
	else
	  {
	    for( i = 0; i < used; i++ )
              printf( "%s\n", namestrings[i] );
	  }

	for( i = 0; i < used; i++ )
	  free( namestrings[i] );
      }
    else
      {
	int i;
	char** string_array = 0;

	/* We'll sort them together */
 	string_array = malloc( used * sizeof( char* ) * 2 ); 
			     
	if( !string_array )
	  perror( "malloc failed, no sorting can be performed." );
	else
	  {
	    for( i = 0; i < used; i++ )
	      {
		string_array[2*i] = namestrings[i];
		string_array[2*i+1] = longstrings[i];
	      }

	    qsort( string_array, used, 2*sizeof( char* ), string_comparer );
	  }

	for( i = 0; i < used; i++ )
	  {
	    if( string_array )
	      {
		printf( "%s\n", string_array[2*i+1] );
		free(  string_array[2*i+1] );
		free(  string_array[2*i] );
	      }
	    else
	      {
		printf( "%s\n", longstrings[i]);
		
		free( namestrings[i] );
		free( longstrings[i] );
	      }
	  }

	free( string_array );
      }
  
  free( namestrings );
  free( longstrings );

  sftp_free_mem( &s->mem );
  
  free( l->memory );
  free( prefix );
  return s->retval;
} 

int
lsftp_internal_ls(const char *dir, const char *command,
		  const char*** dirinfop )
{
      int id;
      int index;
      const char* tmp;
      
      struct sftp_callback s;
      
      id = lsftp_install_lsftp_cb( lsftp_handle_internal_ls );
      index = lsftp_cb_index( id );

      if( id && id != -1 && index != -1 ) /* Everything ok? */
	{
	  tmp = lsftp_qualify_path( dir );
      
	  /* Leave informational message */
	  lsftp_cbs[index].remote = strdup( tmp ); 
	  lsftp_cbs[index].command = strdup( command ); 
	  lsftp_cbs[index].memory = dirinfop; 

	  if( !strlen(tmp) )
	    {
	      /* Empty path, should work, but misbehaves. Replace with . */
	      free( (void *) tmp );
	      
	      tmp = strdup( "." );
	    }
	  
	  lsftp_safe_to_write();   /* Wait for any unsent packet to go away */

	  sftp_ls_init(&s, id, in, out,
		       tmp,
		       strlen( tmp ) );
	  
	  free( (void *) tmp );
      
	  if( s.nextfun )
	    lsftp_install_sftp_cb( &s );
	  else
	    {
	      lsftp_perror( dir, s.localerrno );
	      lsftp_remove_lsftp_cb( id );
	      return -1;
	    }
	}
      
      return id;       
}

int
lsftp_handle_internal_ls(struct sftp_callback *s, 
			 const struct lsftp_callback *l)
{
  char** mem = 0;
  char*** dirinfop = l->memory;
  char* prefix = strdup( l->remote );
  
  int allocated = 0;
  int used = 0;
  int allocstepsize = 100;
  int len;

  if( s->retval != SSH_FX_OK &&
      s->retval != SSH_FX_EOF &&
      s->retval != SSH_FX_NO_SUCH_FILE  &&
      s->retval != SSH_FX_FAILURE 
      )  /* OK or EOF are ok, as are NO_SUCH_FILE */
    {
      lsftp_report_error( s, l );
      free( prefix );
      *dirinfop = 0;
      return -1;
    }

  if( s->localerr ) /* Report any localerrors */
    lsftp_perror( l->local, s->localerrno );

  mem = malloc( allocstepsize * sizeof( char* ) ); /* Allocate initial memory */
  
  if( !mem )
    {
      free( prefix );
      *dirinfop = 0;
      return -1;
    }

  allocated += allocstepsize;

  if( prefix ) /* Dup succeded */
    {
      len = strlen( prefix );

      if( len &&                  /* If needed, add trailing slash */
	  '/' != prefix[len-1] 
	  )
	{
	  char* tmp = lsftp_concat( prefix, "/" );

	  if( tmp )
	    {
	      free( prefix );
	      prefix = tmp;
	    }
	}
    }

  sftp_toggle_mem( &s->mem ); /* Reset counter so we can read */
  
  while( 1 )
    {
      UINT32 slen = 1;
      UINT32 *p;
      
      void* lenptr;
      UINT8* fname = 0;
      UINT32 fnamelen = 0;
      UINT8* longname = 0;
      UINT32 longnamelen = 0;
      void* attrib = 0;
      UINT32 attriblen = 0;
      struct sftp_attrib *a;
      char* prefixed_fname;
      
      lenptr = sftp_retrieve( &s->mem, 4, &slen); /* Get string length */ 
      
      if( slen != 4 )
	break;
      
      p = lenptr; 
      slen = *p;               /* Read as UINT32 (no conversion needed) */
      sftp_free_string( lenptr );
      fname = sftp_retrieve( &s->mem, slen, &fnamelen); /* Get string */
      
      lenptr = sftp_retrieve( &s->mem, 4, &slen); /* Get filename string */ 
      if( slen != 4 )
	break;
  
      p = lenptr; 
      slen = *p;             /* Read as UINT32 (no conversion needed) */
      sftp_free_string( lenptr );
      longname = sftp_retrieve( &s->mem, slen, &longnamelen); /* Get string */
      
      lenptr = sftp_retrieve( &s->mem, 4, &slen); /* Get filename string */ 
 
      if( slen != 4 )
	break;
       
      p = lenptr; 
      slen = *p;            /* Read as UINT32 (no conversion needed) */
      sftp_free_string( lenptr );
      attrib = sftp_retrieve( &s->mem, slen, &attriblen); /* Get attrib */
      a = attrib;
      
      prefixed_fname = lsftp_concat( prefix, fname );

      lsftp_dc_notice( prefixed_fname, a );
      
      if( allocated == used )
	{
	  char** newmem;

	  newmem = realloc( mem, ( allocated + allocstepsize ) * sizeof( char* ) );
	  
	  if( !newmem )  /* realloc failed? */
	    {
	      perror("realloc failed");
	      free( mem );

	      *dirinfop = 0;

	      return -1;
	    }

	  mem = newmem;
	  allocated += allocstepsize;
	}
      
      mem[used++] = prefixed_fname;
      
      sftp_free_string( longname );
      sftp_free_string( fname );
      sftp_free_string( attrib );
    }
  
  if( allocated == used )
    {
      char** newmem;
      
      newmem= realloc( mem, ( allocated + allocstepsize ) * sizeof( char* ) );
      
      if( !newmem ) /* realloc failed? */
	{
	  perror("realloc failed");
	  free( mem );

	  *dirinfop = 0;    /* No pointer */

	  return -1;
	}

      mem = newmem;
      allocated += allocstepsize;
    }

  mem[used++] = 0;

  *dirinfop = mem;

  free( prefix ); 
  sftp_free_mem( &s->mem );
  return s->retval;
}

int
lsftp_do_stat(const char *file, struct stat *st )
{
  int id;
  int index;
  
  const char* tmp;
  struct sftp_callback s;
  
  id = lsftp_install_lsftp_cb( lsftp_handle_stat );
  index = lsftp_cb_index( id );
  
  if( id && id != -1 && index != -1 ) /* Everything ok? */
    {
      int freeflag = 1;
      tmp = lsftp_qualify_path( file );
      
      if( !tmp )   /* Problem with qualifying the name? */
	{
	  freeflag = 0;
	  tmp = file;
	}
      
      lsftp_cbs[index].st = st; /* Fixup attrib */

      lsftp_safe_to_write();   /* Wait for any unsent packet to go away */

      sftp_stat_init(&s, id, in, out,
		     tmp, strlen( tmp ));
      
      if( freeflag )
	free( (void *) tmp );

      /* FIXME: Ugly indentation */
	  if( s.nextfun )
	    lsftp_install_sftp_cb( &s );
	  else
	    {
	      /* We should newer have a local error for setstat */
	      lsftp_perror( file, s.localerrno );
	      lsftp_remove_lsftp_cb( id );
	      return -1;
	    }
    }
  return id;  
}

int
lsftp_do_realpath(const char* file, const char **destptr )
{
  int id;
  int index;
  
  const char* tmp;
  struct sftp_callback s;
  
  id = lsftp_install_lsftp_cb( lsftp_handle_realpath );
  index = lsftp_cb_index( id );
  
  if( id && id != -1 && index != -1 ) /* Everything ok? */
    {
      int freeflag = 1;
      tmp = lsftp_qualify_path( file ); /* Hrrm, should we qualify here? Probably */
      
      if( !tmp )   /* Problem with qualifying the name? */
	{
	  freeflag = 0;
	  tmp = file;
	}
      
      lsftp_cbs[index].memory = destptr;
      lsftp_cbs[index].remote = strdup( file ) ; /* Info */

      lsftp_safe_to_write();   /* Wait for any unsent packet to go away */

      sftp_realpath_init(&s, id, in, out,
			 tmp, 
			 strlen( tmp ) );
      
      if( freeflag )
	free( (void *) tmp );
      
      if( s.nextfun )
	lsftp_install_sftp_cb( &s );
      else
	{
	  /* We should never have a local error for realpath */
	  lsftp_perror( file, s.localerrno );
	  lsftp_remove_lsftp_cb( id );
	  return -1;
	}
    }

  return id;  
}

int
lsftp_handle_realpath(struct sftp_callback *s,
		      const struct lsftp_callback *l)
{
  /* Should we check status here? */

  if( s->retval != SSH_FX_OK )  /* We should have an OK status */
	lsftp_report_error( s, l );

  if( s->localerr )
    lsftp_perror( l->local, s->localerrno );

  sftp_toggle_mem( &s->mem ); /* Reset counter so we can read */
  
  while( 1 ) /* */
    {
      UINT32 slen = 1;
      UINT32 *p;
      
      void* lenptr;
      UINT8* fname;
      UINT32 fnamelen;
      UINT8* longname;
      UINT32 longnamelen;
      void* attrib;
      UINT32 attriblen;
      /* FIXME: Not used? */
      struct sftp_attrib *a;
      char** destptr;


      lenptr = sftp_retrieve( &s->mem, 4, &slen); /* Get string length */ 
      
      if( slen != 4 )
	break;
      
      p = lenptr; 
      slen = *p;          /* Read as UINT32 (no conversion needed) */
      sftp_free_string( lenptr );
      fname = sftp_retrieve( &s->mem, slen, &fnamelen); /* Get string */
      
      /* Get filename string */ 
      lenptr = sftp_retrieve( &s->mem, 4, &slen);
      p = lenptr; 
      slen = *p;     /* Read as UINT32 (no conversion needed) */
      sftp_free_string( lenptr );
      longname = sftp_retrieve( &s->mem, slen, &longnamelen); /* Get string */
      
      
      lenptr = sftp_retrieve( &s->mem, 4, &slen); 
      p = lenptr; 
      slen = *p;            /* Read as UINT32 (no conversion needed) */
      sftp_free_string( lenptr );
      
      /* Get attrib */
      attrib = sftp_retrieve( &s->mem, slen, &attriblen); 
            
      /* The attribs may be fake, so don't notice */

      destptr = l->memory;
      *destptr = strdup( fname ); /* Copy whatever name we have */
      
      sftp_free_string( longname );
      sftp_free_string( fname );
      sftp_free_string( attrib );
    }
  
  sftp_free_mem( &s->mem );
  return s->retval;
} 

int
lsftp_do_chown(const char *file, UINT32 uid, UINT32 gid, const char *command)
{
  int id;
  int index;
      
  const char* tmp;
  struct sftp_callback s;
  struct sftp_attrib* attrib;
  
  id = lsftp_install_lsftp_cb( lsftp_handle_chall );
  index = lsftp_cb_index( id );
  
  if( id && id != -1 && index != -1 ) /* Everything ok? */
    {
      int freeflag = 1;
      tmp = lsftp_qualify_path( file );
      
      if( !tmp )   /* Problem with qualifying the name? */
	{
	  freeflag = 0;
	  tmp = file;
	}
      
      attrib = malloc( sizeof( struct sftp_attrib ) );
      
      if( ! attrib ) /* Malloc failed? FIXME: Report? */
	return -1;
      
      lsftp_cbs[index].a = attrib; /* Fixup attrib */
      /* Leave informational message */
      lsftp_cbs[index].remote = strdup( tmp );
      lsftp_cbs[index].command = strdup( command );
      
      sftp_clear_attrib( attrib );      
      attrib->flags = SSH_FILEXFER_ATTR_UIDGID; /* We send UID & GID */
      attrib->uid = uid;
      attrib->gid = gid;
      
      lsftp_safe_to_write();   /* Wait for any unsent packet to go away */
      
      sftp_setstat_init(&s, id, in, out,
			tmp, strlen( tmp ), 
			attrib);
      
      if( freeflag )
	free( (void *) tmp );
      
      if( s.nextfun )
	lsftp_install_sftp_cb( &s );
      else
	{
	  /* We should newer have a local error for setstat */
	  lsftp_perror( file, s.localerrno );
	  lsftp_remove_lsftp_cb( id );
	  return -1;
	}
    }
  return id;  
}


int
lsftp_do_chmod(const char *file, mode_t mode, const char *command)
{
  int id;
  int index;
  
  const char* tmp;
  struct sftp_callback s;
  struct sftp_attrib* attrib;
  
  id = lsftp_install_lsftp_cb( lsftp_handle_chall );
  index = lsftp_cb_index( id );
  
  if( id && id != -1 && index != -1 ) /* Everything ok? */
    {
      int freeflag = 1;
      tmp = lsftp_qualify_path( file );
      
      if( !tmp )   /* Problem with qualifying the name? */
	{
	  freeflag = 0;
	  tmp = file;
	}
      
      attrib = malloc( sizeof( struct sftp_attrib ) );
      
      if( ! attrib ) /* Malloc failed? FIXME: Report? */
	return -1;
      
      lsftp_cbs[index].a = attrib; /* Fixup attrib */
      
      /* Leave informational message */
      lsftp_cbs[index].remote = strdup( tmp ); 
      lsftp_cbs[index].command = strdup( command ); 
      
      sftp_clear_attrib( attrib );      
      
      /* We send permissions */
      attrib->flags = SSH_FILEXFER_ATTR_PERMISSIONS; 
      attrib->permissions = mode;
      
      lsftp_safe_to_write();   /* Wait for any unsent packet to go away */
      
      sftp_setstat_init(&s, id, in, out,
			tmp, strlen( tmp ), 
			attrib);
      
      if( freeflag )
	free( (void *) tmp );
      
      if( s.nextfun )
	lsftp_install_sftp_cb( &s );
      else
	{
	  /* We should newer have a local error for setstat */
	  lsftp_perror( file, s.localerrno );
	  lsftp_remove_lsftp_cb( id );
	  return -1;
	}
    }
  return id;  
}

int
lsftp_handle_stat(struct sftp_callback *s,
		  const struct lsftp_callback *l)
{
  l->st->st_mode = -1;
  l->st->st_ino = -1;
  l->st->st_dev = -1;
  l->st->st_rdev = -1;
  l->st->st_nlink = -1;
  l->st->st_uid = -1;
  l->st->st_gid = -1;
  l->st->st_size = -1;
  l->st->st_atime = -1;
  l->st->st_mtime = -1;
  l->st->st_ctime = -1;
  
  if( s->localerr )
    lsftp_perror( l->local, s->localerrno );

  if( s->retval == SSH_FX_OK )  /* We should have an OK status */
    {
      if( s->attrib.flags & SSH_FILEXFER_ATTR_SIZE )
	l->st->st_size = s->attrib.size;
      
      if( s->attrib.flags & SSH_FILEXFER_ATTR_UIDGID )
	{
	  l->st->st_uid = s->attrib.uid;
	  l->st->st_gid = s->attrib.gid;
	}
      
      if( s->attrib.flags & SSH_FILEXFER_ATTR_ACMODTIME )
	{
	  l->st->st_atime = s->attrib.atime;
	  l->st->st_ctime = s->attrib.mtime;
	}
      
      if( s->attrib.flags & SSH_FILEXFER_ATTR_PERMISSIONS )
	l->st->st_mode = s->attrib.permissions;
    }
  
  return s->retval;
}


int
lsftp_handle_chall(struct sftp_callback *s,
		   const struct lsftp_callback *l)
{
  if( l->a ) /* Memory for attribute? */
    free( l->a ); /* Free it */

  if( s->retval != SSH_FX_OK )  /* We should have an OK status */
    lsftp_report_error( s, l );

  if( s->localerr )
    lsftp_perror( l->local, s->localerrno );
  
  return s->retval;
}


int
lsftp_do_mv(const char *src, const char *dst, const char *command )
{
  int id;
  int index;
      
  const char* tmp1;
  const char* tmp2;

  struct sftp_callback s;
  
  id = lsftp_install_lsftp_cb( lsftp_handle_alldir );
  index = lsftp_cb_index( id );
  
  if( id && id != -1 && index != -1 ) /* Everything ok? */
    {
      int freeflag1 = 1;
      int freeflag2 = 1;

      tmp1 = lsftp_qualify_path( src );
      tmp2 = lsftp_qualify_path( dst );
      
      if( !tmp1 )   /* Problem with qualifying the name? */
	{
	  freeflag1 = 0;
	  tmp1 = src;
	}

      if( !tmp2 )   /* Problem with qualifying the name? */
	{
	  freeflag2 = 0;
	  tmp2 = dst;
	}
      
      /* Leave informational message */
      lsftp_cbs[index].remote = strdup( tmp2 );
      lsftp_cbs[index].command = strdup( command );

      lsftp_safe_to_write();   /* Wait for any unsent packet to go away */
      
      sftp_rename_init(&s, id, in, out,
		       tmp1,
		       strlen( tmp1 ),
		       tmp2,
		       strlen( tmp2 ));
      
      if( freeflag1 )
	free( (void *) tmp1 );

      if( freeflag2 )
	free( (void *) tmp2 );
     
      if( s.nextfun )
	lsftp_install_sftp_cb( &s );
      else
	{
	  /* We should newer have a local error for mv */
	  lsftp_perror( src, s.localerrno );
	  lsftp_remove_lsftp_cb( id );
	  return -1;
	}
    }
  return id;  
}

int
lsftp_do_ln(const char *link, const char *target, const char *command)
{
  int id;
  int index;
      
  const char* tmp1;
  const char* tmp2;

  struct sftp_callback s;
  
  id = lsftp_install_lsftp_cb( lsftp_handle_alldir );
  index = lsftp_cb_index( id );
  
  if( id && id != -1 && index != -1 ) /* Everything ok? */
    {
      int freeflag1 = 1;
      int freeflag2 = 1;

      tmp1 = lsftp_qualify_path( link );
      tmp2 = lsftp_qualify_path( target );
      
      if( !tmp1 )   /* Problem with qualifying the name? */
	{
	  freeflag1 = 0;
	  tmp1 = link;
	}

      if( !tmp2 )   /* Problem with qualifying the name? */
	{
	  freeflag2 = 0;
	  tmp2 = target;
	}
      
      /* Leave informational message */
      lsftp_cbs[index].remote = strdup( tmp2 );
      lsftp_cbs[index].command = strdup( command );

      lsftp_safe_to_write();   /* Wait for any unsent packet to go away */
      
      sftp_symlink_init(&s, id, in, out,
			tmp1,
			strlen( tmp1 ),
			tmp2,
			strlen( tmp2 ));
      
      if( freeflag1 )
	free( (void *) tmp1 );

      if( freeflag2 )
	free( (void *) tmp2 );
     
      if( s.nextfun )
	lsftp_install_sftp_cb( &s );
      else
	{
	  /* We should newer have a local error for ln */
	  lsftp_perror( link, s.localerrno );
	  lsftp_remove_lsftp_cb( id );
	  return -1;
	}
    }
  return id;  
}

int
lsftp_do_mkdir(const char *dir, int permissions, const char *command)
{
  int id;
  int index;
  int mask = 0777; /* FIXME: Implement remote umask */

  const char *tmp;
  struct sftp_callback s;
  struct sftp_attrib* attrib;
  
  id = lsftp_install_lsftp_cb( lsftp_handle_alldir );
  index = lsftp_cb_index( id );
  
  if( id && id != -1 && index != -1 ) /* Everything ok? */
    {
      int freeflag = 1;
      tmp = lsftp_qualify_path( dir );
      
      if( !tmp )   /* Problem with qualifying the name? */
	{
	  freeflag = 0;
	  tmp = dir;
	}
      
      /* Leave informational message */
      lsftp_cbs[index].remote = strdup( tmp );
      lsftp_cbs[index].command = strdup( command );

      
      attrib = malloc( sizeof( struct sftp_attrib ) );
      
      if( ! attrib ) /* Malloc failed? FIXME: Report? */
	return -1;
      
      /* Leave informational message */
      
      sftp_clear_attrib( attrib );      
      attrib->flags = SSH_FILEXFER_ATTR_PERMISSIONS; /* We send UID & GID */
      attrib->permissions = permissions & mask;
            
      lsftp_safe_to_write();   /* Wait for any unsent packet to go away */
      
      sftp_mkdir_init(&s, id, in, out,
		      tmp,
		      strlen( tmp ),
		      attrib);
      
      if( freeflag )
	free( (void *) tmp );
      
      free( attrib );

      if( s.nextfun )
	lsftp_install_sftp_cb( &s );
      else
	{
	  /* We should newer have a local error for mkdir */
	  lsftp_perror( dir, s.localerrno );
	  lsftp_remove_lsftp_cb( id );
	  return -1;
	}
    }
  return id;  
}

int
lsftp_do_rmdir(const char *dir, const char *command)
{
  int id;
  int index;
      
  const char* tmp;
  struct sftp_callback s;
  /* FIXME: Unsued? */
  struct sftp_attrib* attrib;
  
  id = lsftp_install_lsftp_cb( lsftp_handle_alldir );
  index = lsftp_cb_index( id );
  
  if( id && id != -1 && index != -1 ) /* Everything ok? */
    {
      int freeflag = 1;
      tmp = lsftp_qualify_path( dir );
      
      if( !tmp )   /* Problem with qualifying the name? */
	{
	  freeflag = 0;
	  tmp = dir;
	}
      
      /* Leave informational message */
      lsftp_cbs[index].remote = strdup( tmp );
      lsftp_cbs[index].command = strdup( command );
            
      lsftp_safe_to_write();   /* Wait for any unsent packet to go away */
      
      sftp_rmdir_init(&s, id, in, out,
		      tmp,
		      strlen( tmp ));
      
      if( freeflag )
	free( (void *) tmp );
      
      if( s.nextfun )
	lsftp_install_sftp_cb( &s );
      else
	{
	  /* We should newer have a local error for rmdir */
	  lsftp_perror( dir, s.localerrno );
	  lsftp_remove_lsftp_cb( id );
	  return -1;
	}
    }
  return id;  
}

int
lsftp_do_rm(const char *path, const char *command )
{
  int id;
  int index;
      
  const char* tmp;
  struct sftp_callback s;
  struct sftp_attrib* attrib;
  
  id = lsftp_install_lsftp_cb( lsftp_handle_alldir );
  index = lsftp_cb_index( id );
  
  if( id && id != -1 && index != -1 ) /* Everything ok? */
    {
      int freeflag = 1;
      tmp = lsftp_qualify_path( path );
      
      if( !tmp )   /* Problem with qualifying the name? */
	{
	  freeflag = 0;
	  tmp = path;
	}
      
      /* Leave informational message */
      lsftp_cbs[index].remote = strdup( tmp );
      lsftp_cbs[index].command = strdup( command );
            
      lsftp_safe_to_write();   /* Wait for any unsent packet to go away */
      
      sftp_remove_init(&s, id, in, out,
		       tmp,
		       strlen( tmp ));
      
      if( freeflag )
	free( (void *) tmp );
      
      if( s.nextfun )
	lsftp_install_sftp_cb( &s );
      else
	{
	  /* We should newer have a local error for rmdir */
	  lsftp_perror( path, s.localerrno );
	  lsftp_remove_lsftp_cb( id );
	  return -1;
	}
    }
  return id;  
}


int
lsftp_handle_alldir(struct sftp_callback *s,
		    const struct lsftp_callback *l)
{
  if( s->retval != SSH_FX_OK )  /* We should have an EOF status */
    lsftp_report_error( s, l );

  if( s->localerr )
    lsftp_perror( l->local, s->localerrno );

  return s->retval;
}

