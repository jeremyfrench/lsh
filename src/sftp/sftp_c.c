/*
 * @(#) $Id$
 *
 * sftp_c.c - sftp client protocol functions.
 *
 * Portions of code taken from the sftp test client from 
 * the sftp server of lsh by Niels Möller and myself.
 *
 */

/* lsftp, an implementation of the sftp protocol
 *
 * Copyright (C) 2001 Pontus Sköld
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

#include "sftp_c.h"

void sftp_attrib_from_stat( struct stat *st, struct sftp_attrib* a )
{
  a->permissions = st->st_mode;
  a->uid = st->st_uid;
  a->gid = st->st_gid;
  a->atime = st->st_atime;
  a->mtime = st->st_mtime;
  a->size = st->st_size;
  a->flags = ( 
	      SSH_FILEXFER_ATTR_SIZE ||
	      SSH_FILEXFER_ATTR_UIDGID ||
	      SSH_FILEXFER_ATTR_PERMISSIONS || 
	      SSH_FILEXFER_ATTR_ACMODTIME
	      );
}

mode_t sftp_attrib_perms( struct sftp_attrib* a )
{
  if( a->flags & SSH_FILEXFER_ATTR_PERMISSIONS )
    return a->permissions;
  
  return -1;
}




struct sftp_callback sftp_null_state()
{
  struct sftp_callback s;

  s.nextfun = 0;
  s.id = 0;
  s.fd = 0;
  s.last = SFTP_HANDLE_LAST_UNKNOWN;
  s.filepos = 0;
  s.filesize = 0;
  s.op_id = 0;
  s.retval = 0;
  s.handle = 0;
  s.handlelen = 0;
  s.localerr = 0;
  s.localerrno = 0;

  s.mem = sftp_null_mem(); 

  s.bad_status = 0;
  s.last_bad = SFTP_HANDLE_LAST_UNKNOWN;

  sftp_clear_attrib( &s.attrib );

  return s;
}


struct sftp_mem sftp_alloc_mem( int desired_size )
{
  /* Reserve a memory block*/

  struct sftp_mem s;
  
  s.at = malloc( desired_size );

  assert( s.at != 0 ); /* Make sure we got some memory */

  s.used = 0;
  s.size = desired_size;

  return s;
}



int sftp_resize_mem( struct sftp_mem *mem, int newsize )
{
  if( !newsize ) /* Want to create an empty block? */
    {
      free( mem-> at ); /* Free used memory */

      mem->size = 0; /* Set everything to zero */
      mem->used = 0;
      mem->at = 0;
    }
  else
    {
      char *newat=realloc( mem->at, newsize );
  
      if ( newat ) /* realloc successful? */
	{
	  mem->at = newat;
	  mem->size = newsize;
	  return 0;
	}
    }

  return -1; /* realloc failed, leave mem unchanged */
}



int sftp_free_mem( struct sftp_mem *mem )
{
  /* Free a reserved memory */

  free( mem->at );

  mem->at = 0;
  mem->size = 0;
  mem->used = 0;

  return 0;
}

struct sftp_mem sftp_null_mem( )
{
  struct sftp_mem s;

  s.at = 0;
  s.size = 0;
  s.used = 0;

  return s;
}

int sftp_toggle_mem( struct sftp_mem* mem )
{
  int newsize = mem->used;
  mem->used = 0;

  return sftp_resize_mem( mem, newsize );
}


int sftp_store( struct sftp_mem* mem, void* data, UINT32 datalen )
{
  if( ( mem->size - mem->used ) < datalen ) /* Won't fit? */
    if ( 
	( -1 ==
	  sftp_resize_mem( mem, mem->used + datalen )   /* Make it larger */
	  )
	)
      return -1; /* Resize failed? */

  memcpy( mem->at + mem->used, data, datalen );
  mem->used += datalen;

  return 0;
}

void* sftp_retrieve( struct sftp_mem* mem, UINT32 desired, UINT32* realsize )
{
  UINT8* s;

  if( ( mem->size - mem->used ) < desired ) /* Requests more than available? */
    *realsize =  mem->size - mem->used;
  else
    *realsize = desired;

  s = xmalloc( *realsize+1 );
  memcpy( s, mem->at + mem->used, *realsize );
  mem->used += *realsize;

  s[*realsize] = 0; /* NUL-terminate for convenience */
  return s;
}



UINT32 sftp_rumask( UINT32 new )
{
  static UINT32 old = 0;
  UINT32 ret = old;

  old = new;
  return ret;
}


UINT32 sftp_unique_id()
{
  static UINT32 id = 0;

  id++;
  return id;
}


int sftp_handshake( 
		   struct sftp_input *in,
		   struct sftp_output *out
		   )
{
  UINT8 msg = -1 ;
  UINT32 use_version = -1;
  int ok;

  sftp_set_msg( out, SSH_FXP_INIT );
  sftp_set_id( out, SFTP_VERSION );

  ok = sftp_write_packet( out );

  if( -1 == ok ) /* Failed */
    return -1;

  ok = 0;

  while( !ok )
    ok = sftp_read_packet( in );
  
  if( -1 == ok )
    return -1;

  ok = 0;

  while( !ok )
    ok = sftp_get_uint8( in, &msg );
  
  if( -1 == ok )
    return -1;

  ok = 0;

  while( !ok )
    ok = sftp_get_uint32( in, &use_version );
  
  if( -1 == ok )
    return -1;

  if( msg == SSH_FXP_VERSION )
/*     { */
/*       printf( "Server responded with message %d and version %d \n", msg, use_version ); */
      return 0;
/*     } */
  
  perror( "failed" );
  printf( "Server responded with message %d and version %d \n", msg, use_version );

  /* FIXME; we silently ignore the version given by the server */

  return -1; /* Report failure to handshake correctly */

}




struct sftp_callback sftp_rename_init(
				      int op_id,
				      struct sftp_input *in, 
				      struct sftp_output *out,
				      UINT8 *srcname,
				      UINT32 srclen,
				      UINT8 *dstname,
				      UINT32 dstlen
				      )
{
  UINT32 id;
  struct sftp_callback state = sftp_null_state();

  id=sftp_unique_id();

  sftp_set_msg( out, SSH_FXP_RENAME );
  sftp_set_id( out, id );

  sftp_put_string( out, srclen, srcname );
  sftp_put_string( out, dstlen, dstname );

  state.last = SFTP_RENAME_INIT;
  state.id = id;
  state.nextfun = sftp_handle_status;
  state.op_id = op_id;

  return state;
}


struct sftp_callback sftp_symlink_init(
				       int op_id,
				       struct sftp_input *in, 
				       struct sftp_output *out,
				       UINT8 *linkname,
				       UINT32 linklen,
				       UINT8 *targetname,
				       UINT32 targetlen
				       )
{
  UINT32 id;
  struct sftp_callback state = sftp_null_state();
  
  id=sftp_unique_id();
  
  sftp_set_msg( out, SSH_FXP_SYMLINK );
  sftp_set_id( out, id );
  
  sftp_put_string( out, linklen, linkname );
  sftp_put_string( out, targetlen, targetname );

  state.last = SFTP_SYMLINK_INIT;
  state.id = id;
  state.nextfun = sftp_handle_status;
  state.op_id = op_id;

  return state;
}


struct sftp_callback sftp_remove_init(
				      int op_id,
				      struct sftp_input *in, 
				      struct sftp_output *out,
				      UINT8 *name,
				      UINT32 namelen
				      )
{
  UINT32 id;
  struct sftp_callback state = sftp_null_state();

  id = sftp_unique_id();

  sftp_set_msg( out, SSH_FXP_REMOVE );
  sftp_set_id( out, id );

  sftp_put_string( out, namelen, name );

  state.last = SFTP_REMOVE_INIT;
  state.id = id;
  state.nextfun = sftp_handle_status;
  state.op_id = op_id;

  return state;
}


struct sftp_callback sftp_mkdir_init(
				      int op_id,
				      struct sftp_input *in, 
				      struct sftp_output *out,
				      UINT8 *name,
				      UINT32 namelen,
				      struct sftp_attrib *a
				      )
{
  UINT32 id;
  UINT32 mask;
  struct sftp_attrib locala = *a;
  struct sftp_callback state = sftp_null_state();

  id = sftp_unique_id();

  sftp_set_msg( out, SSH_FXP_MKDIR );
  sftp_set_id( out, id );

  mask = sftp_rumask( 0 );   /* Perform remote umasking */
  sftp_rumask( mask );

  locala.permissions = locala.permissions & ~mask;

  sftp_put_string( out, namelen, name );
  sftp_put_attrib( out, &locala );
  state.last = SFTP_MKDIR_INIT;
  state.id = id;
  state.nextfun = sftp_handle_status;
  state.op_id = op_id;

  return state;
}


struct sftp_callback sftp_realpath_init(
				      int op_id,
				      struct sftp_input *in, 
				      struct sftp_output *out,
				      UINT8 *name,
				      UINT32 namelen
				      )
{
  UINT32 id;
  struct sftp_callback state = sftp_null_state();

  id = sftp_unique_id();

  sftp_set_msg( out, SSH_FXP_REALPATH );
  sftp_set_id( out, id );

  sftp_put_string( out, namelen, name );

  state.last = SFTP_REALPATH_INIT;
  state.id = id;
  state.nextfun = sftp_handle_name;
  state.op_id = op_id;

  return state;
}

struct sftp_callback sftp_readlink_init(
				      int op_id,
				      struct sftp_input *in, 
				      struct sftp_output *out,
				      UINT8 *name,
				      UINT32 namelen
				      )
{
  UINT32 id;
  struct sftp_callback state = sftp_null_state();

  id = sftp_unique_id();

  sftp_set_msg( out, SSH_FXP_READLINK );
  sftp_set_id( out, id );

  sftp_put_string( out, namelen, name );

  state.last = SFTP_READLINK_INIT;
  state.id = id;
  state.nextfun = sftp_handle_name;
  state.op_id = op_id;

  return state;
}


struct sftp_callback sftp_rmdir_init(
				      int op_id,
				      struct sftp_input *in, 
				      struct sftp_output *out,
				      UINT8 *name,
				      UINT32 namelen
				      )
{
  UINT32 id;
  struct sftp_callback state = sftp_null_state();

  id = sftp_unique_id();

  sftp_set_msg( out, SSH_FXP_RMDIR );
  sftp_set_id( out, id );

  sftp_put_string( out, namelen, name );

  state.last = SFTP_RMDIR_INIT;
  state.id = id;
  state.nextfun = sftp_handle_status;
  state.op_id = op_id;

  return state;
}


struct sftp_callback sftp_stat_init(
				      int op_id,
				      struct sftp_input *in, 
				      struct sftp_output *out,
				      UINT8 *name,
				      UINT32 namelen
				      )
{
  UINT32 id;
  struct sftp_callback state = sftp_null_state();

  id = sftp_unique_id();

  sftp_set_msg( out, SSH_FXP_STAT );
  sftp_set_id( out, id );

/*    printf( "Doing stat for %s\n", name ); */

  sftp_put_string( out, namelen, name );

  state.last = SFTP_STAT_INIT;
  state.id = id;
  state.nextfun = sftp_handle_attrs;
  state.op_id = op_id;

  return state;
}


struct sftp_callback sftp_lstat_init(
				      int op_id,
				      struct sftp_input *in, 
				      struct sftp_output *out,
				      UINT8 *name,
				      UINT32 namelen
				      )
{
  UINT32 id;
  struct sftp_callback state  = sftp_null_state();

  id = sftp_unique_id();

  sftp_set_msg( out, SSH_FXP_LSTAT );
  sftp_set_id( out, id );

  sftp_put_string( out, namelen, name );

  state.last = SFTP_LSTAT_INIT;
  state.id = id;
  state.nextfun = sftp_handle_attrs;
  state.op_id = op_id;

  return state;
}


struct sftp_callback sftp_fstat_init(
				      int op_id,
				      struct sftp_input *in, 
				      struct sftp_output *out,
				      UINT8 *handle,
				      UINT32 handlelen
				      )
{
  UINT32 id;
  struct sftp_callback state = sftp_null_state();

  id = sftp_unique_id();

  sftp_set_msg( out, SSH_FXP_FSTAT );
  sftp_set_id( out, id );

  sftp_put_string( out, handlelen, handle );

  state.last = SFTP_FSTAT_INIT;
  state.id = id;
  state.nextfun = sftp_handle_attrs;
  state.op_id = op_id;

  return state;
}


struct sftp_callback sftp_setstat_init(
				      int op_id,
				      struct sftp_input *in, 
				      struct sftp_output *out,
				      UINT8 *name,
				      UINT32 namelen,
				      struct sftp_attrib *attrib
				      )
{
  UINT32 id;
  struct sftp_callback state = sftp_null_state();

  id=sftp_unique_id();

  sftp_set_msg( out, SSH_FXP_SETSTAT );
  sftp_set_id( out, id );

  sftp_put_string( out, namelen, name );
  sftp_put_attrib( out, attrib );

  state.last = SFTP_SETSTAT_INIT;
  state.id=id;
  state.nextfun=sftp_handle_status;
  state.op_id=op_id;

  return state;
}

struct sftp_callback sftp_fsetstat_init(
				      int op_id,
				      struct sftp_input *in, 
				      struct sftp_output *out,
				      UINT8 *handle,
				      UINT32 handlelen,
				      struct sftp_attrib *attrib
				      )
{
  UINT32 id;
  struct sftp_callback state = sftp_null_state();

  id=sftp_unique_id();

  sftp_set_msg( out, SSH_FXP_FSETSTAT );
  sftp_set_id( out, id );

  sftp_put_string( out, handlelen, handle );
  sftp_put_attrib( out, attrib );

  state.last = SFTP_FSETSTAT_INIT;
  state.id=id;
  state.nextfun=sftp_handle_status;
  state.op_id=op_id;

  return state;
}




/* Get a file to memory */

struct sftp_callback sftp_get_mem_init(
				      int op_id,
				      struct sftp_input *in, 
				      struct sftp_output *out,
				      UINT8 *name,
				      UINT32 namelen,
				      struct sftp_mem *mem,
				      UINT64 startat
				      )
{
  UINT32 id;
  struct sftp_callback state = sftp_null_state();
  struct sftp_attrib a;

  sftp_clear_attrib( &a );
  id = sftp_unique_id();

  sftp_set_msg( out, SSH_FXP_OPEN );
  sftp_set_id( out, id );
  sftp_put_string( out, namelen, name );
  sftp_put_uint32( out, SSH_FXF_READ ); /* Only read, no other flag apply */
  sftp_put_attrib( out, &a );            /* Send an empty attribute */

  state.filepos = startat; /* Start reading from the given position */
  state.id = id;
  state.mem = *mem;
  state.nextfun = sftp_get_mem_step_one;
  state.op_id = op_id;
  state.last = SFTP_GET_MEM_INIT;

  return state;
}


struct sftp_callback sftp_get_mem_step_one(
					    UINT8 msg,
					    UINT32 id,
					    struct sftp_input *in, 
					    struct sftp_output *out,
					    struct sftp_callback state
					    )
{
  struct sftp_callback newstate = state;
  
  if( msg == SSH_FXP_STATUS ) /* Status? */
    return sftp_handle_status( msg, id, in, out, state );

/* Otherwise we shouldn't be here FIXME: Fail gracefully?*/

  assert( msg == SSH_FXP_HANDLE && id == state.id ); 
  
  newstate.handle = sftp_get_string( 
				    in, 
				    &newstate.handlelen 
				    ); /* Get handle */



  /* Now we send a read command */

  id=sftp_unique_id();

  sftp_set_msg( out, SSH_FXP_READ );
  sftp_set_id( out, id );

  sftp_put_string( out, newstate.handlelen, newstate.handle );
  sftp_put_uint64( out, newstate.filepos ); /* Offset */
  sftp_put_uint32( out, SFTP_BLOCKSIZE ); /* Length */

  newstate.id = id;
  newstate.nextfun = sftp_get_mem_main;

  return newstate;
}


struct sftp_callback sftp_get_mem_main(
				       UINT8 msg,
				       UINT32 id,
				       struct sftp_input *in, 
				       struct sftp_output *out,
				       struct sftp_callback state
				       )
{
 
  UINT32 datalen;
  int done = 0;

  UINT8* tmp;  

  struct sftp_callback newstate = state;

  if( msg == SSH_FXP_STATUS ) /* Status? */
    return sftp_handle_status( msg, id, in, out, state );

  /* Otherwise we shouldn't be here FIXME: Fail gracefully?*/
  assert( msg == SSH_FXP_DATA && id == state.id );
  
  newstate.last = SFTP_GET_MEM_MAIN; /* Tell theme where we are */
  
  tmp = sftp_get_string( in, &datalen ); /* Get data */

  /* Append to buffer */
  assert( sftp_store( &newstate.mem, tmp, datalen ) == 0 );
  
  /* Move forward in file */

  newstate.filepos += datalen;

  if( datalen != SFTP_BLOCKSIZE )                /* Got what we asked for? */
    done = 1;               /* Nah, assume short read => EOF => we're done */

  sftp_free_string( tmp );                       /* Free temporary buffer */

  /* Now we send a read command */
  
  id = sftp_unique_id();
  newstate.id = id;

  if( !done ) /* Not yet finished? */
    {
      sftp_set_msg( out, SSH_FXP_READ );
      sftp_set_id( out, id );
      
      sftp_put_string( out, newstate.handlelen, newstate.handle );
      sftp_put_uint64( out, newstate.filepos ); /* Offset */
      sftp_put_uint32( out, SFTP_BLOCKSIZE ); /* Length */
      
      newstate.nextfun = sftp_get_mem_main;
    }
  else
    {
      /* We're done - close the file */

      sftp_set_msg( out, SSH_FXP_CLOSE );
      sftp_set_id( out, id );
      
      sftp_put_string( out, newstate.handlelen, newstate.handle );
      
      newstate.nextfun = sftp_handle_status;

      sftp_free_string( newstate.handle ); /* Release memory used by handle */

      newstate.handle = 0;                  /* Replace with a null string */
      newstate.handlelen = 0;  
    }

  return newstate;
}



/* Put a file from memory */

struct sftp_callback sftp_put_mem_init(
				      int op_id,
				      struct sftp_input *in, 
				      struct sftp_output *out,
				      UINT8 *name,
				      UINT32 namelen,
				      struct sftp_mem *mem,
				      UINT64 startat,
				      struct sftp_attrib a
				      )
{
  UINT32 id;
  UINT32 flags;
  UINT32 mask;

  struct sftp_callback state = sftp_null_state();

  id = sftp_unique_id();

  if( startat ) /* Offset given? */
    flags = SSH_FXF_CREAT | SSH_FXF_WRITE;
  else
    flags = SSH_FXF_CREAT | SSH_FXF_WRITE | SSH_FXF_TRUNC;

  mask = sftp_rumask( 0 );  /* Perform remote umasking */
  sftp_rumask( mask );

  a.permissions = a.permissions & ~mask;

  sftp_set_msg( out, SSH_FXP_OPEN );
  sftp_set_id( out, id );
  sftp_put_string( out, namelen, name );
  sftp_put_uint32( out, flags ); /* How to open */
  sftp_put_attrib( out, &a );

  state.filepos = startat;
  state.id = id;
  state.mem = *mem;
  state.nextfun = sftp_put_mem_step_one;
  state.op_id = op_id;
  state.last = SFTP_PUT_MEM_INIT;

  return state;
}


struct sftp_callback sftp_put_mem_step_one(
					   UINT8 msg,
					   UINT32 id,
					   struct sftp_input *in, 
					   struct sftp_output *out,
					   struct sftp_callback state
					)
{
  UINT32 datalen;
  UINT8* tmp;
  struct sftp_callback newstate = state;

  if( msg == SSH_FXP_STATUS ) /* Status? */
    return sftp_handle_status( msg, id, in, out, state );

/* Otherwise we shouldn't be here FIXME: Fail gracefully?*/

  assert( msg == SSH_FXP_HANDLE && id == state.id ); 

  newstate.handle = sftp_get_string( in, &newstate.handlelen ); /* Get handle */

  /* Now we send a read command */

  newstate.id = sftp_unique_id();

  sftp_set_msg( out, SSH_FXP_WRITE );
  sftp_set_id( out, newstate.id );

  sftp_put_string( out, newstate.handlelen, newstate.handle );
  sftp_put_uint64( out, newstate.filepos ); /* Offset */

  tmp = sftp_retrieve( &newstate.mem, SFTP_BLOCKSIZE, &datalen ); /* Get (if possible) SFTP_BLOCKSIZE bytes */
  sftp_put_string( out, datalen, tmp ); /* Write the data */

  sftp_free_string( tmp ); /* Free temporary string */

  newstate.nextfun = sftp_put_mem_main;
  newstate.last = SFTP_PUT_MEM_STEP_ONE;

  return newstate;
}

struct sftp_callback sftp_put_mem_main(
				       UINT8 msg,
				       UINT32 id,
				       struct sftp_input *in, 
				       struct sftp_output *out,
				       struct sftp_callback state
				       )
{
  int done = 0;

  UINT32 datalen;
  UINT8* tmp;  
  struct sftp_callback newstate=state;
 
  assert( msg == SSH_FXP_STATUS && id == state.id); 
  assert( sftp_get_uint32( in, &newstate.retval ) > 0 );

  newstate.id = sftp_unique_id();
  
  if( newstate.retval != SSH_FX_OK ) /* Write failed? */
    {

      newstate.nextfun = sftp_handle_status;
      newstate.last = SFTP_PUT_MEM_MAIN;

      newstate.bad_status = newstate.retval; /* Store status */
      newstate.last_bad = SFTP_PUT_MEM_MAIN;
  
      if( newstate.handle ) /* Any old handles around (we should have) */
	{       
	  sftp_set_msg( out, SSH_FXP_CLOSE ); /* Try to close */
	  sftp_set_id( out, newstate.id );
	  
	  sftp_put_string( out, newstate.handlelen, newstate.handle );
	  
	  sftp_free_string( newstate.handle );
	  newstate.handle = 0;
	  newstate.handlelen = 0;

	}
     
      return newstate;
    }


  tmp = sftp_retrieve( &newstate.mem, SFTP_BLOCKSIZE, &datalen ); /* Get data to write */

/*   printf("sftp_put_mem_main: Will write %d bytes at pos %d\n", datalen, newstate.filepos); */

  if( ! datalen  )                  /* Got nothing at all? */ 
    done = 1;                       /* Assume short read => EOF => we're done */ 

  /* Now we send a write command */
  
/*   printf("sftp_put_mem_main: Datalen is  %d, done is %d\n", datalen, done); */

  if( !done ) /* Not yet finished? */
    {
      sftp_set_msg( out, SSH_FXP_WRITE );
      sftp_set_id( out, newstate.id );
      
/*       printf("Writing %d bytes at %d \n", datalen, newstate.filepos ); */

      sftp_put_string( out, newstate.handlelen, newstate.handle );
      sftp_put_uint64( out, newstate.filepos ); /* Offset */
      sftp_put_string( out, datalen, tmp ); /* What to write */

      newstate.filepos += datalen;

      sftp_free_string( tmp ); /* Free temporary buffer */

      newstate.nextfun = sftp_put_mem_main;
    }
  else
    {
      /* We're done, just close the file and wrap it up */

      sftp_set_msg( out, SSH_FXP_CLOSE );
      sftp_set_id( out, newstate.id );
      
/*       printf("Closing handle %s of len %d\n", newstate.handle, newstate.handlelen ); */

      sftp_put_string( out, newstate.handlelen, newstate.handle );
      
      newstate.nextfun = sftp_handle_status;

      sftp_free_string( tmp )               /* Free temporary buffer */;
      sftp_free_string( newstate.handle ); /* Release memory used by handle */

      newstate.handle = 0;            /* Replace with a null string */
      newstate.handlelen = 0;
    }

  newstate.last = SFTP_PUT_MEM_STEP_ONE;
  return newstate;
}


/* End of put from memory */

/* Get to file - wrapper for the functions to memory */

struct sftp_callback sftp_get_file_init(
				      int op_id,
				      struct sftp_input *in, 
				      struct sftp_output *out,
				      UINT8 *name,
				      UINT32 namelen,
				      UINT8 *fname,
				      UINT32 fnamelen,
				      int cont
				      )
{
  int openmode;

  UINT64 startat = 0;
  struct sftp_callback state = sftp_null_state();
  struct sftp_mem mem;
  int ret, fd;
  int mask;

  /* FIXME: Should probably try to retain permissions from the other side */

  openmode = O_CREAT | O_RDWR;
  state.last = SFTP_GET_FILE_INIT;

  if( cont ) /* If continue mode, stat and continue at end of file */
    {
      int statret;
      struct stat st;
      
      statret = stat( fname, &st );
      
      if( !statret ) /* Returned 0 - file exists */
	startat = st.st_size;
    }
  else
    openmode |= O_TRUNC; /* Not continue? Restart from beginning  */

  mask = umask( 0 );
  umask( mask );

  ret = open( fname, openmode, 0777 & ~mask );
  
  if( ret == -1 ) /* Failed? */
    {
      state.localerr = ret;
      state.localerrno = errno;
      return state;
    }
  else
    fd = ret; /* Success */

#ifdef USING_CYGWIN
  setmode( fd, O_BINARY );
#endif

  if( startat ) /* Only seek if we're continuing */
    {
      ret = lseek( fd, startat, SEEK_SET ); 

      if( ret == -1 ) /* Failed? */
	{
	  state.localerr = ret;
	  state.localerrno = errno;
	  
	  return state;
	} 
    }

  mem = sftp_alloc_mem( 2 * SFTP_BLOCKSIZE );
  state = sftp_get_mem_init( op_id, in, out, name, namelen, &mem, startat );

  state.nextfun = sftp_get_file_step_one;
  state.fd = fd;
  state.last = SFTP_GET_FILE_INIT;
  return state;
}


struct sftp_callback sftp_get_file_step_one(
					    UINT8 msg,
					    UINT32 id,
					    struct sftp_input *in,
					    struct sftp_output *out,
					    struct sftp_callback state
					    )
{
  struct sftp_callback newstate = state;

  if( msg == SSH_FXP_STATUS ) /* Status? */
    return sftp_handle_status( msg, id, in, out, state );

  assert( msg == SSH_FXP_HANDLE && id == state.id ); 
  
  newstate.handle = sftp_get_string( 
				    in, 
				    &newstate.handlelen 
				    ); /* Get handle */



  /* Now we send a stat command */

  newstate.id = sftp_unique_id();

  sftp_set_msg( out, SSH_FXP_FSTAT );
  sftp_set_id( out, newstate.id );

  sftp_put_string( out, newstate.handlelen, newstate.handle );

    newstate.nextfun = sftp_get_file_step_two;
  newstate.last = SFTP_GET_FILE_STEP_ONE;
  
  return newstate;
}


struct sftp_callback sftp_get_file_step_two(
					    UINT8 msg,
					    UINT32 id,
					    struct sftp_input *in,
					    struct sftp_output *out,
					    struct sftp_callback state
					    )
{
  struct sftp_callback newstate = state;
  int remoteperms = 0700;
  int mask;
  int ret;

  if( msg == SSH_FXP_STATUS ) /* Status? */
    return sftp_handle_status( msg, id, in, out, state );

  newstate = sftp_handle_attrs( msg, id, in, out, state );

  if( newstate.attrib.flags &  SSH_FILEXFER_ATTR_PERMISSIONS )
    remoteperms = newstate.attrib.permissions;

  if( newstate.attrib.flags &  SSH_FILEXFER_ATTR_SIZE )
    newstate.filesize = newstate.attrib.size;

  
  mask = umask( 0 );
  umask( mask );

  ret = fchmod( newstate.fd, remoteperms & ~mask ); /* Note: may remove our write permissions */

  if( -1 == ret )
    {
      newstate.localerr = ret;
      newstate.localerrno = errno;
	  
      return newstate;
    }

  newstate.id = sftp_unique_id();

  sftp_set_msg( out, SSH_FXP_READ );
  sftp_set_id( out, newstate.id );

  sftp_put_string( out, newstate.handlelen, newstate.handle );
  sftp_put_uint64( out, newstate.filepos ); /* Offset */
  sftp_put_uint32( out, SFTP_BLOCKSIZE ); /* Length */

  newstate.nextfun = sftp_get_file_main;
  newstate.last = SFTP_GET_FILE_STEP_TWO;
  
  return newstate;
}


struct sftp_callback sftp_get_file_main(
					UINT8 msg,
					UINT32 id,
					struct sftp_input *in,
					struct sftp_output *out,
					struct sftp_callback state
					)
{
  int ret;
  struct sftp_callback newstate;
  int write_needed = 0;
  int i;

  state.mem.used = 0;

  newstate = sftp_get_mem_main( msg, id, in, out, state );

  /* Should we do a lseek here? Just to be sure? */

  newstate.last = SFTP_GET_FILE_MAIN;

  ret = lseek( 
	      newstate.fd,
	      newstate.filepos - newstate.mem.used,  /* filepos is the current position - 
						      * at the end of the block we'll write
						      */
	      SEEK_SET
	      );

  if( ret == -1 ) /* Failed? */
    {
      newstate.nextfun = 0; /* No next callback */
      newstate.id = 0;
      newstate.localerr = ret;
      newstate.localerrno = errno;
      return newstate;
    }


  for( i = 0; i < newstate.mem.used; i++ )   /* Go through the block */
    if( newstate.mem.at[i] )                 
      write_needed = 1;        /* If any byte is non-zero, we write it all */

  if( write_needed )
    {
      ret = write(                                /* Write what we got */
		  newstate.fd, 
		  newstate.mem.at, 
		  newstate.mem.used 
		  );
      
      if( ret == -1 ) /* Failed? */
	{
	  newstate.nextfun = 0; /* No next callback */
	  newstate.id = 0;
	  newstate.localerr = ret;
	  newstate.localerrno = errno;
	  return newstate;
	}
    }
  
  /* It seems to be done, so we close our file and free the memory block */

  if( newstate.nextfun == sftp_handle_status ) 
    {
      /* Just to be sure the file has grown, we (possibly re-) write the last byte of the file 
       * before closing it.
       */

      ret = lseek(                       /* Seek to EOF - 1 (or what should be it anyway) */
		  newstate.fd,
		  newstate.filepos - 1, 
		  SEEK_SET
	      );

      if( ret == -1 ) /* Failed? */
	{
	  newstate.nextfun = 0; /* No next callback */
	  newstate.id = 0;
	  newstate.localerr = ret;
	  newstate.localerrno = errno;
	  return newstate;
	}
      

      ret = write(                                /* Write what we got */
		  newstate.fd, 
		  newstate.mem.at + newstate.mem.used - 1, 
		  1 
		  );
      
      if( ret == -1 ) /* Failed? */
	{
	  newstate.nextfun = 0; /* No next callback */
	  newstate.id = 0;
	  newstate.localerr = ret;
	  newstate.localerrno = errno;
	  return newstate;
	}



      ret = close( newstate.fd );       /* Close file */

      if( ret == -1 ) /* Failed? */
	{
	  newstate.nextfun = 0; /* No next callback */
	  newstate.id = 0;
	  newstate.localerr = ret;
	  newstate.localerrno = errno;
	  return newstate;
	}
	
      sftp_free_mem( &newstate.mem );
      newstate.mem = sftp_null_mem();
    }
  else 
    if( newstate.nextfun ) /* Check so we didn't bail out */
      newstate.nextfun = sftp_get_file_main; /* Not yet done, see to that we interfere the next time */
  
  return newstate;
}


/* End of get to file */



/* Put from file - wrapper for the functions from memory */

struct sftp_callback sftp_put_file_init(
				      int op_id,
				      struct sftp_input *in, 
				      struct sftp_output *out,
				      UINT8 *name,
				      UINT32 namelen,
				      UINT8 *fname,
				      UINT32 fnamelen,
				      int cont
				      )
{


/*
 * Passing a startat of zero makes put_mem_init truncate the
 * destination file, which is not desired in continue-mode.
 *
 * The filepos is fixed after the stat
 */

  UINT64 startat = cont; 
  UINT64 filesize = 0;

  struct sftp_callback state = sftp_null_state();
  struct sftp_mem mem;
  struct stat st;
  struct sftp_attrib a;
  int ret;
  int fd;

  state.last = SFTP_PUT_FILE_INIT;

  ret = open( fname, O_RDONLY );
  
  if( ret == -1 ) /* Failed? */
    {
      state.localerr = ret;
      state.localerrno = errno;
      state.nextfun = 0;
      state.id = 0;

      return state;
    }
  else
    fd = ret; /* Success */

#ifdef USING_CYGWIN
  setmode( fd, O_BINARY );
#endif

  ret = fstat( fd, &st ); /* */

  if( ret == -1 )     /* We had an error while stating, send an empty attribute object instead */
                      /* (we'll still try to send the file) */
    sftp_clear_attrib( &a );
  else /* No error - get attrib from stat */
    {
      sftp_attrib_from_stat( &st, &a );
      filesize = st.st_size;  /* Fill in size */
    }

  /* FIXME: We should probably have calculated startat here */

  mem = sftp_alloc_mem( SFTP_BLOCKSIZE );
  state = sftp_put_mem_init( op_id, in, out, name, namelen, &mem, startat, a );

  state.fd = fd;
  state.filesize = filesize;

  if( cont )
    state.nextfun = sftp_put_file_do_fstat;
  else
    state.nextfun = sftp_put_file_step_one;

  return state;
}

struct sftp_callback sftp_put_file_do_fstat(
					    UINT8 msg,
					    UINT32 id,
					    struct sftp_input *in,
					    struct sftp_output *out,
					    struct sftp_callback state
					    )
{
  struct sftp_callback newstate = state;

  UINT8* handle;
  UINT32 handlelen;
    
  if( msg == SSH_FXP_STATUS ) /* Status? (open failed) */
    return sftp_handle_status( msg, id, in, out, state );

  /* Otherwise we shouldn't be here FIXME: Fail gracefully?*/

  assert( msg == SSH_FXP_HANDLE && id == state.id ); 

  handle = sftp_get_string( in, &handlelen ); /* Get handle */
  newstate = sftp_fstat_init( newstate.op_id, in, out, handle, handlelen );

  newstate.mem = state.mem; /* FIXME; should probably not be here */
  newstate.fd = state.fd;

  newstate.last = SFTP_PUT_FILE_DO_FSTAT;
  newstate.handle = handle;
  newstate.handlelen = handlelen;
  newstate.nextfun = sftp_put_file_handle_stat;

  return newstate;
}

struct sftp_callback sftp_put_file_handle_stat(
					       UINT8 msg,
					       UINT32 id,
					       struct sftp_input *in,
					       struct sftp_output *out,
					       struct sftp_callback state
					       )
{
  struct sftp_callback newstate;
  UINT8 tmp[ SFTP_BLOCKSIZE ];
  int ret;

  newstate = sftp_handle_attrs( msg, id, in, out, state );

  newstate.filepos = 0;
  
  if( newstate.attrib.flags & SSH_FILEXFER_ATTR_SIZE )
    newstate.filepos = newstate.attrib.size;
 
  newstate.last = SFTP_PUT_FILE_HANDLE_STAT;

  ret = lseek( newstate.fd, newstate.filepos, SEEK_SET );

  if( ret == -1 ) /* Failed? */
    {
      newstate.localerr = ret;
      newstate.localerrno = errno;
      newstate.id = 0;
      newstate.nextfun = 0;

      return newstate;
    }

  ret = read( newstate.fd, tmp, SFTP_BLOCKSIZE ); /* Hrrm? */

  if( ret == -1 ) /* Failed? */
    {
      newstate.localerr = ret;
      newstate.localerrno = errno;
      newstate.id = 0;
      newstate.nextfun = 0;

      return newstate;
    }

  newstate.id = sftp_unique_id();

  sftp_set_msg( out, SSH_FXP_WRITE );
  sftp_set_id( out, newstate.id );

  sftp_put_string( out, newstate.handlelen, newstate.handle );
  sftp_put_uint64( out, newstate.filepos ); /* Offset */
  sftp_put_string( out, ret, tmp );

  newstate.nextfun = sftp_put_file_main;
  newstate.filepos += ret;

  return newstate;
}



struct sftp_callback sftp_put_file_step_one(
					    UINT8 msg,
					    UINT32 id,
					    struct sftp_input *in,
					    struct sftp_output *out,
					    struct sftp_callback state
					    )
{
  int ret;
  UINT8 tmp[ SFTP_BLOCKSIZE ];

  struct sftp_callback newstate = state;

  newstate.last = SFTP_PUT_FILE_STEP_ONE;

  /* Not much to do here, we just alter the next callback */
  ret = lseek( newstate.fd, newstate.filepos, SEEK_SET );

  if( ret == -1 ) /* Failed? */
    {
      newstate.localerr = ret;
      newstate.localerrno = errno;
      newstate.id = 0;
      newstate.nextfun = 0;

      return newstate;
    }

  ret = read( newstate.fd, tmp, SFTP_BLOCKSIZE );

  if( ret == -1 ) /* Failed? */
    {
      newstate.localerr = ret;
      newstate.localerrno = errno;
      newstate.id = 0;
      newstate.nextfun = 0;

      return newstate;
    }
  {
    sftp_store( &newstate.mem, tmp, ret );
    sftp_toggle_mem( &newstate.mem );
  }

  newstate = sftp_put_mem_step_one( msg, id, in, out, newstate );

  newstate.last = SFTP_PUT_FILE_STEP_ONE; 

  newstate.nextfun = sftp_put_file_main; /* FIXME: Check for bailing out */
  
  return newstate;
}


struct sftp_callback sftp_put_file_main(
					UINT8 msg,
					UINT32 id,
					struct sftp_input *in,
					struct sftp_output *out,
					struct sftp_callback state
					)
{
  UINT8 tmp[ SFTP_BLOCKSIZE ];
  int ret;
  struct sftp_callback newstate = state;

  newstate.last = SFTP_PUT_FILE_MAIN;

  ret = lseek( newstate.fd, newstate.filepos, SEEK_SET );

  if( ret == -1 ) /* Failed? */
    {
      newstate.localerr = ret;
      newstate.localerrno = errno;
      newstate.id = 0;
      newstate.nextfun = 0;

      return newstate;
    }

  ret = read( newstate.fd, tmp, SFTP_BLOCKSIZE );

  if( ret == -1 ) /* Failed? */
    {
      newstate.localerr = ret;
      newstate.localerrno = errno;
      newstate.id = 0;
      newstate.nextfun = 0;

      return newstate;
    }
  else
  {
/*     printf("Storing %d bytes from filepos %d\n", ret, newstate.filepos ); */

    sftp_toggle_mem( &newstate.mem ); /* Clear buffer by toggling two times */
    sftp_toggle_mem( &newstate.mem );

/*     printf("sftp_put_mem_main: mem has size %d and used %d \n", newstate.mem.size, newstate.mem.used ); */
    sftp_store( &newstate.mem, tmp, ret );
/*     printf("sftp_put_mem_main: mem has size %d and used %d \n", newstate.mem.size, newstate.mem.used ); */
    sftp_toggle_mem( &newstate.mem );
/*     printf("sftp_put_mem_main: mem has size %d and used %d \n", newstate.mem.size, newstate.mem.used ); */
  }


/*   printf("Read %d bytes to be written at %d \n", ret, newstate.filepos); */

  newstate = sftp_put_mem_main( msg, id, in, out, newstate );

  newstate.last = SFTP_PUT_FILE_MAIN;

  if( newstate.nextfun == sftp_handle_status ) 
    /* It seems to be done, so we close our file and free the memory block */
    {
      close( newstate.fd );
      sftp_free_mem( &newstate.mem );
      newstate.mem = sftp_null_mem();
    }
  else 
    if( newstate.nextfun ) /* Check so we didn't bail out */
      /* Not yet done, see to that we interfere the next time */
      newstate.nextfun = sftp_put_file_main; 
  
  return newstate;
}


/* End of put from file */


/* Do a ls, save the results in the result-string */

struct sftp_callback sftp_ls_init(
				      int op_id,
				      struct sftp_input *in, 
				      struct sftp_output *out,
				      UINT8 *dir,
				      UINT32 dirlen				
				      )
{
  struct sftp_callback state = sftp_null_state();

  state.id = sftp_unique_id();

  sftp_set_msg( out, SSH_FXP_OPENDIR );
  sftp_set_id( out, state.id );

  sftp_put_string( out, dirlen, dir );

  state.nextfun = sftp_ls_step_one;
  state.op_id = op_id;

  return state;
}

struct sftp_callback sftp_ls_step_one(
				      UINT8 msg,
				      UINT32 id,
				      struct sftp_input *in, 
				      struct sftp_output *out,
				      struct sftp_callback state
				      )
{
  struct sftp_callback newstate=state;
  
  if( msg == SSH_FXP_STATUS ) /* Status? */
    return sftp_handle_status( msg, id, in, out, state );
  
/* Otherwise we shouldn't be here FIXME: Fail gracefully?*/

  assert( msg == SSH_FXP_HANDLE && id == state.id );

  newstate.handle = sftp_get_string( in, &newstate.handlelen ); /* Get handle */

  /* Now we send a readdir command */

  newstate.id = sftp_unique_id();

  sftp_set_msg( out, SSH_FXP_READDIR );
  sftp_set_id( out, newstate.id );

  sftp_put_string( out, newstate.handlelen, newstate.handle );

  newstate.nextfun = sftp_ls_main;

  return newstate;
}

struct sftp_callback sftp_ls_main(				  
				  UINT8 msg,
				  UINT32 id,
				  struct sftp_input *in, 
				  struct sftp_output *out,
				  struct sftp_callback state
				  )
{
   UINT32 count;
 
   int i;
   UINT8 *fname;
   UINT8 *longname;
   
   UINT32 fnamelen;
   UINT32 longnamelen;
  
  struct sftp_attrib a;

  struct sftp_callback newstate = state;

  if( msg == SSH_FXP_STATUS ) /* Status? */
    return sftp_handle_status( msg, id, in, out, state );

/* Otherwise we shouldn't be here FIXME: Fail gracefully?*/

  assert( msg == SSH_FXP_NAME && id == state.id ); 

  assert( sftp_get_uint32( in, &count ) > 0 ); /* Get count */

  for( i=0; i < count; i++ ) /* Do count times */
    {
      UINT32 attriblen = sizeof( struct sftp_attrib );

      /* Read filename, longname and attrib */

      fname = sftp_get_string( in, &fnamelen ); 
      longname = sftp_get_string( in, &longnamelen );

      sftp_clear_attrib( &a );

      assert( sftp_get_attrib( in, &a ) > 0 );

      /* Write string length before. Explicit casts */

      sftp_store( &newstate.mem, &fnamelen, sizeof( UINT32 ) );
      sftp_store( &newstate.mem, fname, fnamelen );

      /* Write string length before */
      sftp_store( &newstate.mem, &longnamelen, sizeof( UINT32 ) );
      sftp_store( &newstate.mem, longname, longnamelen );

      /* Write length before */
      sftp_store( &newstate.mem, &attriblen, sizeof( UINT32 ) );
      sftp_store( &newstate.mem, &a, attriblen );

      sftp_free_string( fname );
      sftp_free_string( longname );
    }
  
  /* Now we send a new readdir command */

  newstate.id = sftp_unique_id();

  sftp_set_msg( out, SSH_FXP_READDIR );
  sftp_set_id( out, newstate.id );

  sftp_put_string( out, newstate.handlelen, newstate.handle );

  newstate.nextfun = sftp_ls_main;
  newstate.last = SFTP_LS_MAIN;

  return newstate;
}

/* End ls */


/* More general handlers */

struct sftp_callback sftp_handle_status(
					UINT8 msg,
					UINT32 id,
					struct sftp_input *in, 
					struct sftp_output *out,
					struct sftp_callback state
					)
{
    struct sftp_callback newstate = state;  
    
    assert( msg == SSH_FXP_STATUS && id == state.id );    
    assert( sftp_get_uint32( in, &newstate.retval ) > 0 );
    
    newstate.id = 0;
    newstate.nextfun = 0;
    newstate.last = SFTP_HANDLE_STATUS;
    
    if( state.handle ) /* Any old handles around */
      {
	/* We send a SSH_FXP_CLOSE (and ignore the answer) */
	id = sftp_unique_id(); 
	  
	sftp_set_msg( out, SSH_FXP_CLOSE );
	sftp_set_id( out, id );
	
	sftp_put_string( out, state.handlelen, state.handle );
	
	sftp_free_string( state.handle );
	
	newstate.handle = 0;
	newstate.handlelen = 0;
      }
    
    return newstate;
}



struct sftp_callback sftp_handle_attrs(
				       UINT8 msg,
				       UINT32 id,
				       struct sftp_input *in, 
				       struct sftp_output *out,
				       struct sftp_callback state
				       )
{
  struct sftp_callback newstate = state;
  struct sftp_attrib a;

  if( msg == SSH_FXP_STATUS ) /* Not attrib but status? */
    return sftp_handle_status( msg, id, in, out, state );

/* Otherwise we shouldn't be here FIXME: Fail gracefully?*/

  assert( msg == SSH_FXP_ATTRS && id == state.id );

  assert( sftp_get_attrib( in, &a ) > 0 );

  newstate.attrib = a;
  newstate.last = SFTP_HANDLE_ATTRS;

/*    printf( "Flags: %d, perms %d\n", a.flags, a.permissions ); */

  newstate.id = 0;
  newstate.nextfun = 0;

  return newstate;
}


struct sftp_callback sftp_handle_name(
				      UINT8 msg,
				      UINT32 id,
				      struct sftp_input *in, 
				      struct sftp_output *out,
				      struct sftp_callback state
				      )
{
  struct sftp_callback newstate = state;
  UINT32 count;
  int i;

  if( msg == SSH_FXP_STATUS ) /* Not attrib but status? */
    return sftp_handle_status( msg, id, in, out, state );

/* Otherwise we shouldn't be here FIXME: Fail gracefully?*/

  assert( msg == SSH_FXP_NAME && id == state.id); 

  assert( sftp_get_uint32( in, &count ) > 0 );

  for( i=0; i<count; i++ ) /* Do count times */
    {
      UINT8* fname;
      UINT8* longname;
      struct sftp_attrib a;
      UINT32 fnamelen;
      UINT32 longnamelen;

      UINT32 attriblen = sizeof( struct sftp_attrib );

      fname = sftp_get_string( in, &fnamelen ); /* Read filename, longname and attrib */
      longname = sftp_get_string( in, &longnamelen );

      assert( sftp_get_attrib( in, &a ) > 0 );
      /* Write string length before */
      sftp_store( &newstate.mem, &fnamelen, sizeof( UINT32 ) );
      sftp_store( &newstate.mem, fname, fnamelen );

      /* Write length before */

      sftp_store( &newstate.mem, &longnamelen, sizeof( UINT32 ) );
      sftp_store( &newstate.mem, longname, longnamelen );

      /* Write length before */

      sftp_store( &newstate.mem, &attriblen, sizeof( UINT32 ) );
      sftp_store( &newstate.mem, &a, attriblen );

      sftp_free_string( fname );
      sftp_free_string( longname );
    }

  newstate.last = SFTP_HANDLE_NAME;

  newstate.id = 0;
  newstate.nextfun = 0;

  return newstate;
}

/* End general */

