/*
 * @(#) $Id$
 *
 * sftp_bind.h 
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

#ifndef LSFTP_SFTP_BIND_H
#define LSFTP_SFTP_BIND_H


#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define LSH_CLIENT "lsh"
#define LSH_GATEWAY "lshg"
#define LSH_PROGENV "LSFTP_RSH"
#define BEFORE_ARGS_ENV "LSFTP_BEFORE_ARGS"
#define AFTER_ARGS_ENV "LSFTP_AFTER_ARGS"


#ifndef TRANSPORT_BEFORE_OPTS
#define DEFAULT_BEFORE_ARGS "--subsystem=sftp"
#else
#define DEFAULT_BEFORE_ARGS TRANSPORT_BEFORE_OPTS
#endif /* TRANSPORT_BEFORE_OPTS */


#ifndef TRANSPORT_AFTER_OPTS
#define DEFAULT_AFTER_ARGS ""
#else
#define DEFAULT_AFTER_ARGS TRANSPORT_AFTER_OPTS
#endif /* TRANSPORT_AFTER_OPTS */


#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <limits.h>
#include <signal.h>
#include <string.h>

#include "misc_fun.h"
#include "sftp_c.h"
#include "buffer.h"
#include "str_utils.h"
#include "dc.h"

#define KILL_WAIT 5

struct lsftp_callback {
  int op_id;
  int (*nextfun)();
  struct sftp_attrib* a;
  struct stat* st;
  char* local;
  char* remote;
  char* command;
  void* memory;

  int opt1;
  int opt2;
  int opt3;
};

int lsftp_open_connection(char** argv, int argc); /* Open a new outgoing connection */
int lsftp_close_connection();                     /* Close an existing connection */

int lsftp_want_to_write();                        /* Returns whatever we want to write or not */

int lsftp_connected();    /* Are we connected? */

int lsftp_handshake();    /* Handshake with remote */
int lsftp_sftp_init();    /* Init sftp things */

int lsftp_callback();

int lsftp_cb_list();
int lsftp_cb_status( int jobid );


char* lsftp_pwd();

int lsftp_do_ls( char* dir, char* command, int longlist, int all );
int lsftp_handle_ls( struct sftp_callback s, struct lsftp_callback l );

int lsftp_internal_ls( char* dir, char* command, char*** dirinfop );
int lsftp_handle_internal_ls( 
			     struct sftp_callback s,
			     struct lsftp_callback l 
			     );

int lsftp_do_get( char* local, char* remote, char* command, int cont );
int lsftp_handle_get( struct sftp_callback s, struct lsftp_callback l );

int lsftp_do_put( char* local, char* remote, char* command, int cont );
int lsftp_handle_put( struct sftp_callback s, struct lsftp_callback l );

int lsftp_do_cd( char* dir );

int lsftp_do_chmod( char* file, mode_t mode, char* command );
int lsftp_do_chown( char* file, UINT32 uid, UINT32 gid, char* command );
int lsftp_handle_chall( struct sftp_callback s, struct lsftp_callback l );

int lsftp_do_stat( char* file, struct stat* st );
int lsftp_handle_stat( struct sftp_callback s, struct lsftp_callback l );

int lsftp_do_realpath( char* file, char** destptr );
int lsftp_handle_realpath( struct sftp_callback s, struct lsftp_callback l );

int lsftp_do_mv( char* src, char* dst, char* command );
int lsftp_do_rm( char* path, char* command );

int lsftp_do_ln( char* link, char* target, char* command );

int lsftp_do_mkdir( char* dir, int permissions, char* command );
int lsftp_do_rmdir( char* dir, char* command );
int lsftp_handle_alldir( struct sftp_callback s, struct lsftp_callback l );


int lsftp_install_lsftp_cb( int (*nextfun)() );
int lsftp_install_sftp_cb( struct sftp_callback s );


int lsftp_sftp_cb_init( int new_sftp_callbacks );
void lsftp_sftp_cb_uninit();
int lsftp_compact_sftp_cbs();


int lsftp_lsftp_cb_init( int new_lsftp_callbacks );
void lsftp_lsftp_cb_uninit();
int lsftp_compact_lsftp_cbs();

int lsftp_await_command( int id );

char* lsftp_qualify_path( char* path );
char* lsftp_unqualify_path( char* path );

int lsftp_active_cbs();

void lsftp_perror( char* msg, int err );

void lsftp_report_error( struct sftp_callback, struct lsftp_callback l );

int lsftp_fd_read_net();
int lsftp_fd_write_net();


char* status_codes_text[9];

#endif /* LSFTP_SFTP_BIND_H */


