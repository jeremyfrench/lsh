/*
 * @(#) $Id$
 *
 * gnu_stuff.c
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

#include "gnu_stuff.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void lsftp_welcome()
{
  printf( "Welcome to %s %s by Pontus Sköld, Niels Möller and various.\n", PACKAGE, VERSION );
  printf( "This program is free software, for more information\n" );
  printf( "please see the file COPYING or type about, you may\n" );
  printf( "also use help or ? to get help.\n\n");
  printf( "Trying to connect, please stand by.\n");

}

void help_option()
{
  printf("Usage:\n");
  exit(0); /* Exit successfully */
}

void version_option()
{
  printf("%s %s\n", PACKAGE, VERSION);
  printf("Copyright (C) Pontus Sköld, Niels Möller and various contributors\n\n");

  printf("This program is free software, you may distribute it under the\n");
  printf("terms of the GNU Genereal Public License. \n\n");
  
  printf("This program is distributed in the hope that it will be useful,\n");
  printf("but WITHOUT ANY WARRANTY; without even the implied warranty of\n");
  printf("MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU\n");
  printf("General Public License for more details.\n");

  exit(0); /* Exit successfully */
}

void do_gnu_stuff( const char** argv )
{
  const char** current = argv;

  while( *current ) /* More arguments? */
    {
      if( !strcmp( *current, "--version" ) )
	version_option();

      if( !strcmp( *current, "--help" ) )
	help_option();

      current++;
    }
}


