/*
 * @(#) $Id$
 *
 * rl.h
 */

/* lsftp, an implementation of the sftp protocol
 *
 * Copyright (C) 2001, Pontus Sköld
 * Portions of this code originately from the readline manual
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

#ifndef LSFTP_RL_H
#define LSFTP_RL_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "commands.h"
#include "str_utils.h"
#include "misc_fun.h"


/* Ehrm */
#define REMOTEMAXLEN 256             






#ifdef HAVE_READLINE_READLINE_H

/* Use readline */
#include <readline/readline.h>

#endif /* HAVE_READLINE_READLINE_H */





#ifdef  HAVE_READLINE_HISTORY_H

#include <readline/history.h>

#endif /* HAVE_READLINE_HISTORY_H */

#define LSFTP_HISTNAME_VAR "LSFTP_HISTORY_FILE"
#define LSFTP_HIST_FILENAME "/.lsftp"








/* These are "public" functions */

void lsftp_rl_init_get_line(char* prompt);
char* lsftp_rl_get_line();
void lsftp_rl_check_input();
void lsftp_rl_unuse_line(char* line);
void lsftp_rl_init();
void lsftp_rl_exit();
char* lsftp_rl_history_fname();

/* "Private" functions below */

void lsftp_rl_lhandler(char* line);

char** lsftp_rl_completion(char* text, int start, int end);
char* lsftp_rl_command_generator (char* text, int state);
char* lsftp_rl_remotefile_generator (char* text, int state);
char* lsftp_rl_no_generator (char* text, int state);

int char_quoted( char* text, int index);

extern int interactive;

#endif /* LSFTP_RL_H */
