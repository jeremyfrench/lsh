/* tokenize_config.h
 *
 * Tokenizing of configuration files. */

/* lsh, an implementation of the ssh protocol
 *
 * Copyright (C) 2002, 2005 Niels Möller
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

#ifndef LSH_TOKENIZE_CONFIG_H_INCLUDED
#define LSH_TOKENIZE_CONFIG_H_INCLUDED

#include "parse.h"

enum config_token_type
{
  TOK_EOF,
  TOK_BEGIN_GROUP,
  TOK_END_GROUP,
  TOK_STRING,
  TOK_ERROR
};

struct config_tokenizer
{
  struct simple_buffer buffer;

  /* For error messages */
  const char *file;
  unsigned lineno;
  
  enum config_token_type type;
  unsigned token_length;
  const uint8_t *token;
};

void
config_tokenizer_init(struct config_tokenizer *self,
		      const char *file,
		      unsigned length, const uint8_t *data);

enum config_token_type
config_tokenizer_next(struct config_tokenizer *self);

void
config_tokenizer_error(struct config_tokenizer *self, const char *msg);

int
config_tokenizer_looking_at(struct config_tokenizer *self, const char *word);

struct lsh_string *
config_tokenizer_get_string(struct config_tokenizer *self);

int
config_tokenizer_skip_token(struct config_tokenizer *self, enum config_token_type type);

#endif /* LSH_TOKENIZE_CONFIG_H_INCLUDED */
