/* lsh-decode-key.c
 *
 * Decode ssh2 keys.
 *
 * $Id$
 */

#include "digits.h"
#include "dsa.h"
#include "format.h"
#include "io.h"
#include "lsh_argp.h"
#include "publickey_crypto.h"
#include "read_file.h"
#include "rsa.h"
#include "sexp_commands.h"
#include "spki.h"
#include "version.h"
#include "werror.h"
#include "xalloc.h"

#include <string.h>

#include <unistd.h>
#include <fcntl.h>

#include "lsh-decode-key.c.x"

/* Option parsing */

const char *argp_program_version
= "lsh-decode-key-" VERSION;

const char *argp_program_bug_address = BUG_ADDRESS;

/* GABA:
   (class
     (name lsh_decode_key_options)
     (vars
       ; Output filename
       (file string)

       ; Assume input is base64
       (base64 . int)
       (style . sexp_argp_state)))
*/

static struct lsh_decode_key_options *
make_lsh_decode_key_options(void)
{
  NEW(lsh_decode_key_options, self);
  self->file = NULL;
  self->base64 = 0;
  self->style = -1;

  return self;
}

static const struct argp_option
main_options[] =
{
  /* Name, key, arg-name, flags, doc, group */
  { "output-file", 'o', "Filename", 0, "Default is stdout", 0 },
  { "base64", 'b', NULL, 0, "Input is base64 encoded", 0 },
  { NULL, 0, NULL, 0, NULL, 0 }
};

static const struct argp_child
main_argp_children[] =
{
  { &sexp_output_argp, 0, NULL, 0 },
  { &werror_argp, 0, "", 0 },
  { NULL, 0, NULL, 0}
};

static error_t
main_argp_parser(int key, char *arg, struct argp_state *state)
{
  CAST(lsh_decode_key_options, self, state->input);

  switch(key)
    {
    default:
      return ARGP_ERR_UNKNOWN;

    case ARGP_KEY_INIT:
      state->child_inputs[0] = &self->style;
      break;

    case ARGP_KEY_END:
      if (self->style < 0)
	self->style = self->file ? SEXP_CANONICAL : SEXP_TRANSPORT;
      break;
      
    case 'b':
      self->base64 = 1;
      break;
      
    case 'o':
      self->file = ssh_format("%lz", arg);
      break;
    }
  return 0;
}

static const struct argp
main_argp =
{ main_options, main_argp_parser, 
  NULL,
  ( "Converts a raw OpenSSH/ssh2 public key to sexp-format.\v"
    "Usually invoked by the ssh-conv script."),
  main_argp_children,
  NULL, NULL
};


static struct sexp *
lsh_decode_key(struct lsh_string *contents)
{
  struct simple_buffer buffer;
  int type;

  simple_buffer_init(&buffer, contents->length, contents->data);

  if (!parse_atom(&buffer, &type))
    {
      werror("Invalid (binary) input data.\n");
      return NULL;
    }

  switch (type)
    {
    case ATOM_SSH_DSS:
      {
        struct verifier *v;
        
        werror("lsh-decode-key: Reading key of type ssh-dss...\n");

        v = parse_ssh_dss_public(&buffer);
        
        if (!v)
          {
            werror("Invalid dsa key.\n");
            return NULL;
          }
        else
          return spki_make_public_key(v);
      }
      
    case ATOM_SSH_RSA:
      {
          struct verifier *v;
          
          werror("lsh-decode-key: Reading key of type ssh-rsa...\n");

          v = parse_ssh_rsa_public(&buffer);

          if (!v)
            {
              werror("Invalid rsa key.\n");
              return NULL;
            }
          else
            return spki_make_public_key(v);
      }      
    default:
      werror("Unknown key type.");
      return NULL;
    }
}


int main(int argc, char **argv)
{
  struct lsh_decode_key_options *options = make_lsh_decode_key_options();
  const struct exception *e;
  struct lsh_string *input;
  struct lsh_string *output;
  struct sexp *expr;
  
  int out = STDOUT_FILENO;
  
  argp_parse(&main_argp, argc, argv, 0, NULL, options);

  if (options->file)
    {
      out = open(lsh_get_cstring(options->file),
                 O_WRONLY | O_CREAT, 0666);
      if (out < 0)
        {
          werror("Failed to open file `%S' for writing: %z\n",
                 options->file, STRERROR(errno));
          return EXIT_FAILURE;
        }
    }

  input = io_read_file_raw(STDIN_FILENO, 3000);
  if (!input)
    {
      werror("Failed to read stdin: %z\n",
             STRERROR(errno));
      return EXIT_FAILURE;
    }

  if (options->base64)
    {
      struct lsh_string *old = input;
      input = decode_base64(input->length, input->data);
      lsh_string_free(old);

      if (!input)
        {
          werror("Invalid base64 encoding.\n");
          return EXIT_FAILURE;
        }
    }

  expr = lsh_decode_key(input);

  lsh_string_free(input);
  
  if (!expr)
    return EXIT_FAILURE;

  output = sexp_format(expr, options->style, 0);

  e = write_raw(out, output->length, output->data);
  lsh_string_free(output);
  
  if (e)
    {
      werror("Write failed: %z\n",
             e->msg);
      return EXIT_FAILURE;
    }
  
  gc_final();
  
  return EXIT_SUCCESS;
}
