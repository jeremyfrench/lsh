/* spki-check-signature.c */

#include "certificate.h"
#include "parse.h"

#include <stdarg.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void
die(const char *format, ...)
{
  va_list args;
  va_start(args, format);
  vfprintf(stderr, format, args);
  va_end(args);
  exit(EXIT_FAILURE);
}

static void
usage(void)
{
  fprintf(stderr, "spki-check-signature SIGNATURE\n");
  exit(EXIT_FAILURE);
}

int
main(int argc, char **argv)
{
  struct spki_acl_db db;
  struct sexp_iterator sexp;
  struct spki_iterator i;

  struct spki_hash_value hash;
  struct spki_principal *principal;
  
  if (argc != 2)
    usage();

  spki_acl_init(&db);

  if (sexp_transport_iterator_first(&sexp, strlen(argv[1]), argv[1])
      && spki_iterator_first_sexp(&i, &sexp)
      && spki_check_type(&i, SPKI_TYPE_SIGNATURE)
      && spki_parse_hash(&i, &hash)
      && spki_parse_principal(&db, &i, &principal))
  {
    if (!spki_verify(NULL, &hash, principal, &i))
      die("Bad signature\n");
    if (!spki_parse_end(&i))
      die("Invalid signature expression\n");
  }
  else
    die("Invalid signature expression\n");

  spki_acl_clear(&db);
  return EXIT_SUCCESS;
}
