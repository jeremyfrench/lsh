#include "testutils.h"

/* Handle testcases snarfed from CDSA. */

#include <assert.h>
#include <stdio.h>

static char *
read_file(const char *srcdir,
	  const char *prefix, unsigned i, const char *suffix,
	  unsigned *length)
{
  unsigned srcdir_length = srcdir ? strlen(srcdir) : 0;
  char *fname = alloca(srcdir_length + strlen(prefix) + strlen(suffix) + 100);
  FILE *f;
  unsigned done = 0;
  unsigned alloc = 0;
  char *buffer = NULL;
  
  if (srcdir)
    sprintf(fname, "%s/%s%d%s", srcdir, prefix, i, suffix);
  else
    sprintf(fname, "%s%d%s", prefix, i, suffix);

  f = fopen(fname, "rb");

  for (;;)
    {
      assert(alloc == done);
      
      alloc = alloc * 2 + 100;
      buffer = realloc(buffer, alloc);
      if (!buffer)
	{
	  fprintf(stderr, "Virtual memory exhausted.\n");
	  abort();
	}

      done += fread(buffer + done, 1, alloc - done, f);

      if (done < alloc)
	{
	  if (ferror(f))
	    {
	      fprintf(stderr, "Read error on file `%s'\n", fname);
	      exit(EXIT_FAILURE);
	    }
	  else if (feof(f))
	    {
	      *length = done;
	      return buffer;
	    }
	  abort();
	}
    }
}

void
test_main(void)
{
  unsigned i;
  const char *srcdir = getenv("srcdir");
  
  for (i = 1; i <= 91; i++)
    {
      struct spki_acl_db db;      
      struct spki_5_tuple *sequence;
      struct spki_5_tuple *result;

      {
	struct sexp_iterator sexp;
	struct spki_iterator iterator;
	
	unsigned length;
	uint8_t *data;

	fprintf(stderr, "i: %d\n", i);
	
	data = read_file(srcdir, "cdsa-cases/", i, ".in",
			 &length);
	
	ASSERT(sexp_iterator_first(&sexp, length, data));
	ASSERT(sexp_iterator_check_type(&sexp, "red-test"));

	ASSERT(spki_iterator_first_sexp(&iterator, &sexp));
	       
	/* A "red-test" contains an acl and a sequence */
	spki_acl_init(&db);
	ASSERT(spki_acl_parse(&db, &iterator));
	
	sequence = spki_process_sequence_no_signatures(&db, &iterator);
	ASSERT(sequence);
	
	/* Done with the input file. */
	free(data);
      }
      result = spki_5_tuple_reduce(&db, sequence);
      ASSERT(result);

      /* The result should be an acl. */
      assert(!result->issuer);
      
      spki_5_tuple_free_chain(&db, sequence);
      spki_5_tuple_free_chain(&db, result);

      spki_acl_clear(&db);
    }
}
