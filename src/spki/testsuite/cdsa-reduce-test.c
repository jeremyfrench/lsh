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
  if (!f)
    return NULL;
  
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

/* Destructively filters the list */
static struct spki_5_tuple *
filter_by_tag(struct spki_acl_db *db,
	      struct spki_5_tuple *acl,
	      struct spki_iterator *iterator)
{
  struct spki_tag *tag;
  struct spki_5_tuple **pp;
  struct spki_5_tuple *p;
  
  ASSERT(spki_parse_tag(db, iterator, &tag));

  for (pp = &acl; (p = *pp); )
    {
      struct spki_tag *intersection
	= spki_tag_intersect(db->realloc_ctx, db->realloc,
			     tag, p->tag);

      if (intersection)
	{
	  spki_tag_release(db->realloc_ctx, db->realloc, p->tag);
	  p->tag = intersection;

	  pp = &p->next;
	}
      else
	{
	  /* Unlink element */
	  *pp = p->next;
	  p->next = NULL;
	  spki_5_tuple_free_chain(db, p);
	}
    }
  return acl;
}

static struct spki_5_tuple *
filter_by_subject(struct spki_acl_db *db,
		  struct spki_5_tuple *acl,
		  struct spki_iterator *iterator)
{
  struct spki_principal *subject;
  struct spki_5_tuple **pp;
  struct spki_5_tuple *p;

  ASSERT(spki_parse_subject(db, iterator, &subject));

  for (pp = &acl; (p = *pp); )
    {
      if (subject == spki_principal_normalize(p->subject))
	pp = &p->next;
      
      else
	{
	  /* Unlink element */
	  *pp = p->next;
	  p->next = NULL;
	  spki_5_tuple_free_chain(db, p);
	}
    }
  return acl;
}

static struct spki_5_tuple *
filter_by_date(struct spki_acl_db *db,
	       struct spki_5_tuple *acl,
	       struct spki_iterator *iterator)
{
  struct spki_date not_before;
  struct spki_date not_after;
  struct spki_5_tuple **pp;
  struct spki_5_tuple *p;

  if (iterator->sexp.type == SEXP_ATOM)
    {
      /* We have only a single date */
      ASSERT(spki_parse_date(iterator, &not_before));
      not_after = not_before;
    }
  else
    {
      struct spki_5_tuple tuple;
      ASSERT(spki_parse_valid(iterator, &tuple));
      not_before = tuple.not_before;
      not_after = tuple.not_after;
    }
      
      
  for (pp = &acl; (p = *pp); )
    {
      if (SPKI_DATE_CMP(p->not_before, not_before) < 0)
	p->not_before = not_before;

      if (SPKI_DATE_CMP(p->not_after, not_after) > 0)
	p->not_after = not_after;
      
      if (SPKI_DATE_CMP(p->not_before, p->not_after) <= 0)
	pp = &p->next;
	  
      else
	{
	  /* Unlink element */
	  *pp = p->next;
	  p->next = NULL;
	  spki_5_tuple_free_chain(db, p);
	}
    }
  return acl;
}

void
test_main(void)
{
  unsigned i;
  const char *srcdir = getenv("srcdir");
  
  for (i = 1; i <= 91; i++)
    {
      struct spki_acl_db db;      
      struct spki_5_tuple *result;

      if (i == 13 /* This test uses an acl with empty tag. Skip it */
	  || i == 18 /* This tests uses a validity filter with dates missing
		      * seconds. */
	  || i == 19
	  || i == 20 /* This tests uses a validity filter with microseconds. */
	  )
	continue;

      if (i == 27)
	/* Rest of the test cases use features that haven't been
	 * implemented yet. */
	break;
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

	if (iterator.type == SPKI_TYPE_SEQUENCE)
	  {
	    struct spki_5_tuple *sequence
	      = spki_process_sequence_no_signatures(&db, &iterator);
	    ASSERT(sequence);
	    result = spki_5_tuple_reduce(&db, sequence);

	    spki_5_tuple_free_chain(&db, sequence);
	  }
	else
	  {
	    /* Just use the ACL:s */
	    result = db.first_acl;
	    db.first_acl = NULL;
	  }

	if (iterator.type == SPKI_TYPE_TAG)
	  result = filter_by_tag(&db, result, &iterator);

	ASSERT(result);

	if (iterator.type == SPKI_TYPE_SUBJECT)
	  result = filter_by_subject(&db, result, &iterator);

	ASSERT(result);

	if (iterator.type == SPKI_TYPE_VALID)
	  result = filter_by_date(&db, result, &iterator);
	
	/* Done with the input file. */
	free(data);
      }

#if 0
      /* At least case 21 results in an empty acl list */
      ASSERT(result);
#endif

      /* The result should be an acl. */
      if (result)
	ASSERT(!result->issuer);
      
      spki_5_tuple_free_chain(&db, result);

      spki_acl_clear(&db);
    }
}
