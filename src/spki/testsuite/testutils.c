#include "testutils.h"

void
read_acl(struct spki_acl_db *db,
	 unsigned length, const uint8_t *data)
{
  struct spki_iterator i;

  ASSERT(spki_iterator_first(&i, length, data) == SPKI_TYPE_ACL);
  ASSERT(spki_acl_parse(db, &i));
}

int
main(int argc, char **argv)
{
  test_main();

  return EXIT_SUCCESS;
}
