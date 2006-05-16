#include "testutils.h"

#include "server_config.h"

struct values
{
  struct lsh_string *foo;
  struct lsh_string *bar;
};

enum
  {
    OPT_FOO = 1,
    OPT_BAR = 2,
  };

static const struct config_option
options[] = {
  { OPT_FOO, "foo", CONFIG_TYPE_STRING, "Set foo", "xx" },
  { OPT_BAR, "bar", CONFIG_TYPE_STRING, "Set bar", "yy" },
  { 0, NULL, CONFIG_TYPE_NONE, NULL, NULL }  
};

static int
handler(int key, uint32_t value, const uint8_t *data,
	struct config_parser_state *state)
{
  struct values *self = (struct values *) state->input;
  
  switch (key)
    {
    case CONFIG_PARSE_KEY_INIT:
      self->foo = make_string("default-foo");
      self->bar = NULL;
      break;

    case OPT_FOO:
      lsh_string_free(self->foo);
      self->foo = ssh_format("%ls", value, data);
      break;

    case OPT_BAR:
      lsh_string_free(self->bar);
      self->bar = ssh_format("%ls", value, data);
      break;

    case CONFIG_PARSE_KEY_END:
      break;

    default:
      return EINVAL;
    }
  return 0;
}

static const struct config_parser
parser = {
  options,
  handler,
  NULL
};

static const char *config_file =
"# a comment\n"
"foo aaa\n\n   \n"
"bar bbbb\n"
"  # bla bla";

int
test_main(void)
{
  struct values v;
  int err;
  
  err = server_config_parse_string(&parser, "test file", strlen(config_file), config_file, &v);

  ASSERT (err == 0);
  ASSERT(v.foo);
  ASSERT(lsh_string_eq_l(v.foo, 3, "aaa"));
  
  ASSERT(v.bar);
  ASSERT(lsh_string_eq_l(v.bar, 4, "bbbb"));

  SUCCESS();
}
