/* config_parse.h
 *
 * $id$ */

#include "lsh.h"

#include <stdio.h>

enum config_type { RULE_DEFAULT, RULE_NET, RULE_HOST };

#define GABA_DECLARE
#include "config_parse.h.x"
#undef GABA_DECLARE

/* GABA:
   (class
     (name config_pair)
     (vars
       (next object config_pair)
       (name string)
       (value string)))
*/

static struct config_pair *
make_config_pair(struct lsh_string *name, struct lsh_string *value);

/* GABA:
   (class
     (name config_rule)
     (vars
       (next object config_rule)
       (type . "enum config_type")
       (tag string)
       (config object config_pair)))
*/

static struct config_rule *
make_config_rule(enum config_type type,
		 struct lsh_string *tag);

struct config_rule *
config_parse(FILE *f);
