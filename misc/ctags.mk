# ctags support. Automake only supports etags. We base our ctags support on
# automake's etags support.

.PHONY: ctags-recursive ctags

ctags-recursive:
	list='$(SUBDIRS)'; for subdir in $$list; do \
	  (cd $$subdir && $(MAKE) ctags); \
	done

ctags: ctags-recursive $(HEADERS) $(SOURCES) $(CONFIG_HEADER) $(TAGS_DEPENDENCIES) $(LISP)
	tags=; \
	here=`pwd`; \
	list='$(SUBDIRS)'; for subdir in $$list; do \
	  test -f $$subdir/tags && tags="$$tags $$here/$$subdir/tags"; \
	done; \
	list='$(SOURCES) $(HEADERS)'; \
	unique=`for i in $$list; do echo $$i; done | \
	  awk '    { files[$$0] = 1; } \
	       END { for (i in files) print i; }'`; \
	test -z "$(CTAGS_ARGS)$(CONFIG_HEADER)$$unique$(LISP)$$tags" \
	  || (cd $(srcdir) && ctags --langmap=c:.c.x -o $$here/tags $(CTAGS_ARGS) $$tags $(CONFIG_HEADER) $$unique $(LISP))
# This treats .h.x files as C files rather than headers, but we can't
# distinguish them from .c.x files with ctags.

# Override the standard distclean-tags target, as this doesn't support `tags'
distclean-tags:
	-rm -f TAGS ID tags
