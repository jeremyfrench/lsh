principal-test$(EXEEXT): principal-test.$(OBJEXT) $(TEST_DEPS)
	$(LINK) principal-test.$(OBJEXT) $(TEST_OBJS) -o principal-test$(EXEEXT)

date-test$(EXEEXT): date-test.$(OBJEXT) $(TEST_DEPS)
	$(LINK) date-test.$(OBJEXT) $(TEST_OBJS) -o date-test$(EXEEXT)

tag-test$(EXEEXT): tag-test.$(OBJEXT) $(TEST_DEPS)
	$(LINK) tag-test.$(OBJEXT) $(TEST_OBJS) -o tag-test$(EXEEXT)

read-acl-test$(EXEEXT): read-acl-test.$(OBJEXT) $(TEST_DEPS)
	$(LINK) read-acl-test.$(OBJEXT) $(TEST_OBJS) -o read-acl-test$(EXEEXT)

lookup-acl-test$(EXEEXT): lookup-acl-test.$(OBJEXT) $(TEST_DEPS)
	$(LINK) lookup-acl-test.$(OBJEXT) $(TEST_OBJS) -o lookup-acl-test$(EXEEXT)

read-cert-test$(EXEEXT): read-cert-test.$(OBJEXT) $(TEST_DEPS)
	$(LINK) read-cert-test.$(OBJEXT) $(TEST_OBJS) -o read-cert-test$(EXEEXT)

cdsa-reduce-test$(EXEEXT): cdsa-reduce-test.$(OBJEXT) $(TEST_DEPS)
	$(LINK) cdsa-reduce-test.$(OBJEXT) $(TEST_OBJS) -o cdsa-reduce-test$(EXEEXT)

