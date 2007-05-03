arcfour-test$(EXEEXT): arcfour-test.$(OBJEXT) $(TEST_OBJS)
	$(LINK) arcfour-test.$(OBJEXT) $(TEST_OBJS) $(TEST_LIBS) -o arcfour-test$(EXEEXT)

aes-test$(EXEEXT): aes-test.$(OBJEXT) $(TEST_OBJS)
	$(LINK) aes-test.$(OBJEXT) $(TEST_OBJS) $(TEST_LIBS) -o aes-test$(EXEEXT)

blowfish-test$(EXEEXT): blowfish-test.$(OBJEXT) $(TEST_OBJS)
	$(LINK) blowfish-test.$(OBJEXT) $(TEST_OBJS) $(TEST_LIBS) -o blowfish-test$(EXEEXT)

cast128-test$(EXEEXT): cast128-test.$(OBJEXT) $(TEST_OBJS)
	$(LINK) cast128-test.$(OBJEXT) $(TEST_OBJS) $(TEST_LIBS) -o cast128-test$(EXEEXT)

des-test$(EXEEXT): des-test.$(OBJEXT) $(TEST_OBJS)
	$(LINK) des-test.$(OBJEXT) $(TEST_OBJS) $(TEST_LIBS) -o des-test$(EXEEXT)

serpent-test$(EXEEXT): serpent-test.$(OBJEXT) $(TEST_OBJS)
	$(LINK) serpent-test.$(OBJEXT) $(TEST_OBJS) $(TEST_LIBS) -o serpent-test$(EXEEXT)

twofish-test$(EXEEXT): twofish-test.$(OBJEXT) $(TEST_OBJS)
	$(LINK) twofish-test.$(OBJEXT) $(TEST_OBJS) $(TEST_LIBS) -o twofish-test$(EXEEXT)

md5-test$(EXEEXT): md5-test.$(OBJEXT) $(TEST_OBJS)
	$(LINK) md5-test.$(OBJEXT) $(TEST_OBJS) $(TEST_LIBS) -o md5-test$(EXEEXT)

sha1-test$(EXEEXT): sha1-test.$(OBJEXT) $(TEST_OBJS)
	$(LINK) sha1-test.$(OBJEXT) $(TEST_OBJS) $(TEST_LIBS) -o sha1-test$(EXEEXT)

rsa-test$(EXEEXT): rsa-test.$(OBJEXT) $(TEST_OBJS)
	$(LINK) rsa-test.$(OBJEXT) $(TEST_OBJS) $(TEST_LIBS) -o rsa-test$(EXEEXT)

dsa-test$(EXEEXT): dsa-test.$(OBJEXT) $(TEST_OBJS)
	$(LINK) dsa-test.$(OBJEXT) $(TEST_OBJS) $(TEST_LIBS) -o dsa-test$(EXEEXT)

server-config-test$(EXEEXT): server-config-test.$(OBJEXT) $(TEST_OBJS)
	$(LINK) server-config-test.$(OBJEXT) $(TEST_OBJS) $(TEST_LIBS) -o server-config-test$(EXEEXT)

spki-tag-test$(EXEEXT): spki-tag-test.$(OBJEXT) $(TEST_OBJS)
	$(LINK) spki-tag-test.$(OBJEXT) $(TEST_OBJS) $(TEST_LIBS) -o spki-tag-test$(EXEEXT)

string-test$(EXEEXT): string-test.$(OBJEXT) $(TEST_OBJS)
	$(LINK) string-test.$(OBJEXT) $(TEST_OBJS) $(TEST_LIBS) -o string-test$(EXEEXT)

parse-config-test$(EXEEXT): parse-config-test.$(OBJEXT) $(TEST_OBJS)
	$(LINK) parse-config-test.$(OBJEXT) $(TEST_OBJS) $(TEST_LIBS) -o parse-config-test$(EXEEXT)

sockaddr2info-test$(EXEEXT): sockaddr2info-test.$(OBJEXT) $(TEST_OBJS)
	$(LINK) sockaddr2info-test.$(OBJEXT) $(TEST_OBJS) $(TEST_LIBS) -o sockaddr2info-test$(EXEEXT)

utf8-test$(EXEEXT): utf8-test.$(OBJEXT) $(TEST_OBJS)
	$(LINK) utf8-test.$(OBJEXT) $(TEST_OBJS) $(TEST_LIBS) -o utf8-test$(EXEEXT)

