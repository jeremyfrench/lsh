
/* Examples taken from RFC-2693 */
TS_TAG_GRANT(»1«,
  "(3:ftp13:ftp.clark.net3:cme(1:*3:set4:read5:write))",
  "(3:ftp13:ftp.clark.net3:cme4:read)")

TS_TAG_DENY(»2«,
  "(3:ftp13:ftp.clark.net3:cme(1:*3:set4:read5:write))",
  "(3:ftp13:ftp.clark.net3:cme6:delete)")

TS_TAG_DENY(»3«,
  "(3:ftp13:ftp.clark.net3:cme(1:*3:set4:read5:write))",
  "(3:ftp13:ftp.clark.net3:cme)")

