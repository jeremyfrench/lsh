/* From Applied Cryptography, 2:nd edition */

TS_TEST_CRYPTO(»DES AC«, »&crypto_des_algorithm«,
               #01234567 89ABCDEF#,
               #01234567 89ABCDE7#,
               #C9574425 6A5ED31D#)

/* From Dana How's DEScore */
TS_TEST_CRYPTO(»DES 1«, »&crypto_des_algorithm«,
               #01010101 01010180#,
               #00000000 00000000#,
               #9CC62DF4 3B6EED74#)

TS_TEST_CRYPTO(»DES 2«, »&crypto_des_algorithm«,
               #80010101 01010101#,
               #00000000 00000040#,
               #A380E02A 6BE54696#)

TS_TEST_CRYPTO(»DES 3«, »&crypto_des_algorithm«,
               #08192A3B 4C5D6E7F#,
               #00000000 00000000#,
               #25DDAC3E 96176467#)

TS_TEST_CRYPTO(»DES 4«, »&crypto_des_algorithm«,
               #01234567 89ABCDEF#,
	       "Now is t",
               #3FA40E8A 984D4815#)
