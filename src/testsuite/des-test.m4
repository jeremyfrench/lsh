TS_TEST_CRYPTO(»DES 1«, »&crypto_des_algorithm«,
               #01010101 01010180#,
               #00000000 00000000#,
               #5799F72A D23FAE4C#)

TS_TEST_CRYPTO(»DES 2«, »&crypto_des_algorithm«,
               #80010101 01010101#,
               #00000000 00000000#,
               #90E696A2 AD56500D#)

TS_TEST_CRYPTO(»DES 3«, »&crypto_des_algorithm«,
               #08192A3B 4C5D6E7F#,
               #00000000 00000000#,
               #435CFFC5 68B3701D#)

TS_TEST_CRYPTO(»DES 4«, »&crypto_des_algorithm«,
               #01234567 89ABCDEF#,
	       "Now is t",
               #80B507E1 E6A7473D#)
