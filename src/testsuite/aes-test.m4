/* From draft NIST spec on AES modes. */

TS_TEST_CRYPTO(�aes-256 cbc 1�, �&crypto_aes256_cbc_algorithm�, 
	       �603deb1015ca71be2b73aef0857d7781
		1f352c073b6108d72d9810a30914dff4�,
	       �6bc1bee22e409f96e93d7e117393172a
		ae2d8a571e03ac9c9eb76fac45af8e51
		30c81c46a35ce411e5fbc1191a0a52ef
		f69f2445df4f9b17ad2b417be66c3710�,
	       �f58c4c04d6e5f1ba779eabfb5f7bfbd6
		9cfc4e967edb808d679f777bc6702c7d
		39f23369a9d9bacfa530e26304231461
		b2eb05e2c39be9fcda6c19078c6a9d1b�,
	       �000102030405060708090a0b0c0d0e0f�, )

/*
F.2.5 CBC-AES256-Encrypt

Key	603deb1015ca71be2b73aef0857d7781
	1f352c073b6108d72d9810a30914dff4
IV 	000102030405060708090a0b0c0d0e0f
Block #1
Plaintext	6bc1bee22e409f96e93d7e117393172a
Input Block	6bc0bce12a459991e134741a7f9e1925
Output Block	f58c4c04d6e5f1ba779eabfb5f7bfbd6
Ciphertext	f58c4c04d6e5f1ba779eabfb5f7bfbd6
Block #2
Plaintext	ae2d8a571e03ac9c9eb76fac45af8e51
Input Block	5ba1c653c8e65d26e929c4571ad47587
Output Block	9cfc4e967edb808d679f777bc6702c7d
Ciphertext	9cfc4e967edb808d679f777bc6702c7d
Block #3
Plaintext	30c81c46a35ce411e5fbc1191a0a52ef
Input Block	ac3452d0dd87649c8264b662dc7a7e92
Output Block	39f23369a9d9bacfa530e26304231461
Ciphertext	39f23369a9d9bacfa530e26304231461
Block #4
Plaintext	f69f2445df4f9b17ad2b417be66c3710
Input Block	cf6d172c769621d8081ba318e24f2371
Output Block	b2eb05e2c39be9fcda6c19078c6a9d1b
Ciphertext	b2eb05e2c39be9fcda6c19078c6a9d1b

F.2.6 CBC-AES256-Decrypt
Key	603deb1015ca71be2b73aef0857d7781
	1f352c073b6108d72d9810a30914dff4
IV 	000102030405060708090a0b0c0d0e0f
Block #1
Ciphertext	f58c4c04d6e5f1ba779eabfb5f7bfbd6
Input Block	f58c4c04d6e5f1ba779eabfb5f7bfbd6
Output Block	6bc0bce12a459991e134741a7f9e1925
Plaintext	6bc1bee22e409f96e93d7e117393172a
Block #2
Ciphertext	9cfc4e967edb808d679f777bc6702c7d
Input Block	9cfc4e967edb808d679f777bc6702c7d
Output Block	5ba1c653c8e65d26e929c4571ad47587
Plaintext	ae2d8a571e03ac9c9eb76fac45af8e51
Block #3
Ciphertext	39f23369a9d9bacfa530e26304231461
Input Block	39f23369a9d9bacfa530e26304231461
Output Block	ac3452d0dd87649c8264b662dc7a7e92
Plaintext	30c81c46a35ce411e5fbc1191a0a52ef
Block #4
Ciphertext	b2eb05e2c39be9fcda6c19078c6a9d1b
Input Block	b2eb05e2c39be9fcda6c19078c6a9d1b
Output Block	cf6d172c769621d8081ba318e24f2371
Plaintext	f69f2445df4f9b17ad2b417be66c3710
*/
