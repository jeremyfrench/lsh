#include "testutils.h"

int
test_main(void)
{
  /* From draft NIST spec on AES modes. */

  test_cipher("aes-128 cbc 1", &crypto_aes128_cbc_algorithm,
	      H("2b7e151628aed2a6abf7158809cf4f3c"),
	      H("6bc1bee22e409f96e93d7e117393172a"
		 "ae2d8a571e03ac9c9eb76fac45af8e51"
		 "30c81c46a35ce411e5fbc1191a0a52ef"
		 "f69f2445df4f9b17ad2b417be66c3710"),
	      H("7649abac8119b246cee98e9b12e9197d"
		"5086cb9b507219ee95db113a917678b2"
		"73bed6b8e3c1743b7116e69e22229516"
		"3ff1caa1681fac09120eca307586e1a7"),
	      H("000102030405060708090a0b0c0d0e0f"));

  test_cipher("aes-128 ctr 1", &crypto_aes128_ctr_algorithm,
	      H("2b7e151628aed2a6abf7158809cf4f3c"),
	      H("6bc1bee22e409f96e93d7e117393172a"
		"ae2d8a571e03ac9c9eb76fac45af8e51"
		"30c81c46a35ce411e5fbc1191a0a52ef"
		"f69f2445df4f9b17ad2b417be66c3710"),
	      H("874d6191b620e3261bef6864990db6ce"
		"9806f66b7970fdff8617187bb9fffdff"
		"5ae4df3edbd5d35e5b4f09020db03eab"
		"1e031dda2fbe03d1792170a0f3009cee"),
	      H("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"));

  test_cipher("aes-256 cbc 1", &crypto_aes256_cbc_algorithm, 
	      H("603deb1015ca71be2b73aef0857d7781"
		"1f352c073b6108d72d9810a30914dff4"),
	      H("6bc1bee22e409f96e93d7e117393172a"
		"ae2d8a571e03ac9c9eb76fac45af8e51"
		"30c81c46a35ce411e5fbc1191a0a52ef"
		"f69f2445df4f9b17ad2b417be66c3710"),
	      H("f58c4c04d6e5f1ba779eabfb5f7bfbd6"
		"9cfc4e967edb808d679f777bc6702c7d"
		"39f23369a9d9bacfa530e26304231461"
		"b2eb05e2c39be9fcda6c19078c6a9d1b"),
	      H("000102030405060708090a0b0c0d0e0f"));

  test_cipher("aes-256 ctr 1", &crypto_aes256_ctr_algorithm,
	      H("603deb1015ca71be2b73aef0857d7781"
		"1f352c073b6108d72d9810a30914dff4"),
	      H("6bc1bee22e409f96e93d7e117393172a"
		"ae2d8a571e03ac9c9eb76fac45af8e51"
		"30c81c46a35ce411e5fbc1191a0a52ef"
		"f69f2445df4f9b17ad2b417be66c3710"),
	      H("601ec313775789a5b7a7f504bbf3d228"
		"f443e3ca4d62b59aca84e990cacaf5c5"
		"2b0930daa23de94ce87017ba2d84988d"
		"dfc9c58db67aada613c2dd08457941a6"),
	      H("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"));
  SUCCESS();
}
