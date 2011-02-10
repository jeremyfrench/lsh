#include "testutils.h"
#include "aes.h"
#include "gcm.h"

static void
test_gcm_aes(unsigned key_length,
	     const uint8_t *key,
	     unsigned auth_length,
	     const uint8_t *authtext,
	     unsigned length,
	     const uint8_t *cleartext,
	     const uint8_t *ciphertext,
	     unsigned iv_length,
	     const uint8_t *iv,
	     const uint8_t *digest)
{
  struct gcm_aes_ctx ctx;

  uint8_t *data = xalloc(length);
  uint8_t buffer[GCM_BLOCK_SIZE];

  /* encryption */
  memset(buffer, 0, sizeof(buffer));
  gcm_aes_set_key(&ctx, key_length, key);

  gcm_aes_set_iv(&ctx, iv_length, iv);

  if (auth_length)
    gcm_aes_auth(&ctx, auth_length, authtext);
    
  if (length)
    gcm_aes_encrypt(&ctx, length, data, cleartext);

  gcm_aes_digest(&ctx, GCM_BLOCK_SIZE, buffer);

  if (!MEMEQ(length, data, ciphertext))
    FAIL();

  if (!MEMEQ(GCM_BLOCK_SIZE, buffer, digest))
    FAIL();

  /* decryption */
  memset(buffer, 0, sizeof(buffer));
  gcm_aes_set_iv(&ctx, iv_length, iv);

  if (auth_length)
    gcm_aes_auth(&ctx, auth_length, authtext);
    
  if (length)
    gcm_aes_decrypt(&ctx, length, data, data);

  gcm_aes_digest(&ctx, GCM_BLOCK_SIZE, buffer);

  if (!MEMEQ(length, data, cleartext))
    FAIL();

  if (!MEMEQ(GCM_BLOCK_SIZE, buffer, digest))
    FAIL();

  free(data);
}

int
test_main(void)
{
  /* 
   * GCM-AES Test Vectors from
   * htt://www.cryptobarn.com/papers/gcm-spec.pdf
   */

  /* Test case 1 */
  test_gcm_aes(/* key */HL("00000000000000000000000000000000"),
	       /* auth data */ HL(""),
	       /* plaintext */HL(""),
	       /* ciphertext*/H(""),
	       /* IV */HL("000000000000000000000000"),
	       /* tag */H("58e2fccefa7e3061367f1d57a4e7455a"));

  /* Test case 2 */
  test_gcm_aes(HL("00000000000000000000000000000000"),
	       HL(""),
	       HL("00000000000000000000000000000000"),
	       H("0388dace60b6a392f328c2b971b2fe78"),
	       HL("000000000000000000000000"),
	       H("ab6e47d42cec13bdf53a67b21257bddf"));

  /* Test case 3 */
  test_gcm_aes(HL("feffe9928665731c6d6a8f9467308308"),
	       HL(""),
	       HL("d9313225f88406e5a55909c5aff5269a"
		  "86a7a9531534f7da2e4c303d8a318a72"
		  "1c3c0c95956809532fcf0e2449a6b525"
		  "b16aedf5aa0de657ba637b391aafd255"),
	       H("42831ec2217774244b7221b784d0d49c"
		 "e3aa212f2c02a4e035c17e2329aca12e"
		 "21d514b25466931c7d8f6a5aac84aa05"
		 "1ba30b396a0aac973d58e091473f5985"),
	       HL("cafebabefacedbaddecaf888"),
	       H("4d5c2af327cd64a62cf35abd2ba6fab4"));

  /* Test case 4 */
  test_gcm_aes(HL("feffe9928665731c6d6a8f9467308308"),
	       HL("feedfacedeadbeeffeedfacedeadbeef"
		  "abaddad2"),
	       HL("d9313225f88406e5a55909c5aff5269a"
		  "86a7a9531534f7da2e4c303d8a318a72"
		  "1c3c0c95956809532fcf0e2449a6b525"
		  "b16aedf5aa0de657ba637b39"),
	       H("42831ec2217774244b7221b784d0d49c"
		 "e3aa212f2c02a4e035c17e2329aca12e"
		 "21d514b25466931c7d8f6a5aac84aa05"
		 "1ba30b396a0aac973d58e091"),
	       HL("cafebabefacedbaddecaf888"),
	       H("5bc94fbc3221a5db94fae95ae7121a47"));

  /* Test case 5 */
  test_gcm_aes(HL("feffe9928665731c6d6a8f9467308308"),
	       HL("feedfacedeadbeeffeedfacedeadbeef"
		  "abaddad2"),
	       HL("d9313225f88406e5a55909c5aff5269a"
		  "86a7a9531534f7da2e4c303d8a318a72"
		  "1c3c0c95956809532fcf0e2449a6b525"
		  "b16aedf5aa0de657ba637b39"),
	       H("61353b4c2806934a777ff51fa22a4755"
		 "699b2a714fcdc6f83766e5f97b6c7423"
		 "73806900e49f24b22b097544d4896b42"
		 "4989b5e1ebac0f07c23f4598"),
	       HL("cafebabefacedbad"),
	       H("3612d2e79e3b0785561be14aaca2fccb"));

  /* Test case 6 */
  test_gcm_aes(HL("feffe9928665731c6d6a8f9467308308"),
	       HL("feedfacedeadbeeffeedfacedeadbeef"
		  "abaddad2"),
	       HL("d9313225f88406e5a55909c5aff5269a"
		  "86a7a9531534f7da2e4c303d8a318a72"
		  "1c3c0c95956809532fcf0e2449a6b525"
		  "b16aedf5aa0de657ba637b39"),
	       H("8ce24998625615b603a033aca13fb894"
		 "be9112a5c3a211a8ba262a3cca7e2ca7"
		 "01e4a9a4fba43c90ccdcb281d48c7c6f"
		 "d62875d2aca417034c34aee5"),
	       HL("9313225df88406e555909c5aff5269aa"
		  "6a7a9538534f7da1e4c303d2a318a728"
		  "c3c0c95156809539fcf0e2429a6b5254"
		  "16aedbf5a0de6a57a637b39b"),
	       H("619cc5aefffe0bfa462af43c1699d050"));
  
  /* Test case 7 */
  test_gcm_aes(HL("00000000000000000000000000000000"
		  "0000000000000000"),
	       HL(""),
	       HL(""),
	       H(""),
	       HL("000000000000000000000000"),
	       H("cd33b28ac773f74ba00ed1f312572435"));

  /* Test case 8 */
  test_gcm_aes(HL("00000000000000000000000000000000"
		  "0000000000000000"),
	       HL(""),
	       HL("00000000000000000000000000000000"),
	       H("98e7247c07f0fe411c267e4384b0f600"),
	       HL("000000000000000000000000"),
	       H("2ff58d80033927ab8ef4d4587514f0fb"));

  /* Test case 9 */
  test_gcm_aes(HL("feffe9928665731c6d6a8f9467308308"
		  "feffe9928665731c"),
	       HL(""),
	       HL("d9313225f88406e5a55909c5aff5269a"
		  "86a7a9531534f7da2e4c303d8a318a72"
		  "1c3c0c95956809532fcf0e2449a6b525"
		  "b16aedf5aa0de657ba637b391aafd255"),
	       H("3980ca0b3c00e841eb06fac4872a2757"
		  "859e1ceaa6efd984628593b40ca1e19c"
		  "7d773d00c144c525ac619d18c84a3f47"
		  "18e2448b2fe324d9ccda2710acade256"),
	       HL("cafebabefacedbaddecaf888"),
	       H("9924a7c8587336bfb118024db8674a14"));

  /* Test case 10 */
  test_gcm_aes(HL("feffe9928665731c6d6a8f9467308308"
		  "feffe9928665731c"),
	       HL("feedfacedeadbeeffeedfacedeadbeef"
		  "abaddad2"),
	       HL("d9313225f88406e5a55909c5aff5269a"
		  "86a7a9531534f7da2e4c303d8a318a72"
		  "1c3c0c95956809532fcf0e2449a6b525"
		  "b16aedf5aa0de657ba637b39"),
	       H("3980ca0b3c00e841eb06fac4872a2757"
		 "859e1ceaa6efd984628593b40ca1e19c"
		 "7d773d00c144c525ac619d18c84a3f47"
		 "18e2448b2fe324d9ccda2710"),
	       HL("cafebabefacedbaddecaf888"),
	       H("2519498e80f1478f37ba55bd6d27618c"));

  /* Test case 11 */
  test_gcm_aes(HL("feffe9928665731c6d6a8f9467308308"
		  "feffe9928665731c"),
	       HL("feedfacedeadbeeffeedfacedeadbeef"
		  "abaddad2"),
	       HL("d9313225f88406e5a55909c5aff5269a"
		  "86a7a9531534f7da2e4c303d8a318a72"
		  "1c3c0c95956809532fcf0e2449a6b525"
		  "b16aedf5aa0de657ba637b39"),
	       H("0f10f599ae14a154ed24b36e25324db8"
		 "c566632ef2bbb34f8347280fc4507057"
		 "fddc29df9a471f75c66541d4d4dad1c9"
		 "e93a19a58e8b473fa0f062f7"),
	       HL("cafebabefacedbad"),
	       H("65dcc57fcf623a24094fcca40d3533f8"));
#if 0
  /* Test case 12 */
  test_gcm_aes(
	       );

  /* Test case 13 */
  test_gcm_aes(
	       );

  /* Test case 14 */
  test_gcm_aes(
	       );

  /* Test case 15 */
  test_gcm_aes(
	       );

  /* Test case 16 */
  test_gcm_aes(
	       );

  /* Test case 17 */
  test_gcm_aes(
	       );

  /* Test case 18 */
  test_gcm_aes(
	       );
#endif
  SUCCESS();
}

