/*
 * Author: Philip Woolford
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at

 * http://www.apache.org/licenses/LICENSE-2.0

 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

#ifndef HMAC_SHA1_test_
#define HMAC_SHA1_test_

/* local includes */
#include "../hmac_sha1.h"

/* external includes */
#include <CUnit/Basic.h>
#include <CUnit/CUError.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* HMAC test function definitions */
int init_hmac_sha1_suite(void);
int clean_hmac_sha1_suite(void);
void hmac_sha1_testvec1(void);
void hmac_sha1_testvec2(void);
void hmac_sha1_testvec3(void);
void hmac_sha1_testvec4(void);
void hmac_sha1_testvec5(void);

CU_ErrorCode addHMACTestSuite( CU_pSuite pSuite )
{
  /* add the HMAC-SHA1 suite to the registry */
    pSuite = CU_add_suite("HMAC-SHA-1 Test Vectors (RFC 2202)", init_hmac_sha1_suite, clean_hmac_sha1_suite);
    if (pSuite == NULL) {
      CU_cleanup_registry();
      return CU_get_error();
    }

    /* add the HMAC-SHA1 tests to the suite */
    if (   (NULL == CU_add_test(pSuite, "HMAC Test Vector 1", hmac_sha1_testvec1))
        || (NULL == CU_add_test(pSuite, "HMAC Test Vector 2", hmac_sha1_testvec2))
        || (NULL == CU_add_test(pSuite, "HMAC Test Vector 3", hmac_sha1_testvec3))
        || (NULL == CU_add_test(pSuite, "HMAC Test Vector 4", hmac_sha1_testvec4))
        || (NULL == CU_add_test(pSuite, "HMAC Test Vector 5", hmac_sha1_testvec5))) {
      return CU_get_error();
    }

    return CUE_SUCCESS;
}

/* The suite boilerplate functions */
int init_hmac_sha1_suite(void) {
  return CUE_SUCCESS;
}

int clean_hmac_sha1_suite(void) {
  return CUE_SUCCESS;
}

/* HMAC Test Vector 1 */
void hmac_sha1_testvec1(void) {
  char key[21];
  const char expect[] = "b617318655057264e28bc0b6fb378c8ef146be00";
  const char data[] = "Hi There";
  unsigned char *result = (unsigned char *) calloc(21, sizeof(unsigned char));
  char hexresult[41];
  size_t iterator;
  size_t offset;

  /* generate key */
  for (iterator = 0; iterator < 20; iterator++) {
    key[iterator] = (char) 0x0b;
  }
  key[20] = (char) 0x00;

  /* calculate hash */
  HMAC_SHA_1((uint8_t *)result, (uint8_t *)key, strlen(key), (uint8_t *)data, strlen(data));

  /* format the hash for comparison */
  for (offset = 0; offset < 20; offset++) {
    sprintf((hexresult + (2 * offset)), "%02x", result[offset] & 0xff);
  }

  free(result);
  CU_ASSERT(strncmp(hexresult, expect, 40) == CUE_SUCCESS);
}

/* HMAC Test Vector 2 */
void hmac_sha1_testvec2(void) {
  const char key[] = "Jefe";
  const char data[] = "what do ya want for nothing?";
  char const expect[] = "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79";
  unsigned char *result = (unsigned char *) calloc(21, sizeof(unsigned char));
  char hexresult[41];
  size_t offset;

  /* calculate hash */
  HMAC_SHA_1((uint8_t *)result, (uint8_t *)key, strlen(key), (uint8_t *)data, strlen(data));

  /* format the hash for comparison */
  for (offset = 0; offset < 20; offset++) {
    sprintf((hexresult + (2 * offset)), "%02x", result[offset] & 0xff);
  }

  free(result);

  CU_ASSERT(strncmp(hexresult, expect, 40) == CUE_SUCCESS);
}

/* HMAC Test Vector 3 */
void hmac_sha1_testvec3(void) {
  char key[21];
  char data[51];
  char const expect[] = "125d7342b9ac11cd91a39af48aa17b4f63f175d3";
  char result[21];
  char hexresult[41];
  size_t iterator;
  size_t offset;

  /* generate key */
  for (iterator = 0; iterator < 20; iterator++) {
    key[iterator] = (char) 0xaa;
  }
  key[20] = (char) 0x00;

  /* generate data */
  for (iterator = 0; iterator < 50; iterator++) {
    data[iterator] = (char) 0xdd;
  }
  data[50] = (char) 0x00;

  /* calculate hash */
  HMAC_SHA_1((uint8_t *)result, (uint8_t *)key, strlen(key), (uint8_t *)data, strlen(data));

  /* format the hash for comparison */
  for (offset = 0; offset < 20; offset++) {
    sprintf((hexresult + (2 * offset)), "%02x", result[offset] & 0xff);
  }

  CU_ASSERT(strncmp(hexresult, expect, 40) == CUE_SUCCESS);
}

/* HMAC Test Vector 4 */
void hmac_sha1_testvec4(void) {
  char key[26];
  char data[51];
  char const expect[] = "4c9007f4026250c6bc8414f9bf50c86c2d7235da";
  char result[21];
  char hexresult[41];
  size_t iterator;
  size_t offset;

  /* generate key */
  for (iterator = 0; iterator < 25; iterator++) {
    key[iterator] = (char) (iterator + 1);
  }
  key[25] = (char) 0x00;

  /* generate data */
  for (iterator = 0; iterator < 50; iterator++) {
    data[iterator] = (char) 0xcd;
  }
  data[50] = (char) 0x00;

  /* calculate hash */
  HMAC_SHA_1((uint8_t *)result, (uint8_t *)key, strlen(key), (uint8_t *)data, strlen(data));

  /* format the hash for comparison */
  for (offset = 0; offset < 20; offset++) {
    sprintf((hexresult + (2 * offset)), "%02x", result[offset] & 0xff);
  }

  CU_ASSERT(strncmp(hexresult, expect, 40) == CUE_SUCCESS);
}

/* HMAC Test Vector 5 */
void hmac_sha1_testvec5(void) {
  char key[21];
  char data[] = "Test With Truncation";
  char const expect[] = "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04";
  char result[21];
  char hexresult[41];
  size_t iterator;
  size_t offset;

  /* generate key */
  for (iterator = 0; iterator < 20; iterator++) {
    key[iterator] = (char) 0x0c;
  }
  key[20] = (char) 0x00;

  /* calculate hash */
  HMAC_SHA_1((uint8_t *)result, (uint8_t *)key, strlen(key), (uint8_t *)data, strlen(data));

  /* format the hash for comparison */
  for (offset = 0; offset < 20; offset++) {
    sprintf((hexresult + (2 * offset)), "%02x", result[offset] & 0xff);
  }

  CU_ASSERT(strncmp(hexresult, expect, 40) == CUE_SUCCESS);
}

#endif /* HMAC_SHA1_test_ */
