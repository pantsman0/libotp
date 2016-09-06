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

#ifndef HOTP_TEST_
#define HOTP_TEST_

/* local includes */
#include "../libotp.h"

/* external includes */
#include <CUnit/Basic.h>
#include <CUnit/CUError.h>

#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* HMAC test function definitions */
int init_hotp_suite(void);
int clean_hotp_suite(void);
void hotp_testvec1(void);

/* global variable containing the HOTP secret */
char hotp_reference_secret[] = "12345678901234567890";
uint32_t hotp_reference_results[10];

CU_ErrorCode addHOTPTestSuite( CU_pSuite pSuite )
{
  /* add the HMAC-SHA1 suite to the registry */
  pSuite = CU_add_suite("HOTP Test Vectors (RFC 4226)", init_hotp_suite, clean_hotp_suite);
  if (pSuite == NULL) {
    CU_cleanup_registry();
    return CU_get_error();
  }

  /* add the HMAC-SHA1 tests to the suite */
  if ( NULL == CU_add_test(pSuite, "hotp Test Vector 1", hotp_testvec1) ) {
    return CU_get_error();
  }

  return CUE_SUCCESS;
}

/* The suite boilerplate functions */
int init_hotp_suite(void) {
  hotp_reference_results[0] = 1284755224;
  hotp_reference_results[1] = 1094287082;
  hotp_reference_results[2] = 137359152;
  hotp_reference_results[3] = 1726969429;
  hotp_reference_results[4] = 1640338314;
  hotp_reference_results[5] = 868254676;
  hotp_reference_results[6] = 1918287922;
  hotp_reference_results[7] = 82162583;
  hotp_reference_results[8] = 673399871;
  hotp_reference_results[9] = 645520489;
  return CUE_SUCCESS;
}

int clean_hotp_suite(void) {
  return CUE_SUCCESS;
}

void hotp_testvec1(void)
{
  hotp_state state;
  state.secret = (uint8_t *) hotp_reference_secret;
  state.secretLength = sizeof(hotp_reference_secret);
  uint64_t iterator;

  for (iterator = 0; iterator < sizeof(hotp_reference_results)/sizeof(uint32_t); iterator++) {
    state.counter = iterator;

    if (! (CU_ASSERT_EQUAL(hotp(&state),hotp_reference_results[iterator])))
    {
      printf("counter value: %" PRIu64 "\n",iterator);
      printf("hotp() return value: %" PRIu32 "\n", hotp(&state));

      printf( "hotp reference value: %" PRIu32 "\n",
              hotp_reference_results[iterator]);
    }
  }
}

#endif /* HOTP_TEST_ */

