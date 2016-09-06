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

#ifndef TOTP_TEST_
#define TOTP_TEST_

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
int init_totp_suite(void);
int clean_totp_suite(void);
void totp_testvec1(void);

/* global variable containing the TOTP secret */
char totp_reference_secret[] = "12345678901234567890";
uint32_t totp_reference_results[10];

CU_ErrorCode addTOTPTestSuite( CU_pSuite pSuite )
{
  /* add the HMAC-SHA1 suite to the registry */
  pSuite = CU_add_suite("TOTP Test Vectors (adapted from RFC 4226)",
                        init_totp_suite, clean_totp_suite);

  if (pSuite == NULL) {
    CU_cleanup_registry();
    return CU_get_error();
  }

  /* add the HMAC-SHA1 tests to the suite */
  if ( CUE_SUCCESS == CU_add_test(pSuite, "totp Test Vector 1", totp_testvec1) ) {
    return CU_get_error();
  }

  return CUE_SUCCESS;
}

/* The suite boilerplate functions */
int init_totp_suite(void) {
  totp_reference_results[0] = 1284755224;
  totp_reference_results[1] = 1094287082;
  totp_reference_results[2] = 137359152;
  totp_reference_results[3] = 1726969429;
  totp_reference_results[4] = 1640338314;
  totp_reference_results[5] = 868254676;
  totp_reference_results[6] = 1918287922;
  totp_reference_results[7] = 82162583;
  totp_reference_results[8] = 673399871;
  totp_reference_results[9] = 645520489;
  return CUE_SUCCESS;
}

int clean_totp_suite(void) {
  return CUE_SUCCESS;
}

void totp_testvec1(void)
{
  totp_state state;
  state.secret = (uint8_t *) totp_reference_secret;
  state.secretLength = sizeof(totp_reference_secret);
  time_t iterator;
  unsigned int windowLength = 1;

  for (iterator = 0; iterator < sizeof(totp_reference_results)/sizeof(uint32_t); iterator++) {

    /* test start of window interval */
    state.time = iterator;
    if (! (CU_ASSERT_EQUAL(totp(&state, windowLength),totp_reference_results[iterator])))
    {
      printf("counter value: %" PRIu64 "\n",iterator);
      printf("totp() return value: %" PRIu32 "\n", totp(&state,windowLength));
      printf( "totp reference value: %" PRIu32 "\n",
              totp_reference_results[iterator]);
    }

    /* test middle of window interval */
    state.time = iterator + (windowLength/2);
    if (! (CU_ASSERT_EQUAL(totp(&state, windowLength),totp_reference_results[iterator])))
    {
      printf("counter value: %" PRIu64 "\n",iterator);
      printf("totp() return value: %" PRIu32 "\n", totp(&state,windowLength));
      printf( "totp reference value: %" PRIu32 "\n",
              totp_reference_results[iterator]);
    }

    /* test end of window interval */
    state.time = iterator + windowLength - 1;
    if (! (CU_ASSERT_EQUAL(totp(&state, windowLength),totp_reference_results[iterator])))
    {
      printf("counter value: %" PRIu64 "\n",iterator);
      printf("totp() return value: %" PRIu32 "\n", totp(&state,windowLength));
      printf( "totp reference value: %" PRIu32 "\n",
              totp_reference_results[iterator]);
    }
  }
}

#endif /* TOTP_TEST_ */

