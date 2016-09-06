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

#include "tests/test_hmac_sha1.c"
#include "tests/test_hotp.c"
#include "tests/test_totp.c"

#include <CUnit/Basic.h>

int main(void) {
  CU_pSuite pSuite1 = NULL;
  CU_pSuite pSuite2 = NULL;
  CU_pSuite pSuite3 = NULL;

  /* initialize the CUnit test registry */
  if (CU_initialize_registry() != CUE_SUCCESS) {
    return CU_get_error();
  }

  if ( addHMACTestSuite( pSuite1 ) != CUE_SUCCESS) {
   CU_cleanup_registry();
   return CU_get_error();
 }

  if ( addHOTPTestSuite( pSuite2 ) != CUE_SUCCESS) {
    CU_cleanup_registry();
    return CU_get_error();
  }

  if ( addTOTPTestSuite( pSuite3 ) != CUE_SUCCESS) {
    CU_cleanup_registry();
    return CU_get_error();
  }

  /* Run all tests using the CUnit Basic interface */
  CU_basic_set_mode(CU_BRM_VERBOSE);
  CU_basic_run_tests();
  CU_cleanup_registry();
  return CU_get_error();
}
