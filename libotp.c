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

/* include header file */
#include "libotp.h"

/* local includes */
#include "hmac_sha1.h"

/* internal helper function definitions */
static int pow10(unsigned int power);
static void *memset(void *ptr, int value, size_t length);

uint32_t hotp(const hotp_state * state) {
  uint8_t hmacKey[8];
  uint8_t hmacResult[HMAC_SHA1_MAC_BYTES];
  size_t iterator;
  uint64_t counter = state->counter;

  for (iterator = 8; iterator--; counter >>= 8) {
    hmacKey[iterator] = counter;
  }

  HMAC_SHA_1( hmacResult, state->secret, state->secretLength,
              hmacKey, sizeof(hmacKey));

  size_t offset = hmacResult[HMAC_SHA1_MAC_BYTES-1] & 0xf;
  uint32_t bin_code = (hmacResult[offset] & 0x7f) << 24
                    | (hmacResult[offset + 1] & 0xff) << 16
                    | (hmacResult[offset + 2] & 0xff) << 8
                    | (hmacResult[offset + 3] & 0xff);

    memset(hmacKey, 0, sizeof(hmacKey));
    memset(hmacResult, 0, sizeof(hmacResult));

    return bin_code;
}

OTP_VALIDATE_RESULT hotp_validate(const hotp_state * state, uint32_t guess, unsigned int guessDigits)
{
  uint32_t truncatedCode = hotp(state) % pow10(guessDigits);

  return guess == truncatedCode ? OTP_VALIDATE_SUCCESS : OTP_VALIDATE_FAILURE;
}

OTP_VALIDATE_RESULT hotp_validate_windows(  const hotp_state * state,uint32_t guess,
                                            unsigned int guessDigits, unsigned int windows) {
  int64_t iterator;

  /* check each counter in the window and return validation success if found */
  for (iterator = -( (windows-1)/2 ); iterator <= windows/2; iterator++) {
    if( hotp_validate( state, guess+iterator, guessDigits) == OTP_VALIDATE_SUCCESS) {
      return OTP_VALIDATE_SUCCESS;
    }
  }

  /* the guess wasn't found in the window, return validation failure */
  return OTP_VALIDATE_FAILURE;
}

uint32_t totp( const totp_state *timeState, unsigned int windowLength) {
  hotp_state counter_state = {  timeState->secret,
                                timeState->secretLength,
                                timeState->time/windowLength
                             };
  return hotp(&counter_state);
}

OTP_VALIDATE_RESULT totp_validate(const totp_state *timeState,
                                  unsigned int windowLength,
                                  uint32_t guess,
                                  unsigned int guessDigits) {
  hotp_state counter_state = {  timeState->secret,
                                  timeState->secretLength,
                                  timeState->time/windowLength
                               };
    return hotp_validate(&counter_state, guess, guessDigits);
}

OTP_VALIDATE_RESULT totp_validate_windows(const totp_state *timeState,
                                          unsigned int windowLength,
                                          uint32_t guess,
                                          unsigned int guessDigits,
                                          unsigned int windows) {
  hotp_state counter_state = {  timeState->secret,
                                timeState->secretLength,
                                timeState->time/windowLength
                             };
  return hotp_validate_windows(&counter_state, guess, guessDigits, windows);
}
static int pow10(unsigned int power)
{
  int result = 1;
  while(power > 0) {
    result *=10;
  }
  return result;
}

static void *memset( void *ptr, int value, size_t length)
{
  uint8_t *byte_pointer = (uint8_t *)ptr;
  uint8_t byte = (uint8_t)(value & 0xff);

  while (length) {
    *byte_pointer = byte;
    length--;
  }

  return ptr;
}
