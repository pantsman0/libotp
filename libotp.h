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

#ifndef LIBOTP_H_
#define LIBOTP_H_

/* external includes */
#include <stdint.h>
#include <time.h>

/* internal type definitions */
typedef enum OTP_VALIDATE_RESULT{
  OTP_VALIDATE_SUCCESS, OTP_VALIDATE_FAILURE
} OTP_VALIDATE_RESULT;

typedef enum OTP_TYPE {
  OTP_HASH, OTP_TIME
} OTP_TYPE;

typedef struct otp_state {
  uint8_t *secret;
  size_t secretLength;
  uint64_t counter;
} hotp_state;

typedef struct totp_state {
  uint8_t *secret;
  size_t secretLength;
  time_t time;
} totp_state;

uint32_t hotp(const hotp_state *state);

OTP_VALIDATE_RESULT hotp_validate(const hotp_state * state, uint32_t guess,
                                  unsigned int guessDigits);

OTP_VALIDATE_RESULT hotp_validate_windows(const hotp_state * state,
                                          uint32_t guess,
                                          unsigned int guessDigits,
                                          unsigned int windows);


uint32_t totp( const totp_state *timeState, unsigned int windowLength);

OTP_VALIDATE_RESULT totp_validate(const totp_state * timeState,
                                  unsigned int windowLength,
                                  uint32_t guess, unsigned int guessDigits);

OTP_VALIDATE_RESULT totp_validate_windows(const totp_state * timeState,
                                          unsigned int windowLength,
                                          uint32_t guess,
                                          unsigned int guessDigits,
                                          unsigned int windows);

#endif /* LIBOTP_H_ */
