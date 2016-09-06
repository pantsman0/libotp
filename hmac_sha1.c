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

/* local includes */
#include "hmac_sha1.h"

/* external includes; */
#include "sha1/sha1.h"
#include <string.h>

/* local SHA1 defines - See RFC 3174 */
#define INNER_PAD_BYTE 0x36
#define OUTER_PAD_BYTE 0x5c
#define KEY_PAD_BYTE = 0x00
#define SHA1_DIGEST_BYTES 20
#define SHA1_KEY_BYTES 64

/* implement HMAC (https://tools.ietf.org/html/rfc2104) for sha1 */
void HMAC_SHA_1(uint8_t * outerResult, const uint8_t * key,
    size_t keyLength, const uint8_t * message, size_t messageLength) {
  /* declare local variables */
  uint8_t innerResult[SHA1_DIGEST_BYTES];
  uint8_t truncatedKey[SHA1_DIGEST_BYTES];
  uint8_t innerPadBuffer[SHA1_KEY_BYTES];
  uint8_t outerPadBuffer[SHA1_KEY_BYTES];
  size_t iterator;

  memset(innerPadBuffer, INNER_PAD_BYTE, SHA1_KEY_BYTES);
  memset(outerPadBuffer, OUTER_PAD_BYTE, SHA1_KEY_BYTES);

  /* the key can't be longer than the block length */
  if (keyLength > SHA1_KEY_BYTES) {
    SHA1_CTX keyCtx;
    SHA1Init(&keyCtx);
    SHA1Update(&keyCtx, key, keyLength);
    SHA1Final(truncatedKey, &keyCtx);

    key = truncatedKey;
    keyLength = SHA1_DIGEST_BYTES;
  }

  /* XOR key with pre-padded buffers */
  for (iterator = 0; iterator < keyLength; iterator++) {
    innerPadBuffer[iterator] ^= key[iterator];
    outerPadBuffer[iterator] ^= key[iterator];
  }

  /* perform inner hash */
  SHA1_CTX innerHashCtx;
  SHA1Init(&innerHashCtx);
  SHA1Update(&innerHashCtx, innerPadBuffer, SHA1_KEY_BYTES);
  SHA1Update(&innerHashCtx, message, messageLength);
  SHA1Final(innerResult, &innerHashCtx);

  /* perform outer hash */
  SHA1_CTX outerHashCtx;
  SHA1Init(&outerHashCtx);
  SHA1Update(&outerHashCtx, outerPadBuffer, SHA1_KEY_BYTES);
  SHA1Update(&outerHashCtx, innerResult, SHA1_DIGEST_BYTES);
  SHA1Final(outerResult, &outerHashCtx);
}
