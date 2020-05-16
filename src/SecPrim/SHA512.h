/*
 * SHA512.h
 *
 *  Created on: Mar 5, 2020
 *      Author: Ahmed Antar
 */

#ifndef SHA512_H_
#define SHA512_H_

/*************************** HEADER FILES ***************************/

#include "Platform_Types.h"

/****************************** DEFINES ******************************/
#define SHA512_BLOCK_SIZE 64 /* SHA512 outputs a 64 byte digest*/

typedef struct
{
  uint8 data[128];
  uint64 datalen[2];
  uint64 bitlen;
  uint64 state[8];
} SHA512_CTX;

/*********************** FUNCTION DECLARATIONS **********************/
void sha512_init(SHA512_CTX *ctx);
void sha512_update(SHA512_CTX *ctx, const uint8 data[], size_t len);
void sha512_final(SHA512_CTX *ctx, uint8 hash[]);


#endif /* SHA512_H_ */
