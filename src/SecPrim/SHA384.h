/*
 * SHA384.h
 *
 *  Created on: Mar 5, 2020
 *      Author: Ahmed Antar
 */

#ifndef SHA384_H_
#define SHA384_H_

/*************************** HEADER FILES ***************************/
#include "Platform_Types.h"
/****************************** MACROS ******************************/

#define SHA384_BLOCK_SIZE 48 /* SHA384 outputs a 48 uint8 digest*/

/**************************** DATA TYPES ****************************/

typedef struct
{
  uint8 data[128];
  uint64 datalen[2];
  uint64 bitlen;
  uint64 state[8];
} SHA384_CTX;

/*********************** FUNCTION DECLARATIONS **********************/
void sha384_init(SHA384_CTX *ctx);
void sha384_update(SHA384_CTX *ctx, const uint8 data[], uint64 len);
void sha384_final(SHA384_CTX *ctx, uint8 hash[]);


#endif /* SHA384_H_ */
