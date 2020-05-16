/*
 * SHA224.h
 *
 *  Created on: Mar 5, 2020
 *      Author: Ahmed Antar
 */

#ifndef SHA224_H_
#define SHA224_H_

/*************************** HEADER FILES ***************************/
#include "Std_Types.h"
/****************************** MACROS ******************************/
#define SHA224_BLOCK_SIZE 28            // SHA224 outputs a 28 byte digest

/**************************** DATA TYPES ****************************/

typedef struct {
	uint8 data[64];
	uint32 datalen;
	unsigned long long bitlen;
	uint32 state[8];
} SHA224_CTX;

/*********************** FUNCTION DECLARATIONS **********************/
void sha224_init(SHA224_CTX *ctx);
void sha224_update(SHA224_CTX *ctx, const uint8 data[], uint32 len);
void sha224_final(SHA224_CTX *ctx, uint8 hash[]);





#endif /* SHA224_H_ */
