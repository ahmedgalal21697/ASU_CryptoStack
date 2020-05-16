/*
 * sha_1.h
 *
 *  Created on: Mar 3, 2020
 *      Author: Ahmed Antar
 */

#ifndef SHA_1_H_
#define SHA_1_H_

/*************************** HEADER FILES ***************************/
#include <stddef.h>
#include "Platform_Types.h"
/****************************** MACROS ******************************/
#define SHA1_BLOCK_SIZE 20              // SHA1 outputs a 20 byte digest

/**************************** DATA TYPES ****************************/
//typedef unsigned char uint8;             // 8-bit byte
//typedef unsigned int  uint32;             // 32-bit word, change to "long" for 16-bit machines

typedef struct {
	uint8 data[64];
	uint32 datalen;
	unsigned long long bitlen;
	uint32 state[5];
	uint32 k[4];
} SHA1_CTX;

/*********************** FUNCTION DECLARATIONS **********************/
void sha1_init(SHA1_CTX *ctx);
void sha1_update(SHA1_CTX *ctx, const uint8 data[], uint32 len);
void sha1_final(SHA1_CTX *ctx, uint8 hash[]);
//void sha1( const uint8 data[],size_t len,uint8** hash,SHA1_CTX *ctx);


#endif /* SHA_1_H_ */
