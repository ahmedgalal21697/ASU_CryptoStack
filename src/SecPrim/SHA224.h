/*
 * SHA224.h
 *
 *  Created on: Mar 5, 2020
 *      Author: Ahmed Antar
 */

#ifndef SHA224_H_
#define SHA224_H_

/*************************** HEADER FILES ***************************/
#include <stddef.h>

/****************************** MACROS ******************************/
#define SHA224_BLOCK_SIZE 28 // SHA224 outputs a 28 byte digest

/**************************** DATA TYPES ****************************/
typedef unsigned char BYTE; // 8-bit byte
typedef unsigned int WORD;	// 32-bit word, change to "long" for 16-bit machines

typedef struct
{
	BYTE data[64];
	WORD datalen;
	unsigned long long bitlen;
	WORD state[8];
} SHA224_CTX;

/*********************** FUNCTION DECLARATIONS **********************/
void sha224_init(SHA224_CTX *ctx);
void sha224_update(SHA224_CTX *ctx, const BYTE data[], size_t len);
void sha224_final(SHA224_CTX *ctx, BYTE hash[]);
void sha224(const BYTE data[], size_t len, BYTE hash[], SHA224_CTX *ctx);

#endif /* SHA224_H_ */
