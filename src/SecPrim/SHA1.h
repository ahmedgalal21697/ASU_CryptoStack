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

/****************************** MACROS ******************************/
#define SHA1_BLOCK_SIZE 20 // SHA1 outputs a 20 byte digest

/**************************** DATA TYPES ****************************/
typedef unsigned char BYTE; // 8-bit byte
typedef unsigned int WORD;	// 32-bit word, change to "long" for 16-bit machines

typedef struct
{
	BYTE data[64];
	WORD datalen;
	unsigned long long bitlen;
	WORD state[5];
	WORD k[4];
} SHA1_CTX;

/*********************** FUNCTION DECLARATIONS **********************/
void sha1_init(SHA1_CTX *ctx);
void sha1_update(SHA1_CTX *ctx, const BYTE data[], size_t len);
void sha1_final(SHA1_CTX *ctx, BYTE hash[]);
void sha1(const BYTE data[], size_t len, BYTE hash[], SHA1_CTX *ctx);

#endif /* SHA_1_H_ */
