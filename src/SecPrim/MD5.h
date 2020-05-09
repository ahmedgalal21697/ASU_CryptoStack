/*
 * MD5.h
 *
 *  Created on: Mar 4, 2020
 *      Author: Ahmed Antar
 */

#ifndef MD5_H_
#define MD5_H_

/*************************** HEADER FILES ***************************/
#include <stddef.h>

/****************************** MACROS ******************************/
#define MD5_BLOCK_SIZE 16               // MD5 outputs a 16 byte digest

/**************************** DATA TYPES ****************************/
typedef unsigned char MD5_BYTE;             // 8-bit byte
typedef unsigned int  MD5_WORD;             // 32-bit word, change to "long" for 16-bit machines

typedef struct {
   MD5_BYTE data[64];
   MD5_WORD datalen;
   unsigned long long bitlen;
   MD5_WORD state[4];
} MD5_CTX;

/*********************** FUNCTION DECLARATIONS **********************/
void md5_init(MD5_CTX *ctx);
void md5_update(MD5_CTX *ctx, const MD5_BYTE data[], size_t len);
void md5_final(MD5_CTX *ctx, MD5_BYTE hash[]);
void md5( const MD5_BYTE data[],size_t len,MD5_BYTE hash[],MD5_CTX *ctx);



#endif /* MD5_H_ */
