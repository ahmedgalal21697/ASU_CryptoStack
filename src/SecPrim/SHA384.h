/*
 * SHA384.h
 *
 *  Created on: Mar 5, 2020
 *      Author: Ahmed Antar
 */

#ifndef SHA384_H_
#define SHA384_H_

/*************************** HEADER FILES ***************************/
#include <stddef.h>

/****************************** MACROS ******************************/

#define SHA384_BLOCK_SIZE 48 // SHA384 outputs a 48 byte digest
#define GET_UINT64_BE(n, b, i)                                                                  \
  {                                                                                             \
    (n) = ((unsigned long long)(b)[(i)] << 56) | ((unsigned long long)(b)[(i) + 1] << 48) |     \
          ((unsigned long long)(b)[(i) + 2] << 40) | ((unsigned long long)(b)[(i) + 3] << 32) | \
          ((unsigned long long)(b)[(i) + 4] << 24) | ((unsigned long long)(b)[(i) + 5] << 16) | \
          ((unsigned long long)(b)[(i) + 6] << 8) | ((unsigned long long)(b)[(i) + 7]);         \
  }
#define PUT_UINT64_BE(n, b, i)                 \
  {                                            \
    (b)[(i)] = (unsigned char)((n) >> 56);     \
    (b)[(i) + 1] = (unsigned char)((n) >> 48); \
    (b)[(i) + 2] = (unsigned char)((n) >> 40); \
    (b)[(i) + 3] = (unsigned char)((n) >> 32); \
    (b)[(i) + 4] = (unsigned char)((n) >> 24); \
    (b)[(i) + 5] = (unsigned char)((n) >> 16); \
    (b)[(i) + 6] = (unsigned char)((n) >> 8);  \
    (b)[(i) + 7] = (unsigned char)((n));       \
  }
#define SHR(x, n) (x >> n)
#define ROTR(x, n) (SHR(x, n) | (x << (64 - n)))

#define S0(x) (ROTR(x, 1) ^ ROTR(x, 8) ^ SHR(x, 7))
#define S1(x) (ROTR(x, 19) ^ ROTR(x, 61) ^ SHR(x, 6))

#define S2(x) (ROTR(x, 28) ^ ROTR(x, 34) ^ ROTR(x, 39))
#define S3(x) (ROTR(x, 14) ^ ROTR(x, 18) ^ ROTR(x, 41))

#define F0(x, y, z) ((x & y) | (z & (x | y)))
#define F1(x, y, z) (z ^ (x & (y ^ z)))

#define P(a, b, c, d, e, f, g, h, x, K)      \
  {                                          \
    temp1 = h + S3(e) + F1(e, f, g) + K + x; \
    temp2 = S2(a) + F0(a, b, c);             \
    d += temp1;                              \
    h = temp1 + temp2;                       \
  }
/**************************** DATA TYPES ****************************/
typedef unsigned long long WORD64; // 64-bit word, change to "long" for 16-bit machines

typedef unsigned char BYTE; // 8-bit byte
typedef unsigned long long u128;
typedef struct
{
  BYTE data[128];
  WORD64 datalen[2];
  unsigned long long bitlen;
  u128 state[8];
} SHA384_CTX;

/*********************** FUNCTION DECLARATIONS **********************/
void sha384_init(SHA384_CTX *ctx);
void sha384_update(SHA384_CTX *ctx, const BYTE data[], size_t len);
void sha384_final(SHA384_CTX *ctx, BYTE hash[]);
void sha384(const BYTE data[], size_t len, BYTE hash[], SHA384_CTX *ctx);

#endif /* SHA384_H_ */
