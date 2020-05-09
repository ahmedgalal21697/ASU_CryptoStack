#ifndef Crypto_Cfg_H_
#define Crypto_Cfg_H_
#include "Std_Types.h"

#define Keys 10
#define KeyTypes 10
#define KeyElements 100
#define CRYPTO_DEV_ERROR_DETECT (STD_ON)

typedef enum
{
	CRYPTO_RA_DENIED = 0x01,
	CRYPTO_RA_INTERNAL_COPY = 0x02,
	CRYPTO_RA_ALLOWED = 0x03,
	CRYPTO_RA_ENCRYPTED = 0x04

} ElementReadAccessEnum;

typedef enum
{
	CRYPTO_WA_DENIED = 0x01,
	CRYPTO_WA_INTERNAL_COPY = 0x02,
	CRYPTO_WA_ALLOWED = 0x03,
	CRYPTO_WA_ENCRYPTED = 0x04
} ElementWriteAccessEnum;
typedef struct
{
	uint32 CryptoKeyElementId;
	uint64 CryptoKeyElementInitValue;
	boolean CryptoKeyElementAllowPartialAccess;
	ElementReadAccessEnum CryptoKeyElementReadAccess;
	uint32 CryptoKeyElementSize;
	ElementWriteAccessEnum CryptoKeyElementWriteAccess;
	uint8 *DataPtr;

} CryptoKeyElement;

CryptoKeyElement CryptoKeyElements[KeyElements];

typedef struct
{
	unsigned int StartingKeyElementIDx;
	unsigned int EndingKeyElementIDx;

} ElementIdRange;

typedef struct
{
	unsigned int CryptoKeyTypeId;
	ElementIdRange CryptoKeyElementRef;
} CryptoKeyType;

CryptoKeyType CryptoKeyTypes[KeyTypes];

typedef struct
{
	unsigned int CryptoKeyId;
	unsigned int CryptoKeyTypeRef;

} CryptoKey;

CryptoKey CryptoKeys[Keys];
//
#endif