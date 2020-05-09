#ifndef CRYIF_CFG_H
#define CRYIF_CFG_H
#include "Platform_Types.h"

#if (!(CRYIF_SW_MAJOR_VERSION == 4) && (CRYIF_SW_MINOR_VERSION == 3))
#error CryIf: Configuration file expected BSW module version to be 4.3.*
#endif

#define CYIF_VERSION_INFO_API (STD_ON)
#define CRYIF_DEV_ERROR_DETECT (STD_ON) /*SRS_CryptoStack_00034*/
//////////////////////////////////////////////////////////////////////////////////////////////////////
#define NO_OF_CHANNELS 3
#define NO_OF_KEYS 3
///////////////////////////////////////////////////////////////////////////////////////////////////////
// i assume 3 channels only and 3 drivers
typedef enum
{
	CRYIF_CHANNEL_A_ID,
	CRYIF_CHANNEL_B_ID,
	CRYIF_CHANNEL_C_ID
} CRYIF_CHANNEL_ID;
// i assume a crypto driver has one crypto object
typedef enum
{
	CRYPTO_DRIVER_OBJECT_A,
	CRYPTO_DRIVER_OBJECT_B,
	CRYPTO_DRIVER_OBJECT_C
} CRYPTO_DRIVER_OBJECT_REF;

// i assume 3 keys only

typedef enum
{
	CRYIF_KEY_ID_A,
	CRYIF_KEY_ID_B,
	CRYIF_KEY_ID_C
} CRYIF_KEY_ID;

// CryIfKeyRef
#define CryptoKey_A 5
#define CryptoKey_B 6
#define CryptoKey_C 5

typedef struct
{

	CRYIF_CHANNEL_ID CHANNEL;
	CRYPTO_DRIVER_OBJECT_REF obj; //This parameter refers to a Crypto Driver Object.
	//Specifies to which Crypto Driver Object the crypto channel is connected to

} CRYIF_CHANNEL;

typedef struct
{

	CRYIF_KEY_ID KEY;

	uint8 CryptoKey;

} CRYIF_KEY;

#endif
