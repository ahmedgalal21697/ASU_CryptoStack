#ifndef CRYIF_H
#define CRYIF_H

#include "Csm_Types.h"
#include "CryIf_Cfg.h"

#define MODULE_ID_CRYIF  (uint16)112



/* version macrocs*/
#define CRYIF_VENDOR_ID          (1U)
#define CRYIF_MODULE_ID          (110U)
#define CRYIF_AR_MAJOR_VERSION   4
#define CRYIF_AR_MINOR_VERSION   3
#define CRYIF_AR_PATCH_VERSION   1

#define CRYIF_SW_MAJOR_VERSION   4
#define CRYIF_SW_MINOR_VERSION   3
#define CRYIF_SW_PATCH_VERSION   1
//-----------------------------------------------------------//

/* Services IDs */

#define CRYIF_INIT_ID 0x00
#define CRYIF_GET_VERSION_INFO 0x10
#define CRYIF_PROCESSJOB_ID 0x02
#define CRYIF_CANCEL_JOB_ID 0x0e
#define CRYIF_KEY_ELEMENT_SET_ID 0x04
#define CRYIF_KEY_SET_VALID_ID 0x05
#define CRYIF_KEY_ELEMENT_GET_ID 0x06
#define CRYIF_KEY_ELEMENT_COPY_ID 0x0f
#define CRYIF_KEY_COPY_ID 0x10
#define CRYIF_RANDOM_SEED_ID 0x07
#define CRYIF_KEY_GENERATE_ID 0x08
#define CRYIF_KEY_DERIVE_ID 0x09
#define CRYIF_KEY_EXCHANGE_CALC_PUBVAL_ID 0x0a
#define CRYIF_KEY_EXCHANGE_CALC_SECRET_ID 0x0b
#define CRYIF_CERTIFICATE_PARSE_ID 0x0c
#define CRYIF_CERTIFICATE_VERIFY_ID 0x11
#define CryIf_Call_back_Notification 0x0d
//-------------------------------------------------------------//
/*errors*/
#define CRYIF_E_UNINIT 0x00
#define CRYIF_E_INIT_FAILED 0x01
#define CRYIF_E_PARAM_POINTER 0x02
#define CRYIF_E_PARAM_HANDLE 0x03
#define CRYIF_E_PARAM_VALUE 0x04
#define CRYIF_E_KEY_SIZE_MISMATCH 0x05


void CryIf_Init( void );
void CryIf_GetVersionInfo( Std_VersionInfoType* versioninfo );
Std_ReturnType CryIf_ProcessJob( uint32 channelId, Crypto_JobType* job );
Std_ReturnType CryIf_CancelJob( uint32 channelId, Crypto_JobType* job );
Std_ReturnType CryIf_KeyElementSet( uint32 cryIfKeyId, uint32 keyElementId, const uint8* keyPtr, uint32 keyLength);
Std_ReturnType CryIf_KeySetValid( uint32 cryIfKeyId);
Std_ReturnType CryIf_KeyElementGet( uint32 cryIfKeyId, uint32 keyElementId, uint8* resultPtr, uint32* resultLengthPtr);
Std_ReturnType CryIf_KeyElementCopy( uint32 cryIfKeyId, uint32 keyElementId, uint32 targetCryIfKeyId, uint32 targetKeyElementId );
Std_ReturnType CryIf_KeyCopy( uint32 cryIfKeyId, uint32 targetCryIfKeyId );
Std_ReturnType CryIf_RandomSeed( uint32 cryIfKeyId, const uint8* seedPtr, uint32 seedLength);
Std_ReturnType CryIf_KeyGenerate( uint32 cryIfKeyId);
Std_ReturnType CryIf_KeyDerive( uint32 cryIfKeyId, uint32 targetCryIfKeyId);
Std_ReturnType CryIf_KeyExchangeCalcPubVal( uint32 cryIfKeyId, uint8* publicValuePtr, uint32* publicValueLengthPtr);
Std_ReturnType CryIf_KeyExchangeCalcSecret( uint32 cryIfKeyId, const uint8* partnerPublicValuePtr, uint32* partnerPublicValueLength);
Std_ReturnType CryIf_CertificateParse( uint32 cryIfKeyId);
Std_ReturnType CryIf_CertificateVerify( uint32 cryIfKeyId, uint32 verifyCryIfKeyId, Crypto_VerifyResultType* verifyPtr);

void CryIf_CallbackNotification( const Crypto_JobType* job, Std_ReturnType result);




#if ( CRYIF_VERSION_INFO_API == STD_ON )
#define CryIf_GetVersionInfo(_vi) (STD_GET_VERSION_INFO((_vi),(CRYIF)))
#endif

#endif

extern CRYIF_KEY KEYS [];
extern CRYIF_CHANNEL  CHANNELS [];


