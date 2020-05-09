#ifndef CSM_H
#define CSM_H

#include "Csm_Types.h"

// Macros for Csm Status
#define CSM_INITIALIZED (1U)
#define CSM_NOT_INITIALIZED (0U)

//Id for the company in the AUTOSAR
#define CSM_VENDOR_ID (1U)

// CSM Module Id
#define CSM_MODULE_ID (110U)

//CSM Instance Id
#define CSM_INSTANCE_ID (0U)

/*********************************************************************************************************
*                                       SERVICE ID OF APIS                                               *
*********************************************************************************************************/
//Service ID for CSM Init
#define CSM_INIT_SID 0x00
//Service ID for CSM GetVersionInfo
#define Csm_GetVersionInfo_SID 0x3b
//Service ID for Csm_Hash
#define Csm_Hash_SID 0x5d
//Service ID for Csm_Encrypt
#define Csm_Encrypt_SID 0x5e
//Service ID for Csm_Decrypt
#define Csm_Decrypt_SID 0x5f

// Module Version 4.3.1
#define CSM_MAJOR_VERSION (4U)
#define CSM_MINOR_VERSION (3U)
#define CSM_PATCH_VERSION (1U)

//Development Error Types
//API request called with invalid parameter (Nullpointer)
#define CSM_E_PARAM_POINTER 0x01
//Buffer is too small for operation
#define CSM_E_SMALL_BUFFER 0x03
//keyID is out of range
#define CSM_E_PARAM_HANDLE 0x04
//API request called before initialization of CSM module
#define CSM_E_UNINIT 0x05
//Initialization of CSM module failed
#define CSM_E_INIT_FAILED 0x07
//Requested service is not initialized
#define CSM_E_SERVICE_NOT_STARTED 0x09

void Csm_Init(void);
void Csm_GetVersionInfo(Std_VersionInfoType *versioninfo);
Std_ReturnType Csm_Hash(uint32 jobId,
						Crypto_OperationModeType mode,
						const uint8 *dataPtr,
						uint32 dataLength,
						uint8 *resultPtr,
						uint32 *resultLengthPtr);
Std_ReturnType Csm_MacGenerate(uint32 jobId,
							   Crypto_OperationModeType mode,
							   const uint8 *dataPtr,
							   uint32 dataLength,
							   uint8 *macPtr,
							   uint32 *macLengthPtr);
Std_ReturnType Csm_MacVerify(uint32 jobId,
							 Crypto_OperationModeType mode,
							 const uint8 *dataPtr,
							 uint32 dataLength,
							 const uint8 *macPtr,
							 const uint32 macLength,
							 Crypto_VerifyResultType *verifyPtr);
Std_ReturnType Csm_Encrypt(uint32 jobId,
						   Crypto_OperationModeType mode,
						   const uint8 *dataPtr,
						   uint32 dataLength,
						   uint8 *resultPtr,
						   uint32 *resultLengthPtr);
Std_ReturnType Csm_Decrypt(uint32 jobId,
						   Crypto_OperationModeType mode,
						   const uint8 *dataPtr,
						   uint32 dataLength,
						   uint8 *resultPtr,
						   uint32 *resultLengthPtr);
Std_ReturnType Csm_AEADEncrypt(uint32 jobId,
							   Crypto_OperationModeType mode,
							   const uint8 *plaintextPtr,
							   uint32 plaintextLength,
							   const uint8 *associatedDataPtr,
							   uint32 associatedDataLength,
							   uint8 *ciphertextPtr,
							   uint32 *ciphertextLengthPtr,
							   uint8 *tagPtr,
							   uint32 *tagLengthPtr);
Std_ReturnType Csm_AEADDecrypt(uint32 jobId,
							   Crypto_OperationModeType mode,
							   const uint8 *ciphertextPtr,
							   uint32 ciphertextLength,
							   const uint8 *associatedDataPtr,
							   uint32 associatedDataLength,
							   const uint8 *tagPtr,
							   uint32 tagLength,
							   uint8 *plaintextPtr,
							   uint32 *plaintextLengthPtr,
							   Crypto_VerifyResultType *verifyPtr);
Std_ReturnType Csm_SignatureGenerate(uint32 jobId,
									 Crypto_OperationModeType mode,
									 const uint8 *dataPtr,
									 uint32 dataLength,
									 uint8 *resultPtr,
									 uint32 *resultLengthPtr);
Std_ReturnType Csm_SignatureVerify(uint32 jobId,
								   Crypto_OperationModeType mode,
								   const uint8 *dataPtr,
								   uint32 dataLength,
								   const uint8 *signaturePtr,
								   uint32 signatureLength,
								   Crypto_VerifyResultType *verifyPtr);
Std_ReturnType Csm_SecureCounterIncrement(uint32 jobId,
										  uint64 stepSize);
Std_ReturnType Csm_SecureCounterRead(uint32 jobId,
									 uint64 *counterValuePtr);
Std_ReturnType Csm_RandomGenerate(uint32 jobId,
								  uint8 *resultPtr,
								  uint32 *resultLengthPtr);
Std_ReturnType Csm_KeyElementSet(uint32 keyId,
								 uint32 keyElementId,
								 const uint8 *keyPtr,
								 uint32 keyLength);
Std_ReturnType Csm_KeySetValid(uint32 keyId);
Std_ReturnType Csm_KeyElementGet(uint32 keyId,
								 uint32 keyElementId,
								 uint8 *keyPtr,
								 uint32 *keyLengthPtr);
Std_ReturnType Csm_KeyElementCopy(const uint32 keyId,
								  const uint32 keyElementId,
								  const uint32 targetKeyId,
								  const uint32 targetKeyElementId);
Std_ReturnType Csm_KeyCopy(const uint32 keyId,
						   const uint32 targetKeyId);
Std_ReturnType Csm_RandomSeed(uint32 keyId,
							  const uint8 *seedPtr,
							  uint32 seedLength);
Std_ReturnType Csm_KeyGenerate(uint32 keyId);
Std_ReturnType Csm_KeyDerive(uint32 keyId,
							 uint32 targetKeyId);
Std_ReturnType Csm_KeyExchangeCalcPubVal(uint32 keyId,
										 uint8 *publicValuePtr,
										 uint32 *publicValueLengthPtr);
Std_ReturnType Csm_KeyExchangeCalcSecret(uint32 keyId,
										 const uint8 *partnerPublicValuePtr,
										 uint32 partnerPublicValueLength);
Std_ReturnType Csm_CertificateParse(const uint32 keyId);
Std_ReturnType Csm_CertificateVerify(const uint32 keyId,
									 const uint32 verifyCryIfKeyId,
									 Crypto_VerifyResultType *verifyPtr);
Std_ReturnType Csm_CancelJob(uint32 job,
							 Crypto_OperationModeType mode);
void Csm_CallbackNotification(Crypto_JobType *job,
							  Csm_ResultType result);
void Csm_MainFunction(void);

#endif //CSM_H
