#include "Csm.h"
#include "Det.h"
#include "SecPrim.h"

static uint8 Csm_Status = CSM_NOT_INITIALIZED;
//Initializes the CSM module
void Csm_Init(void)
{
	Csm_Status = CSM_INITIALIZED;

	if (Csm_Status != CSM_INITIALIZED)
	{
		Det_ReportError(CSM_MODULE_ID,
						CSM_INSTANCE_ID,
						CSM_INIT_SID,
						CSM_E_INIT_FAILED);
	}
}

//Returns the version information of this module
void Csm_GetVersionInfo(Std_VersionInfoType *versioninfo)
{
	if (Csm_Status != CSM_INITIALIZED)
	{
		Det_ReportError(CSM_MODULE_ID,
						CSM_INSTANCE_ID,
						Csm_GetVersionInfo_SID,
						CSM_E_UNINIT);
	}
	else
	{
	}
	versioninfo->vendorID = CSM_VENDOR_ID;
	versioninfo->moduleID = CSM_MODULE_ID;
	versioninfo->sw_major_version = CSM_MAJOR_VERSION;
	versioninfo->sw_minor_version = CSM_MINOR_VERSION;
	versioninfo->sw_patch_version = CSM_PATCH_VERSION;
}
//all algo works while initialized

//Uses the given data to perform the hash calculation and stores the hash
Std_ReturnType Csm_Hash(uint32 jobId,
						Crypto_OperationModeType mode,
						const uint8 *dataPtr,
						uint32 dataLength,
						uint8 *resultPtr,
						uint32 *resultLengthPtr)
{
    Std_ReturnType Ret = E_NOT_OK;
	if (Csm_Status != CSM_INITIALIZED)
	{
		Det_ReportError(CSM_MODULE_ID,
						CSM_INSTANCE_ID,
						Csm_Hash_SID,
						CSM_E_UNINIT);
	}
	else
	{
	}

#define ALGO_MD5_H_
#ifdef ALGO_MD5_H_
	MD5_CTX md5_ctx;
	//check size of output
	if ((*resultLengthPtr) >= MD5_BLOCK_SIZE)
	{
		if (mode == CRYPTO_OPERATIONMODE_START)
		{
			md5_init(&md5_ctx);
			Ret = E_OK; //request successful
		}
		else if (mode == CRYPTO_OPERATIONMODE_UPDATE)
		{
			md5_update(&md5_ctx, dataPtr, dataLength);
			Ret = E_OK; //request successful
		}
		else if (mode == CRYPTO_OPERATIONMODE_STREAMSTART)
		{
			md5_init(&md5_ctx);
			md5_update(&md5_ctx, dataPtr, dataLength);
			Ret = E_OK; //request successful
		}
		else if (mode == CRYPTO_OPERATIONMODE_FINISH)
		{
			md5_final(&md5_ctx, resultPtr);
			return E_OK; //request successful
		}
		else if (mode == CRYPTO_OPERATIONMODE_SINGLECALL)
		{
			md5(dataPtr, dataLength, resultPtr, &md5_ctx);
			Ret = E_OK; //request successful
		}
	}
	else
	{
		return CRYPTO_E_SMALL_BUFFER; //the provided buffer is too small to store the result
	}

#endif

#ifdef ALGO_SHA_1_H_
	SHA1_CTX sha1_ctx;
	if ((*resultLengthPtr) >= MD5_BLOCK_SIZE)
	{
		if (mode == CRYPTO_OPERATIONMODE_START)
		{
			sha1_init(&sha1_ctx);
			return E_OK; //request successful
		}
		else if (mode == CRYPTO_OPERATIONMODE_UPDATE)
		{
			sha1_update(&sha1_ctx, dataPtr, dataLength);
			return E_OK; //request successful
		}
		else if (mode == CRYPTO_OPERATIONMODE_STREAMSTART)
		{
			sha1_init(&sha1_ctx);
			sha1_update(&sha1_ctx, dataPtr, dataLength);
			return E_OK; //request successful
		}
		else if (mode == CRYPTO_OPERATIONMODE_FINISH)
		{
			sha1_final(&sha1_ctx, resultPtr);
			return E_OK; //request successful
		}
		else if (mode == CRYPTO_OPERATIONMODE_SINGLECALL)
		{
			sha1(dataPtr, dataLength, resultPtr, &sha1_ctx);
			return E_OK; //request successful
		}
	}
	else
	{
		return CRYPTO_E_SMALL_BUFFER; //the provided buffer is too small to store the result
	}
#endif

#ifdef ALGO_SHA224_H_
	SHA224_CTX sha224_ctx;
	if ((*resultLengthPtr) >= MD5_BLOCK_SIZE)
	{
		if (mode == CRYPTO_OPERATIONMODE_START)
		{
			sha224_init(&sha224_ctx);
			return E_OK; //request successful
		}
		else if (mode == CRYPTO_OPERATIONMODE_UPDATE)
		{
			sha224_update(&sha224_ctx, dataPtr, dataLength);
			return E_OK; //request successful
		}
		else if (mode == CRYPTO_OPERATIONMODE_STREAMSTART)
		{
			sha224_init(&sha224_ctx);
			sha224_update(&sha224_ctx, dataPtr, dataLength);
			return E_OK; //request successful
		}
		else if (mode == CRYPTO_OPERATIONMODE_FINISH)
		{
			sha224_final(&sha224_ctx, resultPtr);
			return E_OK; //request successful
		}
		else if (mode == CRYPTO_OPERATIONMODE_SINGLECALL)
		{
			sha224(dataPtr, dataLength, resultPtr, &sha224_ctx);
			return E_OK; //request successful
		}
	}
	else
	{
		return CRYPTO_E_SMALL_BUFFER; //the provided buffer is too small to store the result
	}
#endif

#ifdef ALGO_SHA256_H_
	SHA256_CTX sha256_ctx;
	if ((*resultLengthPtr) >= MD5_BLOCK_SIZE)
	{
		if (mode == CRYPTO_OPERATIONMODE_START)
		{
			sha256_init(&sha256_ctx);
			return E_OK; //request successful
		}
		else if (mode == CRYPTO_OPERATIONMODE_UPDATE)
		{
			sha256_update(&sha256_ctx, dataPtr, dataLength);
			return E_OK; //request successful
		}
		else if (mode == CRYPTO_OPERATIONMODE_STREAMSTART)
		{
			sha256_init(&sha256_ctx);
			sha256_update(&sha256_ctx, dataPtr, dataLength);
			return E_OK; //request successful
		}
		else if (mode == CRYPTO_OPERATIONMODE_FINISH)
		{
			sha256_final(&sha256_ctx, resultPtr);
			return E_OK; //request successful
		}
		else if (mode == CRYPTO_OPERATIONMODE_SINGLECALL)
		{
			sha256(dataPtr, dataLength, resultPtr, &sha256_ctx);
			return E_OK; //request successful
		}
	}
	else
	{
		return CRYPTO_E_SMALL_BUFFER; //the provided buffer is too small to store the result
	}
#endif

#ifdef ALGO_SHA384_H_
	SHA384_CTX sha384_ctx;
	if ((*resultLengthPtr) >= MD5_BLOCK_SIZE)
	{
		if (mode == CRYPTO_OPERATIONMODE_START)
		{
			sha384_init(&sha384_ctx);
			return E_OK; //request successful
		}
		else if (mode == CRYPTO_OPERATIONMODE_UPDATE)
		{
			sha384_update(&sha384_ctx, dataPtr, dataLength);
			return E_OK; //request successful
		}
		else if (mode == CRYPTO_OPERATIONMODE_STREAMSTART)
		{
			sha384_init(&sha384_ctx);
			sha384_update(&sha384_ctx, dataPtr, dataLength);
			return E_OK; //request successful
		}
		else if (mode == CRYPTO_OPERATIONMODE_FINISH)
		{
			sha384_final(&sha384_ctx, resultPtr);
			return E_OK; //request successful
		}
		else if (mode == CRYPTO_OPERATIONMODE_SINGLECALL)
		{
			sha384(dataPtr, dataLength, resultPtr, &sha384_ctx);
			return E_OK; //request successful
		}
	}
	else
	{
		return CRYPTO_E_SMALL_BUFFER; //the provided buffer is too small to store the result
	}
#endif

#ifdef ALGO_SHA512_H_
	SHA512_CTX sha512_ctx;
	if ((*resultLengthPtr) >= MD5_BLOCK_SIZE)
	{
		if (mode == CRYPTO_OPERATIONMODE_START)
		{
			sha512_init(&sha512_ctx);
			return E_OK; //request successful
		}
		else if (mode == CRYPTO_OPERATIONMODE_UPDATE)
		{
			sha512_update(&sha512_ctx, dataPtr, dataLength);
			return E_OK; //request successful
		}
		else if (mode == CRYPTO_OPERATIONMODE_STREAMSTART)
		{
			sha512_init(&sha512_ctx);
			sha512_update(&sha512_ctx, dataPtr, dataLength);
			return E_OK; //request successful
		}
		else if (mode == CRYPTO_OPERATIONMODE_FINISH)
		{
			sha512_final(&sha512_ctx, resultPtr);
			return E_OK; //request successful
		}
		else if (mode == CRYPTO_OPERATIONMODE_SINGLECALL)
		{
			sha512(dataPtr, dataLength, resultPtr, &sha512_ctx);
			return E_OK; //request successful
		}
	}
	else
	{
		return CRYPTO_E_SMALL_BUFFER; //the provided buffer is too small to store the result
	}
#endif

	return Ret; //request failed

}

//Uses the given data to perform a MAC generation and stores the MAC in the memory location pointed to by the MAC pointer
Std_ReturnType Csm_MacGenerate(uint32 jobId,
							   Crypto_OperationModeType mode,
							   const uint8 *dataPtr,
							   uint32 dataLength,
							   uint8 *macPtr,
							   uint32 *macLengthPtr)
{
	return E_OK; //request successful

}

//Verifies the given MAC by comparing if the MAC is generated with the given data
Std_ReturnType Csm_MacVerify(uint32 jobId,
							 Crypto_OperationModeType mode,
							 const uint8 *dataPtr,
							 uint32 dataLength,
							 const uint8 *macPtr,
							 const uint32 macLength,
							 Crypto_VerifyResultType *verifyPtr)
{
	return E_OK; // request successful

}
//Encrypts the given data and store the ciphertext in the memory location pointed by the result pointer
Std_ReturnType Csm_Encrypt(uint32 jobId,
						   Crypto_OperationModeType mode,
						   const uint8 *dataPtr,
						   uint32 dataLength,
						   uint8 *resultPtr,
						   uint32 *resultLengthPtr)
{
	if (Csm_Status != CSM_INITIALIZED)
	{
		Det_ReportError(CSM_MODULE_ID,
						CSM_INSTANCE_ID,
						Csm_Encrypt_SID,
						CSM_E_UNINIT);
	}
	else
	{
	}

#define ALGO_AES_ENC_H_
#ifdef ALGO_AES_ENC_H_
	//check size of output
	if ((*resultLengthPtr) >= AES_Enc_BLOCK_SIZE)
	{

		if (mode == CRYPTO_OPERATIONMODE_SINGLECALL)
		{
			encrypt_AES(dataPtr, dataLength, resultPtr);
			return E_OK; //request successful
		}
	}
	else
	{
		return CRYPTO_E_SMALL_BUFFER; //the provided buffer is too small to store the result
	}
#endif
//this algo pass input type uint8 , and its input type uint64
// #define ALGO_DES_ENC_H_
#ifdef ALGO_DES_ENC_H_
	//check size of output
	if ((*resultLengthPtr) >= DES_Enc_BLOCK_SIZE)
	{

		if (mode == CRYPTO_OPERATIONMODE_SINGLECALL)
		{
			encrypt_DES(*dataPtr, *resultPtr);

			return E_OK; //request successful
		}
	}
	else
	{
		return CRYPTO_E_SMALL_BUFFER; //the provided buffer is too small to store the result
	}
#endif
	return E_NOT_OK; //request failed CRYPTO_E_BUSY: request failed, service is still busy
}
//Decrypts the given encrypted data and store the decrypted plaintext in the memory location pointed by the result pointer
Std_ReturnType Csm_Decrypt(uint32 jobId,
						   Crypto_OperationModeType mode,
						   const uint8 *dataPtr,
						   uint32 dataLength,
						   uint8 *resultPtr,
						   uint32 *resultLengthPtr)
{
	if (Csm_Status != CSM_INITIALIZED)
	{
		Det_ReportError(CSM_MODULE_ID,
						CSM_INSTANCE_ID,
						Csm_Decrypt_SID,
						CSM_E_UNINIT);
	}
	else
	{
	}
#define ALGO_AES_DEC_H_
#ifdef ALGO_AES_DEC_H_
	//check size of output
	if ((*resultLengthPtr) >= AES_Dec_BLOCK_SIZE)
	{

		if (mode == CRYPTO_OPERATIONMODE_SINGLECALL)
		{
			decrypt_AES(dataPtr, dataLength, resultPtr);
			return E_OK; //request successful
		}
	}
	else
	{
		return CRYPTO_E_SMALL_BUFFER; //the provided buffer is too small to store the result
	}
#endif
//this algo pass input type uint8 , and its input type uint64
// #define ALGO_DES_DEC_H_
#ifdef ALGO_DES_DEC_H_
	//check size of output
	if ((*resultLengthPtr) >= DES_Enc_BLOCK_SIZE)
	{

		if (mode == CRYPTO_OPERATIONMODE_SINGLECALL)
		{
			decrypt_DES(*dataPtr, *resultPtr);

			return E_OK; //request successful
		}
	}
	else
	{
		return CRYPTO_E_SMALL_BUFFER; //the provided buffer is too small to store the result
	}
#endif
	return E_OK; //request successful
				 //		return E_NOT_OK;                            //request failed CRYPTO_E_BUSY: request failed, service is still busy
				 //		return CRYPTO_E_QUEUE_FULL;                 //request failed, the queue is full
				 //		return CRYPTO_E_KEY_NOT_VALID;              //request failed, the key's state is "invalid"
				 //		return CRYPTO_E_SMALL_BUFFER;               //the provided buffer is too small to store the result
}
//Uses the given input data to perform a AEAD encryption and stores the ciphertext and the MAC in the memory locations pointed by the ciphertext pointer and Tag pointer
Std_ReturnType Csm_AEADEncrypt(uint32 jobId,
							   Crypto_OperationModeType mode,
							   const uint8 *plaintextPtr,
							   uint32 plaintextLength,
							   const uint8 *associatedDataPtr,
							   uint32 associatedDataLength,
							   uint8 *ciphertextPtr,
							   uint32 *ciphertextLengthPtr,
							   uint8 *tagPtr,
							   uint32 *tagLengthPtr)
{
	return E_OK; //request successful
				 //		return E_NOT_OK;                            //request failed CRYPTO_E_BUSY: request failed, service is still busy
				 //		return CRYPTO_E_BUSY;            //request failed, service is still busy
				 //		return CRYPTO_E_QUEUE_FULL;                 //request failed, the queue is full
				 //			return CRYPTO_E_KEY_NOT_VALID;              //request failed, the key's state is "invalid"
}
//Uses the given data to perform an AEAD encryption and stores the ciphertext and the MAC in the memory locations pointed by the ciphertext pointer and Tag pointer											}
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
							   Crypto_VerifyResultType *verifyPtr)
{
	return E_OK; //request successful
				 //							return E_NOT_OK;                            //request failed CRYPTO_E_BUSY: request failed, service is still busy
				 //		return CRYPTO_E_BUSY;            //request failed, service is still busy
				 //		return CRYPTO_E_QUEUE_FULL;                 //request failed, the queue is full
				 //		return CRYPTO_E_KEY_NOT_VALID;              //request failed, the key's state is "invalid"
}
//Uses the given data to perform the signature calculation and stores the signature in the memory location pointed by the result pointer
Std_ReturnType Csm_SignatureGenerate(uint32 jobId,
									 Crypto_OperationModeType mode,
									 const uint8 *dataPtr,
									 uint32 dataLength,
									 uint8 *resultPtr,
									 uint32 *resultLengthPtr)
{
	return E_OK; //request successful
				 //      return E_NOT_OK;                            //request failed CRYPTO_E_BUSY: request failed, service is still busy
				 //     return CRYPTO_E_BUSY;            //request failed, service is still busy
				 //    return CRYPTO_E_QUEUE_FULL;                 //request failed, the queue is full
				 //    return CRYPTO_E_KEY_NOT_VALID;              //request failed, the key's state is "invalid"
				 //     return CRYPTO_E_SMALL_BUFFER;               //the provided buffer is too small to store the result
}
//Verifies the given MAC by comparing if the signature is generated with the given data
Std_ReturnType Csm_SignatureVerify(uint32 jobId,
								   Crypto_OperationModeType mode,
								   const uint8 *dataPtr,
								   uint32 dataLength,
								   const uint8 *signaturePtr,
								   uint32 signatureLength,
								   Crypto_VerifyResultType *verifyPtr)
{
	return E_OK; //request successful
				 //     return E_NOT_OK;                            //request failed CRYPTO_E_BUSY: request failed, service is still busy
				 //    return CRYPTO_E_BUSY;            //request failed, service is still busy
				 //    return CRYPTO_E_QUEUE_FULL;                 //request failed, the queue is full
				 //   return CRYPTO_E_KEY_NOT_VALID;              //request failed, the key's state is "invalid"
				 //    return CRYPTO_E_SMALL_BUFFER;               //the provided buffer is too small to store the result
}
//Increments the value of the secure counter by the value contained in stepSize
Std_ReturnType Csm_SecureCounterIncrement(uint32 jobId,
										  uint64 stepSize)
{
	return E_OK; //request successful
				 //      return E_NOT_OK;                            //request failed CRYPTO_E_BUSY: request failed, service is still busy
				 //     return CRYPTO_E_BUSY;                       //request failed, service is still busy
				 //     return CRYPTO_E_QUEUE_FULL;                 //request failed, the queue is full
				 //     return CRYPTO_E_COUNTER_OVERFLOW;           //the counter is overflowed ;
}
//Retrieves the value of a secure counter
Std_ReturnType Csm_SecureCounterRead(uint32 jobId,
									 uint64 *counterValuePtr)
{
	return E_OK; //request successful
				 //    return E_NOT_OK;                            //request failed CRYPTO_E_BUSY: request failed, service is still busy
				 //     return CRYPTO_E_BUSY;                       //request failed, service is still busy
				 //    return CRYPTO_E_QUEUE_FULL;                 //request failed, the queue is full
}
//Generate a random number and stores it in the memory location pointed by the result pointer
Std_ReturnType Csm_RandomGenerate(uint32 jobId,
								  uint8 *resultPtr,
								  uint32 *resultLengthPtr)
{
	return E_OK; //request successful
				 //   return E_NOT_OK;                            //request failed CRYPTO_E_BUSY: request failed, service is still busy
				 //   return CRYPTO_E_BUSY;                       //request failed, service is still busy
				 //   return CRYPTO_E_QUEUE_FULL;                 //request failed, the queue is full
				 //	 return CRYPTO_E_ENTROPY_EXHAUSTION;         //request failed, entropy of random number generator is exhausted
}
//Sets the given key element bytes to the key identified by keyId
Std_ReturnType Csm_KeyElementSet(uint32 keyId,
								 uint32 keyElementId,
								 const uint8 *keyPtr,
								 uint32 keyLength)
{

	return E_OK; //request successful
				 //   return E_NOT_OK;                           //request failed CRYPTO_E_BUSY: request failed, service is still busy
				 //   return CRYPTO_E_BUSY;                      //request failed, service is still busy
				 //   return CRYPTO_E_KEY_WRITE_FAIL;            //Request failed because write access was denied
				 //		return CRYPTO_E_KEY_NOT_AVAILABLE;         //Request failed because the key is not available
				 //		return CRYPTO_E_KEY_SIZE_MISMATCH;         //Request failed, key element size does not match size of provided data.
}
//Sets the key state of the key identified by keyId to valid
Std_ReturnType Csm_KeySetValid(uint32 keyId)
{
	return E_OK; //request successful
				 //   return E_NOT_OK;                           //request failed CRYPTO_E_BUSY: request failed, service is still busy
				 //   return CRYPTO_E_BUSY;                      //request failed, service is still busy
}
//Retrieves the key element bytes from a specific key element of the key identified by the keyId and stores the key element in the memory location pointed by the key pointer
Std_ReturnType Csm_KeyElementGet(uint32 keyId,
								 uint32 keyElementId,
								 uint8 *keyPtr,
								 uint32 *keyLengthPtr)
{
	return E_OK; //request successful
				 //	return E_NOT_OK;                             //request failed
				 //	return CRYPTO_E_BUSY;                        //Request Failed, Crypto Driver Object is Busy
				 //	return CRYPTO_E_KEY_NOT_AVAILABLE;           //request failed, the requested key element is not available
				 //	return CRYPTO_E_KEY_READ_FAIL;               //Request failed because read access was denied
				 //	return CRYPTO_E_SMALL_BUFFER;                //the provided buffer is too small to store the result
}
//This function shall copy a key elements from one key to a target key
Std_ReturnType Csm_KeyElementCopy(const uint32 keyId,
								  const uint32 keyElementId,
								  const uint32 targetKeyId,
								  const uint32 targetKeyElementId)
{
	return E_OK; //request successful
				 //		return E_NOT_OK;                             //request failed
				 //		return CRYPTO_E_BUSY;                        //Request Failed, Crypto Driver Object is Busy
				 //		return CRYPTO_E_KEY_NOT_AVAILABLE;           //request failed, the requested key element is not available
				 //		return CRYPTO_E_KEY_READ_FAIL;               //Request failed because read access was denied
				 //		return CRYPTO_E_KEY_WRITE_FAIL;              //Request failed, not allowed to write key element.
				 //		return CRYPTO_E_KEY_SIZE_MISMATCH;           //Request failed, key element sizes are not compatible
}
//This function shall copy all key elements from the source key to a target key
Std_ReturnType Csm_KeyCopy(const uint32 keyId,
						   const uint32 targetKeyId)
{
	return E_OK; //request successful
				 //		return E_NOT_OK;                             //request failed
				 //		return CRYPTO_E_BUSY;                        //Request Failed, Crypto Driver Object is Busy
				 //		return CRYPTO_E_KEY_NOT_AVAILABLE;           //request failed, the requested key element is not available
				 //		return CRYPTO_E_KEY_READ_FAIL;               //Request failed because read access was denied
				 //		return CRYPTO_E_KEY_WRITE_FAIL;              //Request failed, not allowed to write key element.
				 //		return CRYPTO_E_KEY_SIZE_MISMATCH;           //Request failed, key element sizes are not compatible
}
//This function shall dispatch the random seed function to the configured crypto driver object
Std_ReturnType Csm_RandomSeed(uint32 keyId,
							  const uint8 *seedPtr,
							  uint32 seedLength)
{
	return E_OK; //request successful
				 //	 return E_NOT_OK;                             //request failed
}
//Generates new key material and store it in the key identified by keyId
Std_ReturnType Csm_KeyGenerate(uint32 keyId)
{
	return E_OK; //request successful
				 //	 return E_NOT_OK;                             //request failed
}
//Derives a new key by using the key elements in the given key identified by the keyId. The given key contains the key elements for the password and salt. The derived key is stored in the key element with the id 1 of the key identified by targetCryptoKeyId
Std_ReturnType Csm_KeyDerive(uint32 keyId,
							 uint32 targetKeyId)
{
	return E_OK; //request successful
				 //	return E_NOT_OK;                             //request failed
				 //	return CRYPTO_E_BUSY;                        //Request Failed, Crypto Driver Object is Busy
}
//Calculates the public value of the current user for the key exchange and stores the public key in the memory location pointed by the public value pointer
Std_ReturnType Csm_KeyExchangeCalcPubVal(uint32 keyId,
										 uint8 *publicValuePtr,
										 uint32 *publicValueLengthPtr)
{
	return E_OK; //request successful
				 //	return E_NOT_OK;                             //request failed
				 //	return CRYPTO_E_BUSY;                        //Request Failed, Crypto Driver Object is Busy
				 //	return CRYPTO_E_KEY_NOT_VALID;              //request failed, the key's state is "invalid"
				 //	return CRYPTO_E_SMALL_BUFFER;                //the provided buffer is too small to store the result
}
//Calculates the shared secret key for the key exchange with the key material of the key identified by the keyId and the partner public key. The shared secret key is stored as a key element in the same key
Std_ReturnType Csm_KeyExchangeCalcSecret(uint32 keyId,
										 const uint8 *partnerPublicValuePtr,
										 uint32 partnerPublicValueLength)
{
	return E_OK; //request successful
				 //		return E_NOT_OK;                             //request failed
				 //		return CRYPTO_E_BUSY;                        //Request Failed, Crypto Driver Object is Busy
				 //    return CRYPTO_E_SMALL_BUFFER;                //the provided buffer is too small to store the result
}
//This function shall dispatch the certificate parse function to the CRYIF
Std_ReturnType Csm_CertificateParse(const uint32 keyId)
{
	return E_OK; //request successful
				 //			return E_NOT_OK;                             //request failed
}
//Verifies the certificate stored in the key referenced by verifyKeyId with the certificate stored in the key referenced by keyId
Std_ReturnType Csm_CertificateVerify(const uint32 keyId,
									 const uint32 verifyCryIfKeyId,
									 Crypto_VerifyResultType *verifyPtr)
{
	return E_OK; //request successful
				 //		return E_NOT_OK;                             //request failed
}
//Removes the job in the Csm Queue and calls the job's callback with the result CRYPTO_E_JOB_CANCELED. It also passes the cancellation command to the CryIf to try to cancel the job in the Crypto Driver
Std_ReturnType Csm_CancelJob(uint32 job,
							 Crypto_OperationModeType mode)
{
	return E_OK; //request successful
				 //		return E_NOT_OK;                             //request failed
}
//Notifies the CSM that a job has finished. This function is used by the underlying layer (CRYIF)
void Csm_CallbackNotification(Crypto_JobType *job,
							  Csm_ResultType result)
{
}
//API to be called cyclically to process the requested jobs. The Csm_MainFunction shall check the queues for jobs to pass to the underlying CRYIF
void Csm_MainFunction(void)
{
}
