#include "Crypto.h"
#include "CryIf.h"
#include "Det.h"

SHA1_CTX sha1_ctx;
SHA224_CTX sha224_ctx;
SHA256_CTX sha256_ctx;
SHA384_CTX sha384_ctx;
SHA512_CTX sha512_ctx;
MD5_CTX md5_ctx;
static boolean Cryptoinit = FALSE;
//General API
void Crypto_Init(void)
{

	Cryptoinit = TRUE;
}
void Crypto_GetVersionInfo(Std_VersionInfoType *versioninfo)
{
}

//Job Processing Interface
Std_ReturnType Crypto_ProcessJob(uint32 objectId, Crypto_JobType *job)
{
	if (FALSE == Cryptoinit)
	{

		Det_ReportError(CRYPTO_MODULE_ID, 0, Crypto_ProcessJob_ID, CRYPTO_E_UNINIT);
		return E_NOT_OK;
	}

	if (NULL == job)
	{
		Det_ReportError(CRYPTO_MODULE_ID, 0, Crypto_ProcessJob_ID, CRYPTO_E_PARAM_POINTER);
		return E_NOT_OK;
	}
	if (job->jobPrimitiveInfo->primitiveInfo->service > 0x0b | job->jobPrimitiveInfo->primitiveInfo->service < 0x00)
	{
		Det_ReportError(CRYPTO_MODULE_ID, 0, Crypto_ProcessJob_ID, CRYPTO_E_PARAM_HANDLE);
		return E_NOT_OK;
	}

	//Hash

	if (job->jobPrimitiveInfo->primitiveInfo->service == 0x00)
	{

		if (NULL == job->jobPrimitiveInputOutput.inputPtr)
		{
			Det_ReportError(CRYPTO_MODULE_ID, 0, Crypto_ProcessJob_ID, CRYPTO_E_PARAM_POINTER);
			return E_NOT_OK;
		}

		if (0 == job->jobPrimitiveInputOutput.inputLength)
		{
			Det_ReportError(CRYPTO_MODULE_ID, 0, Crypto_ProcessJob_ID, CRYPTO_E_PARAM_VALUE);
			return E_NOT_OK;
		}

		if (NULL == job->jobPrimitiveInputOutput.outputLengthPtr)
		{
			Det_ReportError(CRYPTO_MODULE_ID, 0, Crypto_ProcessJob_ID, CRYPTO_E_PARAM_POINTER);
			return E_NOT_OK;
		}
		/*	if(0==*(job->jobPrimitiveInputOutput.outputLengthPtr))
		{
				Det_ReportError(CRYPTO_MODULE_ID,0,Crypto_ProcessJob_ID,   CRYPTO_E_PARAM_VALUE );
			return E_NOT_OK;
		}*/

		/* if (job->jobPrimitiveInfo->primitiveInfo->algorithm.family>0&&job->jobPrimitiveInfo->primitiveInfo->algorithm.family<0x05&&job->jobPrimitiveInfo->primitiveInfo->algorithm.family!=0xff)
		{
					Det_ReportError(CRYPTO_MODULE_ID,0,Crypto_ProcessJob_ID, CRYPTO_E_PARAM_HANDLE  );
		return  E_NOT_OK;
		}*/

		if (job->jobPrimitiveInfo->primitiveInfo->algorithm.family == 0x01)
		{

			sha1(job->jobPrimitiveInputOutput.inputPtr, job->jobPrimitiveInputOutput.inputLength - 1, job->jobPrimitiveInputOutput.outputPtr, &sha1_ctx);
			*(job->jobPrimitiveInputOutput.outputLengthPtr) = 20;
			return E_OK;
		}
		//SHA224
		else if (job->jobPrimitiveInfo->primitiveInfo->algorithm.family == 0x02)
		{

			sha224(job->jobPrimitiveInputOutput.inputPtr, job->jobPrimitiveInputOutput.inputLength - 1, job->jobPrimitiveInputOutput.outputPtr, &sha224_ctx);
			*(job->jobPrimitiveInputOutput.outputLengthPtr) = 28;

			return E_OK;
		}
		//SHA256
		else if (job->jobPrimitiveInfo->primitiveInfo->algorithm.family == 0x03)
		{

			sha256(job->jobPrimitiveInputOutput.inputPtr, job->jobPrimitiveInputOutput.inputLength - 1, job->jobPrimitiveInputOutput.outputPtr, &sha256_ctx);
			*(job->jobPrimitiveInputOutput.outputLengthPtr) = 32;

			return E_OK;
		}
		//SHA384
		else if (job->jobPrimitiveInfo->primitiveInfo->algorithm.family == 0x04)
		{

			sha384(job->jobPrimitiveInputOutput.inputPtr, job->jobPrimitiveInputOutput.inputLength - 1, job->jobPrimitiveInputOutput.outputPtr, &sha384_ctx);
			*(job->jobPrimitiveInputOutput.outputLengthPtr) = 48;

			return E_OK;
		}
		//SHA512
		else if (job->jobPrimitiveInfo->primitiveInfo->algorithm.family == 0x05)
		{

			sha512(job->jobPrimitiveInputOutput.inputPtr, job->jobPrimitiveInputOutput.inputLength - 1, job->jobPrimitiveInputOutput.outputPtr, &sha512_ctx);
			*(job->jobPrimitiveInputOutput.outputLengthPtr) = 64;

			return E_OK;
		}
		//MD5
		else if (job->jobPrimitiveInfo->primitiveInfo->algorithm.family == 0xff)
		{

			md5(job->jobPrimitiveInputOutput.inputPtr, job->jobPrimitiveInputOutput.inputLength - 1, job->jobPrimitiveInputOutput.outputPtr, &md5_ctx);
			*(job->jobPrimitiveInputOutput.outputLengthPtr) = 16;

			return E_OK;
		}
		else
		{
			Det_ReportError(CRYPTO_MODULE_ID, 0, Crypto_ProcessJob_ID, CRYPTO_E_PARAM_HANDLE);
			return E_NOT_OK;
		}
	}

	if (job->jobPrimitiveInfo->primitiveInfo->service == 0x03)
	{

		if (NULL == job->jobPrimitiveInputOutput.inputPtr)
		{
			Det_ReportError(CRYPTO_MODULE_ID, 0, Crypto_ProcessJob_ID, CRYPTO_E_PARAM_POINTER);
			return E_NOT_OK;
		}

		if (0 == job->jobPrimitiveInputOutput.inputLength)
		{
			Det_ReportError(CRYPTO_MODULE_ID, 0, Crypto_ProcessJob_ID, CRYPTO_E_PARAM_VALUE);
			return E_NOT_OK;
		}

		if (NULL == job->jobPrimitiveInputOutput.outputLengthPtr)
		{
			Det_ReportError(CRYPTO_MODULE_ID, 0, Crypto_ProcessJob_ID, CRYPTO_E_PARAM_POINTER);
			return E_NOT_OK;
		}

		if (job->jobPrimitiveInfo->primitiveInfo->algorithm.family > 0 && job->jobPrimitiveInfo->primitiveInfo->algorithm.family < 0x05 && job->jobPrimitiveInfo->primitiveInfo->algorithm.family != 0xff)
		{
			Det_ReportError(CRYPTO_MODULE_ID, 0, Crypto_ProcessJob_ID, CRYPTO_E_PARAM_HANDLE);
			return E_NOT_OK;
		}

		if (job->jobPrimitiveInfo->primitiveInfo->algorithm.family == 0x13)
		{
		}
		if (job->jobPrimitiveInfo->primitiveInfo->algorithm.family == 0x14)
		{
		}
	}

	if (job->jobPrimitiveInfo->primitiveInfo->service == 0x04)
	{

		if (NULL == job->jobPrimitiveInputOutput.inputPtr)
		{
			Det_ReportError(CRYPTO_MODULE_ID, 0, Crypto_ProcessJob_ID, CRYPTO_E_PARAM_POINTER);
			return E_NOT_OK;
		}

		if (0 == job->jobPrimitiveInputOutput.inputLength)
		{
			Det_ReportError(CRYPTO_MODULE_ID, 0, Crypto_ProcessJob_ID, CRYPTO_E_PARAM_VALUE);
			return E_NOT_OK;
		}

		if (NULL == job->jobPrimitiveInputOutput.outputLengthPtr)
		{
			Det_ReportError(CRYPTO_MODULE_ID, 0, Crypto_ProcessJob_ID, CRYPTO_E_PARAM_POINTER);
			return E_NOT_OK;
		}

		if (job->jobPrimitiveInfo->primitiveInfo->algorithm.family > 0 && job->jobPrimitiveInfo->primitiveInfo->algorithm.family < 0x05 && job->jobPrimitiveInfo->primitiveInfo->algorithm.family != 0xff)
		{
			Det_ReportError(CRYPTO_MODULE_ID, 0, Crypto_ProcessJob_ID, CRYPTO_E_PARAM_HANDLE);
			return E_NOT_OK;
		}

		if (job->jobPrimitiveInfo->primitiveInfo->algorithm.family == 0x13)
		{
		}
		if (job->jobPrimitiveInfo->primitiveInfo->algorithm.family == 0x14)
		{
		}
	}
}
//Job Cancellation Interface
Std_ReturnType Crypto_CancelJob(uint32 objectId, Crypto_JobInfoType *job)
{
	if (FALSE == Cryptoinit)
	{

		Det_ReportError(CRYPTO_MODULE_ID, 0, Crypto_ProcessJob_ID, CRYPTO_E_UNINIT);
		return E_NOT_OK;
	}

	else if (NULL == job)
	{
		Det_ReportError(CRYPTO_MODULE_ID, 0, Crypto_ProcessJob_ID, CRYPTO_E_PARAM_POINTER);
		return E_NOT_OK;
	}

	else if (objectId > Objects)
	{
		Det_ReportError(CRYPTO_MODULE_ID, 0, Crypto_ProcessJob_ID, CRYPTO_E_PARAM_HANDLE);
		return E_NOT_OK;
	}
	else
	{
		return CRYPTO_E_JOB_CANCELED;
	}
}
//Key Setting Interface
Std_ReturnType Crypto_KeyElementSet(uint32 cryptoKeyId, uint32 keyElementId, const uint8 *keyPtr, uint32 keyLength)
{
	uint32 current;
	uint8 keyflag = 0;
	uint8 keyelementflag = 0;
	for (uint32 i = 0; i < 10; i++)
	{
		if (CryptoKeys[i].CryptoKeyId == cryptoKeyId)
		{
			current = i;
			keyflag = 1;
			break;
		}
	}
	/*if(0==keyflag)
	{
		
	}*/

	for (uint32 i = 0; i < 10; i++)
	{
		if (CryptoKeyTypes[i].CryptoKeyTypeId == (CryptoKeys[current].CryptoKeyTypeRef))

		{
			current = i;
			break;
		}
	}
	//check for the keyelement id within the keyelement reference
	for (uint32 i = CryptoKeyTypes[current].CryptoKeyElementRef.StartingKeyElementIDx; i < CryptoKeyTypes[current].CryptoKeyElementRef.EndingKeyElementIDx; i++)
	{
		if (CryptoKeyElements[i].CryptoKeyElementId == keyElementId)

		{
			current = i;
			break;
			keyelementflag = 1;
		}
	}
#if (CRYPTO_DEV_ERROR_DETECT == STD_ON)
	if (FALSE == Cryptoinit)
	{

		Det_ReportError(CRYPTO_MODULE_ID, 0, Crypto_KeyElementSet_ID, CRYPTO_E_UNINIT);
		return E_NOT_OK;
	}
	else if (0 == keyflag)
	{
		Det_ReportError(CRYPTO_MODULE_ID, 0, Crypto_KeyElementSet_ID, CRYPTO_E_PARAM_HANDLE);
		return E_NOT_OK;
	}
	else if (0 == keyelementflag)
	{
		Det_ReportError(CRYPTO_MODULE_ID, 0, Crypto_KeyElementSet_ID, CRYPTO_E_PARAM_HANDLE);
		return E_NOT_OK;
	}
	else if (0 == keyLength)
	{
		Det_ReportError(CRYPTO_MODULE_ID, 0, Crypto_KeyElementSet_ID, CRYPTO_E_PARAM_VALUE);
		return E_NOT_OK;
	}
	else if (NULL == keyPtr)
	{
		Det_ReportError(CRYPTO_MODULE_ID, 0, Crypto_KeyElementSet_ID, CRYPTO_E_PARAM_POINTER);
		return E_NOT_OK;
	}

#endif
}

Std_ReturnType Crypto_KeySetValid(uint32 cryptoKeyId)
{
}

//Key Extraction Interface
Std_ReturnType Crypto_KeyElementGet(uint32 cryptoKeyId, uint32 keyElementId, uint8 *resultPtr, uint32 *resultLengthPtr)
{
}
//Key Copying Interface
Std_ReturnType Crypto_KeyElementCopy(uint32 cryptoKeyId, uint32 keyElementId, uint32 targetCryptoKeyId, uint32 targetKeyElementId)
{
}
Std_ReturnType Crypto_KeyCopy(uint32 cryptoKeyId, uint32 targetCryptoKeyId)
{
}
Std_ReturnType Crypto_KeyElementIdsGet(uint32 cryptoKeyId, uint32 *keyElementIdsPtr, uint32 *keyElementIdsLengthPtr)
{
}
//Key Generation Interface
Std_ReturnType Crypto_RandomSeed(uint32 cryptoKeyId, const uint8 *seedPtr, uint32 seedLength)
{
}
Std_ReturnType Crypto_KeyGenerate(uint32 cryptoKeyId)
{
}
//Key Derivation Interface
Std_ReturnType Crypto_KeyDerive(uint32 cryptoKeyId, uint32 targetCryptoKeyId)
{
}
//Key Exchange Interface
Std_ReturnType Crypto_KeyExchangeCalcPubVal(uint32 cryptoKeyId, uint8 *publicValuePtr, uint32 *publicValueLengthPtr)
{
}
Std_ReturnType Crypto_KeyExchangeCalcSecret(uint32 cryptoKeyId, const uint8 *partnerPublicValuePtr, uint32 partnerPublicValueLength)
{
}
//Certificate Interface
Std_ReturnType Crypto_CertificateParse(uint32 cryptoKeyId)
{
}
Std_ReturnType Crypto_CertificateVerify(uint32 cryptoKeyId, uint32 verifyCryptoKeyId, Crypto_VerifyResultType *verifyPtr)
{
}
//Main function
void Crypto_MainFunction(void)
{
}