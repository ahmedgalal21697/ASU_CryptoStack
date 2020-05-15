/*
 *  -------------------------------------------------------------------------------------------------------------------
 *  FILE DESCRIPTION
 *  -----------------------------------------------------------------------------------------------------------------*/
/*!        \file  Crypto.c
 *        \brief  MICROSAR Crypto Driver (Crypto)
 *
 *      \details  Implementation of the MICROSAR Crypto Driver (Crypto)
 *
 *********************************************************************************************************************/
/**********************************************************************************************************************
 *  INCLUDES
 *********************************************************************************************************************/

#include "Crypto.h"
#include "CryIf.h"
#include "Det.h"



/*General API*/

static boolean Cryptoinit = FALSE;


/**********************************************************************************************************************
 *  Crypto_Init()
 *********************************************************************************************************************/
/*! \brief         Initializes the Crypto Driver.
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *********************************************************************************************************************/

void Crypto_Init(void)
{

    Cryptoinit = TRUE;

	if(FALSE==Cryptoinit)
	{
	    Det_ReportError(CRYPTO_MODULE_ID,
	                    0,
	                    Crypto_Init_ID,
	                    CRYPTO_E_INIT_FAILED);
	}
	/*SWS_Crypto_00045 satisfied */
}

/**********************************************************************************************************************
 *  Crypto_GetVersionInfo()
 *********************************************************************************************************************/
/*! \brief         Returns the version information of this module.
 *  \param[in]     versioninfo             Pointer to where to store the version information of this module.
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *********************************************************************************************************************/
void Crypto_GetVersionInfo(Std_VersionInfoType *versioninfo)
{
    if(NULL==versioninfo)
    {
        Det_ReportError(CRYPTO_MODULE_ID,
                        0,
                        Crypto_GetVersionInfo_ID,
                        CRYPTO_E_PARAM_POINTER);
    }
    /*SWS_Crypto_00047 satisfied*/
}

/**********************************************************************************************************************
 *  Crypto_ProcessJob()
 *********************************************************************************************************************/
/*! \brief         Performs the crypto primitive, that is configured in the job parameter.
 *  \param[in]     objectId                Holds the identifier of the Crypto Driver Object.
 *  \param[in,out] job                     Pointer to the configuration of the job. Contains structures with user and
 *                                         primitive relevant information.
 *  \return        E_OK                    Request successful.
 *  \return        E_NOT_OK                Request failed.
 *  \return        CRYPTO_E_BUSY           Request failed, Crypto Driver Object is busy.
 *  \return        CRYPTO_E_KEY_NOT_VALID  Request failed, the key is not valid.
 *  \return        CRYPTO_E_KEY_SIZE_MISMATCH Request failed, a key element has the wrong size.
 *  \return        CRYPTO_E_ENTROPY_EXHAUSTION Request failed, the entropy is exhausted.
 *  \return        CRYPTO_E_COUNTER_OVERFLOW The counter is overflowed.
 *  \return        CRYPTO_E_QUEUE_FULL     Request failed, the queue is full.
 *  \return        CRYPTO_E_SMALL_BUFFER   Request failed, the provided buffer is too small to store the result.
 *  \return        CRYPTO_E_JOB_CANCELED   The service request failed because the synchronous Job has been canceled.
 *  \reentrant     TRUE
 *  \synchronous   Depends on the job configuration
 *********************************************************************************************************************/
Std_ReturnType Crypto_ProcessJob(uint32 objectId,
                                 Crypto_JobType *job)
{
    Std_ReturnType ret =E_NOT_OK;
	if (FALSE == Cryptoinit)
	{

		Det_ReportError(CRYPTO_MODULE_ID,
		                0,
		                Crypto_ProcessJob_ID,
		                CRYPTO_E_UNINIT);
		ret= E_NOT_OK;
	}
	/*SWS_Crypto_00057 satisfied*/

	else if (NULL == job)
	{
		Det_ReportError(CRYPTO_MODULE_ID,
		                0,
		                Crypto_ProcessJob_ID,
		                CRYPTO_E_PARAM_POINTER);
		ret= E_NOT_OK;
	}
	/*SWS_Crypto_00058 satisfied*/
	else if (((job->jobPrimitiveInfo->primitiveInfo->service) > 0x0b) | ((job->jobPrimitiveInfo->primitiveInfo->service) < 0x00))
	{
		Det_ReportError(CRYPTO_MODULE_ID,
		                0,
		                Crypto_ProcessJob_ID,
		                CRYPTO_E_PARAM_HANDLE);
		ret= E_NOT_OK;
	}
	/*SWS_Crypto_00064 satisfied*/


	/*Hash*/

	if (CRYPTO_HASH==(job->jobPrimitiveInfo->primitiveInfo->service) )
	{
	    SHA1_CTX sha1_ctx;
	    SHA224_CTX sha224_ctx;
	    SHA256_CTX sha256_ctx;
	    SHA384_CTX sha384_ctx;
	    SHA512_CTX sha512_ctx;
	    MD5_CTX md5_ctx;

		if (NULL == (job->jobPrimitiveInputOutput.inputPtr))
		{
			Det_ReportError(CRYPTO_MODULE_ID,
			                0,
			                Crypto_ProcessJob_ID,
			                CRYPTO_E_PARAM_POINTER);
			ret= E_NOT_OK;
		}
		/*SWS_Crypto_00059 satisfied*/

		else if (0 == (job->jobPrimitiveInputOutput.inputLength))
		{
			Det_ReportError(CRYPTO_MODULE_ID,
			                0,
			                Crypto_ProcessJob_ID,
			                CRYPTO_E_PARAM_VALUE);
			ret= E_NOT_OK;
		}
		/*SWS_Crypto_00142 satisfied*/

		else if (NULL == (job->jobPrimitiveInputOutput.outputLengthPtr))
		{
			Det_ReportError(CRYPTO_MODULE_ID,
			                0,
			                Crypto_ProcessJob_ID,
			                CRYPTO_E_PARAM_POINTER);
			ret= E_NOT_OK;
		}
		/*SWS_Crypto_00059 satisfied*/
		/*TODO*/
		if(0==*(job->jobPrimitiveInputOutput.outputLengthPtr))
		{
				Det_ReportError(CRYPTO_MODULE_ID,0,Crypto_ProcessJob_ID,   CRYPTO_E_PARAM_VALUE );
			return E_NOT_OK;
		}


		/*SHA1*/
		if (CRYPTO_ALGOFAM_SHA1==(job->jobPrimitiveInfo->primitiveInfo->algorithm.family ))
		{
		     /*TODO*/
			sha1((job->jobPrimitiveInputOutput.inputPtr),
			     (job->jobPrimitiveInputOutput.inputLength) ,
			     job->jobPrimitiveInputOutput.outputPtr,
			     &sha1_ctx);
			*(job->jobPrimitiveInputOutput.outputLengthPtr) = 20;
			ret= E_OK;
		}
		/*SHA224*/
		else if (CRYPTO_ALGOFAM_SHA2_224==(job->jobPrimitiveInfo->primitiveInfo->algorithm.family ))
		{
		    /*TODO*/
			sha224(job->jobPrimitiveInputOutput.inputPtr,
			       job->jobPrimitiveInputOutput.inputLength ,
			       job->jobPrimitiveInputOutput.outputPtr,
			       &sha224_ctx);
			*(job->jobPrimitiveInputOutput.outputLengthPtr) = 28;

			ret= E_OK;
		}
		/*SHA256*/
		else if (CRYPTO_ALGOFAM_SHA2_256==(job->jobPrimitiveInfo->primitiveInfo->algorithm.family ))
		{
		    /*TODO*/
			sha256(job->jobPrimitiveInputOutput.inputPtr,
			       job->jobPrimitiveInputOutput.inputLength,
			       job->jobPrimitiveInputOutput.outputPtr,
			       &sha256_ctx);
			*(job->jobPrimitiveInputOutput.outputLengthPtr) = 32;

			ret= E_OK;
		}
		/*SHA384*/
		else if (CRYPTO_ALGOFAM_SHA2_384==(job->jobPrimitiveInfo->primitiveInfo->algorithm.family ))
		{

			sha384(job->jobPrimitiveInputOutput.inputPtr,
			       job->jobPrimitiveInputOutput.inputLength,
			       job->jobPrimitiveInputOutput.outputPtr,
			       &sha384_ctx);
			*(job->jobPrimitiveInputOutput.outputLengthPtr) = 48;

			ret=E_OK;
		}
		/*SHA512*/
		else if (CRYPTO_ALGOFAM_SHA2_512==(job->jobPrimitiveInfo->primitiveInfo->algorithm.family ))
		{
		    /*TODO*/
			sha512(job->jobPrimitiveInputOutput.inputPtr,
			       job->jobPrimitiveInputOutput.inputLength,
			       job->jobPrimitiveInputOutput.outputPtr,
			       &sha512_ctx);
			*(job->jobPrimitiveInputOutput.outputLengthPtr) = 64;

			ret= E_OK;
		}
		/*MD5*/
		else if (CRYPTO_ALGOFAM_CUSTOM==(job->jobPrimitiveInfo->primitiveInfo->algorithm.family ))
		{
		    /*TODO*/
			md5(job->jobPrimitiveInputOutput.inputPtr,
			    job->jobPrimitiveInputOutput.inputLength,
			    job->jobPrimitiveInputOutput.outputPtr,
			    &md5_ctx);
			*(job->jobPrimitiveInputOutput.outputLengthPtr) = 16;

			ret= E_OK;
		}
		else
		{
			Det_ReportError(CRYPTO_MODULE_ID,
			                0,
			                Crypto_ProcessJob_ID,
			                CRYPTO_E_PARAM_HANDLE);
			ret= E_NOT_OK;
		}
		/*SWS_Crypto_00067 satisfied*/
	}

	if (CRYPTO_ENCRYPT==(job->jobPrimitiveInfo->primitiveInfo->service ))
	{

        if (NULL == (job->jobPrimitiveInputOutput.inputPtr))
        {
            Det_ReportError(CRYPTO_MODULE_ID,
                            0,
                            Crypto_ProcessJob_ID,
                            CRYPTO_E_PARAM_POINTER);
            ret= E_NOT_OK;
        }
        /*SWS_Crypto_00059 satisfied*/

        else if (0 == (job->jobPrimitiveInputOutput.inputLength))
        {
            Det_ReportError(CRYPTO_MODULE_ID,
                            0,
                            Crypto_ProcessJob_ID,
                            CRYPTO_E_PARAM_VALUE);
            ret= E_NOT_OK;
        }
        /*SWS_Crypto_00142 satisfied*/

        else if (NULL == (job->jobPrimitiveInputOutput.outputLengthPtr))
        {
            Det_ReportError(CRYPTO_MODULE_ID,
                            0,
                            Crypto_ProcessJob_ID,
                            CRYPTO_E_PARAM_POINTER);
            ret= E_NOT_OK;
        }
        /*SWS_Crypto_00059 satisfied*/



		 if (CRYPTO_ALGOFAM_3DES==(job->jobPrimitiveInfo->primitiveInfo->algorithm.family ))
		 {
		 }
		 else if (CRYPTO_ALGOFAM_AES==(job->jobPrimitiveInfo->primitiveInfo->algorithm.family ))
		 {
		 }
		 else
		 {
		      Det_ReportError(CRYPTO_MODULE_ID,
		                      0,
		                      Crypto_ProcessJob_ID,
		                      CRYPTO_E_PARAM_HANDLE);
		      ret= E_NOT_OK;
		 }
		 /*SWS_Crypto_00067 satisfied*/
	}

	if ( CRYPTO_DECRYPT==(job->jobPrimitiveInfo->primitiveInfo->service ))
	{


        if (NULL == (job->jobPrimitiveInputOutput.inputPtr))
        {
            Det_ReportError(CRYPTO_MODULE_ID,
                            0,
                            Crypto_ProcessJob_ID,
                            CRYPTO_E_PARAM_POINTER);
            ret= E_NOT_OK;
        }
        /*SWS_Crypto_00059 satisfied*/

        else if (0 == (job->jobPrimitiveInputOutput.inputLength))
        {
            Det_ReportError(CRYPTO_MODULE_ID,
                            0,
                            Crypto_ProcessJob_ID,
                            CRYPTO_E_PARAM_VALUE);
            ret= E_NOT_OK;
        }
        /*SWS_Crypto_00142 satisfied*/

        else if (NULL == (job->jobPrimitiveInputOutput.outputLengthPtr))
        {
            Det_ReportError(CRYPTO_MODULE_ID,
                            0,
                            Crypto_ProcessJob_ID,
                            CRYPTO_E_PARAM_POINTER);
            ret= E_NOT_OK;
        }
        /*SWS_Crypto_00059 satisfied*/



         if (CRYPTO_ALGOFAM_3DES==(job->jobPrimitiveInfo->primitiveInfo->algorithm.family ))
         {
         }
         else if (CRYPTO_ALGOFAM_AES==(job->jobPrimitiveInfo->primitiveInfo->algorithm.family ))
         {
         }
         else
         {
              Det_ReportError(CRYPTO_MODULE_ID,
                              0,
                              Crypto_ProcessJob_ID,
                              CRYPTO_E_PARAM_HANDLE);
              ret= E_NOT_OK;
         }
         /*SWS_Crypto_00067 satisfied*/
	}
	return ret;
}
/*Job Cancellation Interface*/


/**********************************************************************************************************************
 *  Crypto_CancelJob()
 *********************************************************************************************************************/
/*! \brief         This interface removes the provided job from the queue and cancels the processing of the job if possible.
 *  \param[in]     objectId                Holds the identifier of the Crypto Driver Object.
 *  \param[in,out] job                     Pointer to the configuration of the job. Contains structures with user and
 *                                         primitive relevant information.
 *  \return        E_OK                    Request successful, job has been removed
 *  \return        E_NOT_OK                Request Failed, job couldn't be removed.
 *  \return        CRYPTO_E_JOB_CANCELED   The job has been cancelled but is still processed. No results will be returned to the application.
 *  \reentrant     Reentrant, but not for same Crypto Driver Object
 *  \synchronous   TRUE
 *********************************************************************************************************************/

Std_ReturnType Crypto_CancelJob(uint32 objectId, Crypto_JobInfoType *job)
{
    Std_ReturnType ret=E_NOT_OK;

	if (FALSE == Cryptoinit)
	{

		Det_ReportError(CRYPTO_MODULE_ID,
		                0,
		                Crypto_ProcessJob_ID,
		                CRYPTO_E_UNINIT);
		ret= E_NOT_OK;

	}
	/*SWS_Crypto_00123 satisfied*/

	else if (NULL == job)
	{
		Det_ReportError(CRYPTO_MODULE_ID,
		                0,
		                Crypto_ProcessJob_ID,
		                CRYPTO_E_PARAM_POINTER);
		ret= E_NOT_OK;
	}
	/*SWS_Crypto_00125 satisfied*/

	else if (objectId > Objects)
	{
		Det_ReportError(CRYPTO_MODULE_ID,
		                0,
		                Crypto_ProcessJob_ID,
		                CRYPTO_E_PARAM_HANDLE);
		ret= E_NOT_OK;
	}
	/*SWS_Crypto_00124 satisfied*/
	else
	{
		ret= CRYPTO_E_JOB_CANCELED;
	}
	return ret;
}
/*Key Setting Interface*/

/**********************************************************************************************************************
 *  Crypto_KeyElementSet()
 *********************************************************************************************************************/
/*! \brief         Sets the given key element bytes to the key identified by cryptoKeyId.
 *  \param[in]     cryptoKeyId             Holds the identifier of the key whose key element shall be set.
 *  \param[in]     keyElementId            Holds the identifier of the key element which shall be set.
 *  \param[in]     keyPtr                  Holds the pointer to the key data which shall be set as key element.
 *  \param[in]     keyLength               Contains the length of the key element in bytes.
 *  \return        E_OK                    Request successful.
 *  \return        E_NOT_OK                Request failed.
 *  \return        CRYPTO_E_BUSY           Request failed, Crypto Driver Object is busy.
 *  \return        CRYPTO_E_KEY_WRITE_FAIL Request failed because write access was denied
 *  \return        CRYPTO_E_KEY_NOT_AVAILABLE Request failed because the key is not available.
 *  \return        CRYPTO_E_KEY_SIZE_MISMATCH Request failed, key element size does not match size of provided data.
 *  \reentrant     FALSE
 *  \synchronous   TRUE
 *********************************************************************************************************************/
Std_ReturnType Crypto_KeyElementSet(uint32 cryptoKeyId, uint32 keyElementId, const uint8 *keyPtr, uint32 keyLength)
{
    Std_ReturnType ret =E_NOT_OK;
	uint32 current=0;
	uint8 keyflag = 0;
	uint8 keyelementflag = 0;
	for (uint32 i = 0; i < Keys; i++)
	{
		if (CryptoKeys[i].CryptoKeyId == cryptoKeyId)
		{
			current = i;
			keyflag = 1;
			break;
		}
	}


	for (uint32 i = 0; i < KeyTypes; i++)
	{
		if (CryptoKeyTypes[i].CryptoKeyTypeId == (CryptoKeys[current].CryptoKeyTypeRef))

		{
			current = i;
			break;
		}
	}
	/*check for the keyelement id within the keyelement reference*/
	for (uint32 i = CryptoKeyTypes[current].CryptoKeyElementRef.StartingKeyElementIDx;
	        i < CryptoKeyTypes[current].CryptoKeyElementRef.EndingKeyElementIDx;
	        i++)
	{
		if (CryptoKeyElements[i].CryptoKeyElementId == keyElementId)

		{
			current = i;
			keyelementflag = 1;
			break;

		}
	}
#if (CRYPTO_DEV_ERROR_DETECT == STD_ON)
	if (FALSE == Cryptoinit)
	{

		Det_ReportError(CRYPTO_MODULE_ID,
		                0,
		                Crypto_KeyElementSet_ID,
		                CRYPTO_E_UNINIT);
		ret= E_NOT_OK;
	}
	/*SWS_Crypto_00075 satisfied*/
	else if (0 == keyflag)
	{
		Det_ReportError(CRYPTO_MODULE_ID,
		                0,
		                Crypto_KeyElementSet_ID,
		                CRYPTO_E_PARAM_HANDLE);
		ret= E_NOT_OK;
	}
	/*SWS_Crypto_00076 satisfied*/
	else if (0 == keyelementflag)
	{
		Det_ReportError(CRYPTO_MODULE_ID,
		                0,
		                Crypto_KeyElementSet_ID,
		                CRYPTO_E_PARAM_HANDLE);
		ret= E_NOT_OK;
	}
	/*SWS_Crypto_00077 satisfied*/
	else if (0 == keyLength)
	{
		Det_ReportError(CRYPTO_MODULE_ID,
		                0,
		                Crypto_KeyElementSet_ID,
		                CRYPTO_E_PARAM_VALUE);
		ret= E_NOT_OK;
	}
	/*SWS_Crypto_00079 satisfied*/
	else if (NULL == keyPtr)
	{
		Det_ReportError(CRYPTO_MODULE_ID,
		                0,
		                Crypto_KeyElementSet_ID,
		                CRYPTO_E_PARAM_POINTER);
		ret= E_NOT_OK;
	}
	/*SWS_Crypto_00078*/

#endif
	return ret;
}

/**********************************************************************************************************************
 *  Crypto_KeySetValid()
 *********************************************************************************************************************/
/*! \brief         Sets the key state of the key identified by cryptoKeyId to valid.
 *  \param[in]     cryptoKeyId             Holds the identifier of the key which shall be set to valid.
 *  \return        E_OK                    Request successful.
 *  \return        E_NOT_OK                Request failed.
 *  \return        CRYPTO_E_BUSY           Request failed, Crypto Driver Object is busy.
 *  \reentrant     TRUE
 *  \synchronous   FALSE
 *********************************************************************************************************************/
Std_ReturnType Crypto_KeySetValid(uint32 cryptoKeyId)
{ Std_ReturnType ret=E_NOT_OK;
return ret;
}

/*Key Extraction Interface*/

/**********************************************************************************************************************
 *  Crypto_KeyElementGet()
 *********************************************************************************************************************/
/*! \brief         This interface shall be used to get a key element of the key identified by the cryptoKeyId and
                   store the key element in the memory location pointed by the result pointer.
                   If the actual key element is directly mapped to flash memory, there could be a bigger delay
                   when calling this function (synchronous operation).
 *  \param[in]     cryptoKeyId             Holds the identifier of the key whose key element shall be returned.
 *  \param[in]     keyElementId            Holds the identifier of the key element which shall be returned.
 *  \param[in,out] resultLengthPtr         Holds a pointer to a memory location in which the length information is stored.
 *                                         On calling this function this parameter shall contain the size of the buffer provided by resultPtr.
 *                                         If the key element is configured to allow partial access,
 *                                         this parameter contains the amount of data which should be read from the key element.
 *                                         The size may not be equal to the size of the provided buffer anymore.
 *                                         When the request has finished, the amount of data that has been stored shall be stored.
 *  \return        E_OK                    Request successful.
 *  \return        E_NOT_OK                Request failed.
 *  \return        CRYPTO_E_BUSY           Request failed, Crypto Driver Object is busy.
 *  \return        CRYPTO_E_KEY_NOT_AVAILABLE Request failed, the requested key element is not available
 *  \return        CRYPTO_E_KEY_READ_FAIL Request failed because read access was denied
 *  \return        CRYPTO_E_SMALL_BUFFER   Request failed, the provided buffer is too small to store the result.
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *********************************************************************************************************************/
Std_ReturnType Crypto_KeyElementGet(uint32 cryptoKeyId, uint32 keyElementId, uint8 *resultPtr, uint32 *resultLengthPtr)
{
    Std_ReturnType ret=E_NOT_OK;
    return ret;
}
/*Key Copying Interface*/

/**********************************************************************************************************************
 *  Crypto_KeyElementCopy()
 *********************************************************************************************************************/
/*! \brief         Copies a key element to another key element in the same crypto driver.
 *                 If the actual key element is directly mapped to flash memory,
 *                 there could be a bigger delay when calling this function (synchronous operation)
 *  \param[in]     cryptoKeyId             Holds the identifier of the key whose key element shall be the source element.
 *  \param[in]     keyElementId            Holds the identifier of the key element which shall be the source for the copy operation.
 *  \param[in]     targetCryptoKeyId       Holds the identifier of the key whose key element shall be the destination element.
 *  \param[in]     targetKeyElementId      Holds the identifier of the key element which shall be the destination for the copy operation.
 *  \return        E_OK                    Request successful.
 *  \return        E_NOT_OK                Request failed.
 *  \return        CRYPTO_E_BUSY           Request failed, Crypto Driver Object is busy.
 *  \return        CRYPTO_E_KEY_NOT_AVAILABLE Request failed, the requested key element is not available
 *  \return        CRYPTO_E_KEY_READ_FAIL Request failed because read access was denied
 *  \return        CRYPTO_E_KEY_WRITE_FAIL Request failed, not allowed to write key element.
 *  \return        CRYPTO_E_KEY_SIZE_MISMATCH Request failed, key element sizes are not compatible.
 *  \reentrant     TRUE, but not for the same cryptoKeyId
 *  \synchronous   TRUE
 *********************************************************************************************************************/
Std_ReturnType Crypto_KeyElementCopy(uint32 cryptoKeyId, uint32 keyElementId, uint32 targetCryptoKeyId, uint32 targetKeyElementId)
{
    Std_ReturnType ret=E_NOT_OK;
        return ret;

}


/**********************************************************************************************************************
 *  Crypto_KeyCopy()
 *********************************************************************************************************************/
/*! \brief         Copies a key with all its elements to another key in the same crypto driver.
 *                 If the actual key element is directly mapped to flash memory,
 *                 there could be a bigger delay when calling this function (synchronous operation)
 *  \param[in]     cryptoKeyId             Holds the identifier of the key whose key element shall be the source element
 *  \param[in]     targetCryptoKeyId       Holds the identifier of the key whose key element shall be the destination element.
 *  \return        E_OK                    Request successful.
 *  \return        E_NOT_OK                Request failed.
 *  \return        CRYPTO_E_BUSY           Request failed, Crypto Driver Object is busy.
 *  \return        CRYPTO_E_KEY_NOT_AVAILABLE Request failed, the requested key element is not available
 *  \return        CRYPTO_E_KEY_READ_FAIL Request failed because read access was denied
 *  \return        CRYPTO_E_KEY_WRITE_FAIL Request failed, not allowed to write key element.
 *  \return        CRYPTO_E_KEY_SIZE_MISMATCH Request failed, key element sizes are not compatible.
 *  \reentrant     TRUE, but not for the same cryptoKeyId
 *  \synchronous   TRUE
 *********************************************************************************************************************/
Std_ReturnType Crypto_KeyCopy(uint32 cryptoKeyId, uint32 targetCryptoKeyId)
{
    Std_ReturnType ret=E_NOT_OK;
        return ret;

}


/**********************************************************************************************************************
 *  Crypto_KeyElementIdsGet()
 *********************************************************************************************************************/
/*! \brief         Used to retrieve information which key elements are available in a given key.
 *  \param[in]     cryptoKeyId             Holds the identifier of the key whose available element ids shall be exported.
 *  \param[in]     keyElementIdsLengthPtr  Holds a pointer to the memory location in which the number of key elements in the given key is stored.
 *                                         On calling this function, this parameter shall contain the size of the buffer provided by keyElementIdsPtr.
 *                                         When the request has finished, the actual number of key elements shall be stored.
 *  \param[out]    keyElementIdsPtr        Contains the pointer to the array where the ids of the key elements shall be stored.
 *  \return        E_OK                    Request successful.
 *  \return        E_NOT_OK                Request failed.
 *  \return        CRYPTO_E_BUSY           Request failed, Crypto Driver Object is busy.
 *  \return        CRYPTO_E_SMALL_BUFFER   The provided buffer is too small to store the result
 *  \reentrant     TRUE, but not for the same cryptoKeyId
 *  \synchronous   TRUE
 *********************************************************************************************************************/
Std_ReturnType Crypto_KeyElementIdsGet(uint32 cryptoKeyId, uint32 *keyElementIdsPtr, uint32 *keyElementIdsLengthPtr)
{
    Std_ReturnType ret=E_NOT_OK;
        return ret;

}
/*Key Generation Interface*/

/**********************************************************************************************************************
 *  Crypto_RandomSeed()
 *********************************************************************************************************************/
/*! \brief         This function generates the internal seed state using the provided entropy source.
 *                 Furthermore, this function can be used to update the seed state with new entropy
 *  \param[in]     cryptoKeyId             Holds the identifier of the key for which a new seed shall be generated.
 *  \param[in]     seedPtr                 Holds a pointer to the memory location which contains the data to feed the seed.
 *  \param[in]     seedLength              Contains the length of the seed in bytes.
 *  \return        E_OK                    Request successful.
 *  \return        E_NOT_OK                Request failed.
 *  \reentrant     TRUE, but not for the same cryptoKeyId
 *  \synchronous   TRUE
 *********************************************************************************************************************/
Std_ReturnType Crypto_RandomSeed(uint32 cryptoKeyId, const uint8 *seedPtr, uint32 seedLength)
{
    Std_ReturnType ret=E_NOT_OK;
        return ret;

}


/**********************************************************************************************************************
 *  Crypto_KeyGenerate()
 *********************************************************************************************************************/
/*! \brief         Generates new key material store it in the key identified by cryptoKeyId.
 *  \param[in]     cryptoKeyId             Holds the identifier of the key which is to be updated with the generated value.
 *  \return        E_OK                    Request successful.
 *  \return        E_NOT_OK                Request failed.
 *  \return        CRYPTO_E_BUSY           Request failed, Crypto Driver Object is busy.
 *  \reentrant     TRUE, but not for the same cryptoKeyId
 *  \synchronous   TRUE
 *********************************************************************************************************************/
Std_ReturnType Crypto_KeyGenerate(uint32 cryptoKeyId)
{
    Std_ReturnType ret=E_NOT_OK;
        return ret;

}

/*Key Derivation Interface*/

/**********************************************************************************************************************
 *  Crypto_KeyDerive()
 *********************************************************************************************************************/
/*! \brief         Derives a new key by using the key elements in the given key identified by the cryptoKeyId.
 *                 The given key contains the key elements for the password, salt.
 *                 The derived key is stored in the key element with the id 1 of the key identified by targetCryptoKeyId.
 *                 The number of iterations is given in the key element CRYPTO_KE_KEYDERIVATION_ITERATIONS.
 *  \param[in]     cryptoKeyId             Holds the identifier of the key which is used for key derivation.
 *  \param[in]     targetCryptoKeyId       Holds the identifier of the key which is used to store the derived key.
 *  \return        E_OK                    Request successful.
 *  \return        E_NOT_OK                Request failed.
 *  \return        CRYPTO_E_BUSY           Request failed, Crypto Driver Object is busy.
 *  \reentrant     TRUE, but not for the same cryptoKeyId
 *  \synchronous   TRUE
 *********************************************************************************************************************/
Std_ReturnType Crypto_KeyDerive(uint32 cryptoKeyId, uint32 targetCryptoKeyId)
{
    Std_ReturnType ret=E_NOT_OK;
        return ret;

}
/*Key Exchange Interface*/


/**********************************************************************************************************************
 *  Crypto_KeyExchangeCalcPubVal()
 *********************************************************************************************************************/
/*! \brief         Calculates the public value for the key exchange
 *                 and stores the public key in the memory location pointed by the public value pointer.
 *  \param[in]     cryptoKeyId             Holds the identifier of the key which shall be used for the key exchange protocol.
 *  \param[in,out] publicValueLengthPtr    Holds a pointer to the memory location in which the public value length information is stored.
 *                                         On calling this function, this parameter shall contain the size of the buffer provided by publicValuePtr.
 *                                         When the request has finished, the actual length of the returned value shall be stored.
 *  \param[out]    publicValuePtr          Contains the pointer to the data where the public value shall be stored.
 *  \return        E_OK                    Request successful.
 *  \return        E_NOT_OK                Request failed.
 *  \return        CRYPTO_E_BUSY           Request failed, Crypto Driver Object is busy.
 *  \return        CRYPTO_E_SMALL_BUFFER   Request failed, the provided buffer is too small to store the result.
 *  \reentrant     TRUE, but not for the same cryptoKeyId
 *  \synchronous   TRUE
 *********************************************************************************************************************/
Std_ReturnType Crypto_KeyExchangeCalcPubVal(uint32 cryptoKeyId, uint8 *publicValuePtr, uint32 *publicValueLengthPtr)
{
    Std_ReturnType ret=E_NOT_OK;
        return ret;

}

/**********************************************************************************************************************
 *  Crypto_KeyExchangeCalcSecret()
 *********************************************************************************************************************/
/*! \brief         Calculates the shared secret key for the key exchange with the key material of the key identified by the cryptoKeyId and the partner public key.
 *                 The shared secret key is stored as a key element in the same key.
 *  \param[in]     cryptoKeyId             Holds the identifier of the key which shall be used for the key exchange protocol.
 *  \param[in]     partnerPublicValuePtr   Holds the pointer to the memory location which contains the partner's public value.
 *  \param[in]     partnerPublicValueLength Contains the length of the partner's public value in bytes.
 *  \return        E_OK                    Request successful.
 *  \return        E_NOT_OK                Request failed.
 *  \return        CRYPTO_E_BUSY           Request failed, Crypto Driver Object is busy.
 *  \return        CRYPTO_E_SMALL_BUFFER   Request failed, the provided buffer is too small to store the result.
 *  \reentrant     TRUE, but not for the same cryptoKeyId
 *  \synchronous   TRUE
 *********************************************************************************************************************/
Std_ReturnType Crypto_KeyExchangeCalcSecret(uint32 cryptoKeyId, const uint8 *partnerPublicValuePtr, uint32 partnerPublicValueLength)
{
    Std_ReturnType ret=E_NOT_OK;
        return ret;

}
/*Certificate Interface*/

/**********************************************************************************************************************
 *  Crypto_CertificateParse()
 *********************************************************************************************************************/
/*! \brief         Parses the certificate data stored in the key element CRYPTO_KE_CERT_DATA
 *                 and fills the key elements CRYPTO_KE_CERT_SIGNEDDATA, CRYPTO_KE_CERT_PARSEDPUBLICKEY and CRYPTO_KE_CERT_SIGNATURE.
 *  \param[in]     cryptoKeyId             Holds the identifier of the key which shall be parsed.
 *  \return        E_OK                    Request successful.
 *  \return        E_NOT_OK                Request failed.
 *  \return        CRYPTO_E_BUSY           Request failed, Crypto Driver Object is busy.
 *  \reentrant     TRUE, but not for the same cryptoKeyId
 *  \synchronous   TRUE
 *********************************************************************************************************************/

Std_ReturnType Crypto_CertificateParse(uint32 cryptoKeyId)
{
    Std_ReturnType ret=E_NOT_OK;
        return ret;

}

/**********************************************************************************************************************
 *  Crypto_CertificateVerify()
 *********************************************************************************************************************/
/*! \brief         Verifies the certificate stored in the key referenced by cryptoValidateKeyId with the certificate stored in the key referenced by cryptoKeyId.
 *  \param[in]     cryptoKeyId             Holds the identifier of the key which shall be used to validate the certificate.
 *  \param[in]     verifyCryptoKeyId       Holds the identifier of the key contain.
 *  \param[out]    verifyPtr               Holds a pointer to the memory location which will contain the result of the certificate verification.
 *  \return        E_OK                    Request successful.
 *  \return        E_NOT_OK                Request failed.
 *  \return        CRYPTO_E_BUSY           Request failed, Crypto Driver Object is busy.
 *  \reentrant     TRUE, but not for the same cryptoKeyId
 *  \synchronous   TRUE
 *********************************************************************************************************************/

Std_ReturnType Crypto_CertificateVerify(uint32 cryptoKeyId, uint32 verifyCryptoKeyId, Crypto_VerifyResultType *verifyPtr)
{
    Std_ReturnType ret=E_NOT_OK;
        return ret;

}
/*Main function*/


/**********************************************************************************************************************
 *  Crypto_MainFunction()
 *********************************************************************************************************************/
/*! \brief         If asynchronous job processing is configured and there are job queues, the function is called cyclically to process queued jobs.

 *********************************************************************************************************************/
void Crypto_MainFunction(void)
{
}
