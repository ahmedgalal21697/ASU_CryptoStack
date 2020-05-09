
#include "CryIf.h"
#include "Csm_Cbk.h"
#include "Crypto.h"
#include "Det.h"

/*only for this version*/

#define MODULE_ID_CRYIF (uint16)112 // i know this id shall be included in a file called MODULES.h
#define ObjID 1
/*------------------------------------------------------------------------------------------------------------------*/
extern CRYIF_CHANNEL CHANNELS[];
extern CRYIF_KEY KEYS[];
static boolean CryinitDone = FALSE;

/*===========================================================*/
/*TODO Delete the following implementation and use the right symbols */
#define NO_KEY_ELEMENT  1
#define NO_DRIVERS      1

typedef struct
{
    uint32 id;
    uint32 size;
}KeyElementType;

KeyElementType KE[NO_KEY_ELEMENT];
uint32 CDs_keys[NO_DRIVERS][NO_DRIVERS];

boolean validateID(uint32 id)
{
    return FALSE;
}
boolean check_Drivers(uint8 x, uint8 y,uint32  CDs_keys, uint32 cryIfKeyId,uint32 targetCryIfKeyId)
{
    return FALSE;
}
/*==========================================================*/
/*
 SRS_BSW_00101 ---> SWS_CryIf_91000
 SRS_BSW_00358 ---> SWS_CryIf_91000
 */
void CryIf_Init(void)
{
    CryinitDone = TRUE;
    // idk what i can test to make init func fails
};

///////////////////////////////////////////////////////////////////////////////////////////////////

/*SWS_CryIf_91003*/
Std_ReturnType CryIf_ProcessJob(uint32 channelId, Crypto_JobType *job)
{

#if (CRYIF_DEV_ERROR_DETECT == STD_ON)

    if (FALSE == CryinitDone)
    { //[SWS_CryIf_00027]
        Det_ReportError(MODULE_ID_CRYIF, 0, CRYIF_PROCESSJOB_ID, CRYIF_E_UNINIT);

        return E_NOT_OK;
    }
    if (NULL == job)
    { //[SWS_CryIf_00029]
        Det_ReportError(MODULE_ID_CRYIF, 0, CRYIF_PROCESSJOB_ID, CRYIF_E_PARAM_POINTER);

        return E_NOT_OK;
    }

    if (FALSE == validateID(channelId))
    { //[SWS_CryIf_00028]
        Det_ReportError(MODULE_ID_CRYIF, 0, CRYIF_PROCESSJOB_ID, CRYIF_E_PARAM_HANDLE);
        return E_NOT_OK;
    }
#endif

    return Crypto_ProcessJob(CHANNELS[channelId].obj, job); //[SWS_CryIf_00044]
};
/////////////////////////////////////////////////////////////////////////////////////////////////////
/*SWS_CryIf_91014*/
Std_ReturnType CryIf_CancelJob(uint32 channelId, Crypto_JobType *job)
{
#if (CRYIF_DEV_ERROR_DETECT == STD_ON)

    if (FALSE == CryinitDone)
    { //[SWS_CryIf_00129]
        Det_ReportError(MODULE_ID_CRYIF, 0, CRYIF_CANCEL_JOB_ID, CRYIF_E_UNINIT);

        return E_NOT_OK;
    }
    if (NULL == job)
    { //[SWS_CryIf_00131]
        Det_ReportError(MODULE_ID_CRYIF, 0, CRYIF_CANCEL_JOB_ID, CRYIF_E_PARAM_POINTER);

        return E_NOT_OK;
    }

    if (FALSE == validateID(channelId))
    { //[SWS_CryIf_00130]
        Det_ReportError(MODULE_ID_CRYIF, 0, CRYIF_CANCEL_JOB_ID, CRYIF_E_PARAM_HANDLE);
        return E_NOT_OK;
    }
#endif
    Crypto_JobInfoType **Const_to_NON = (Crypto_JobInfoType **)((Crypto_JobInfoType *)&job->jobInfo); //pointerTopointer //cast to avoid warning;
    return Crypto_CancelJob(CHANNELS[channelId].obj, *Const_to_NON);                                  //[SWS_CryIf_00132]
};
/////////////////////////////////////////////////////////////////////////////////////////////////
/* SWS_CryIf_91004*/
Std_ReturnType CryIf_KeyElementSet(uint32 cryIfKeyId, uint32 keyElementId, const uint8 *keyPtr, uint32 keyLength)
{
#if (CRYIF_DEV_ERROR_DETECT == STD_ON)

    if (FALSE == CryinitDone)
    { //[SWS_CryIf_00049]
        Det_ReportError(MODULE_ID_CRYIF, 0, CRYIF_KEY_ELEMENT_SET_ID, CRYIF_E_UNINIT);
        return E_NOT_OK;
    }

    if (FALSE == validateID(cryIfKeyId))
    { //[SWS_CryIf_00050]
        Det_ReportError(MODULE_ID_CRYIF, 0, CRYIF_KEY_ELEMENT_SET_ID, CRYIF_E_PARAM_HANDLE);
        return E_NOT_OK;
    }

    if (0 == keyLength)
    { //[SWS_CryIf_00053]
        Det_ReportError(MODULE_ID_CRYIF, 0, CRYIF_KEY_ELEMENT_SET_ID, CRYIF_E_PARAM_VALUE);
        return E_NOT_OK;
    }

    if (NULL == keyPtr)
    { //[SWS_CryIf_00052]
        Det_ReportError(MODULE_ID_CRYIF, 0, CRYIF_PROCESSJOB_ID, CRYIF_E_PARAM_POINTER);
        return E_NOT_OK;
    }
#endif
    return Crypto_KeyElementSet(KEYS[cryIfKeyId].CryptoKey, keyElementId, keyPtr, keyLength); //[SWS_CryIf_00055]
};
////////////////////////////////////////////////////////////////////////////////////////////////////

/*SWS_CryIf_91005*/
Std_ReturnType CryIf_Key_SetValid(uint32 cryIfKeyId)
{
#if (CRYIF_DEV_ERROR_DETECT == STD_ON)
    if (FALSE == CryinitDone)
    { //[SWS_CryIf_00056]
        Det_ReportError(MODULE_ID_CRYIF, 0, CRYIF_KEY_SET_VALID_ID, CRYIF_E_UNINIT);
        return E_NOT_OK;
    }

    if (FALSE == validateID(cryIfKeyId))
    { //[SWS_CryIf_00057]
        Det_ReportError(MODULE_ID_CRYIF, 0, CRYIF_KEY_SET_VALID_ID, CRYIF_E_PARAM_HANDLE);
        return E_NOT_OK;
    }
#endif
    return Crypto_KeySetValid(KEYS[cryIfKeyId].CryptoKey); //[SWS_CryIf_00058]
};
//////////////////////////////////////////////////////////////////////////////////////////////////////
/* SWS_CryIf_91006 */
Std_ReturnType CryIf_KeyElementGet(uint32 cryIfKeyId, uint32 keyElementId, uint8 *resultPtr, uint32 *resultLengthPtr)
{

#if (CRYIF_DEV_ERROR_DETECT == STD_ON)

    if (FALSE == CryinitDone)
    { //[SWS_CryIf_00059]
        Det_ReportError(MODULE_ID_CRYIF, 0, CRYIF_KEY_ELEMENT_GET_ID, CRYIF_E_UNINIT);

        return E_NOT_OK;
    }
    if (FALSE == validateID(cryIfKeyId))
    { //[SWS_CryIf_00060]
        Det_ReportError(MODULE_ID_CRYIF, 0, CRYIF_KEY_ELEMENT_GET_ID, CRYIF_E_PARAM_HANDLE);
        return E_NOT_OK;
    }
    if (NULL == resultPtr)
    { //[SWS_CryIf_00062]
        Det_ReportError(MODULE_ID_CRYIF, 0, CRYIF_KEY_ELEMENT_GET_ID, CRYIF_E_PARAM_POINTER);

        return E_NOT_OK;
    }
    if (NULL == resultLengthPtr)
    { //[SWS_CryIf_00063]
        Det_ReportError(MODULE_ID_CRYIF, 0, CRYIF_KEY_ELEMENT_GET_ID, CRYIF_E_PARAM_POINTER);

        return E_NOT_OK;
    }

    if (0 == *resultLengthPtr)
    { //[SWS_CryIf_00064]
        Det_ReportError(MODULE_ID_CRYIF, 0, CRYIF_KEY_ELEMENT_GET_ID, CRYIF_E_PARAM_VALUE);
        return E_NOT_OK;
    }

#endif

    return Crypto_KeyElementGet(KEYS[cryIfKeyId].CryptoKey, keyElementId, resultPtr, resultLengthPtr); //[SWS_CryIf_00065]
};
///////////////////////////////////////////////////////////////////////////////////////////////////////

/*SWS_CryIf_91015*/
Std_ReturnType CryIf_KeyElementCopy(uint32 cryIfKeyId, uint32 keyElementId, uint32 targetCryIfKeyId, uint32 targetKeyElementId)
{
#if (CRYIF_DEV_ERROR_DETECT == STD_ON)

    if (FALSE == CryinitDone)
    { //[SWS_CryIf_00110]
        Det_ReportError(MODULE_ID_CRYIF, 0, CRYIF_KEY_ELEMENT_COPY_ID, CRYIF_E_UNINIT);

        return E_NOT_OK;
    }

    if (FALSE == validateID(cryIfKeyId))
    { //[SWS_CryIf_00111]
        Det_ReportError(MODULE_ID_CRYIF, 0, CRYIF_KEY_ELEMENT_COPY_ID, CRYIF_E_PARAM_HANDLE);
        return E_NOT_OK;
    }

    if (FALSE == validateID(targetCryIfKeyId))
    { //[SWS_CryIf_00112]
        Det_ReportError(MODULE_ID_CRYIF, 0, CRYIF_KEY_ELEMENT_COPY_ID, CRYIF_E_PARAM_HANDLE);
        return E_NOT_OK;
    }

    if (KE[keyElementId].size != KE[targetKeyElementId].size)
    { //[SWS_CryIf_00115]
        Det_ReportError(MODULE_ID_CRYIF, 0, CRYIF_KEY_ELEMENT_COPY_ID, CRYIF_E_KEY_SIZE_MISMATCH);

        return E_NOT_OK;
    }
#endif
    if (TRUE == check_Drivers(NO_OF_CHANNELS, NO_OF_CHANNELS, CDs_keys, cryIfKeyId, targetCryIfKeyId))
    { //[SWS_CryIf_00113]
        return Crypto_KeyElementCopy(KEYS[cryIfKeyId].CryptoKey, keyElementId, KEYS[targetCryIfKeyId].CryptoKey, targetKeyElementId);
    }
    //[SWS_CryIf_00114]
    /*
	and the cryIfKeyId and targetCryIfKeyId are located in different Crypto Drivers, 
	the service CryIf_KeyElementCopy() shall copy the provided key element by getting the element 
	with Crypto_<vi>_<ai>_KeyElementGet() and setting the target key element
	via Crypto_<vi>_<ai>_KeyElementSet().
	Q)how can i get the rest of KeyElementGet() ,KeyElementSet() parameters ??
     */
};
///////////////////////////////////////////////////////////////////////////////////////////////////////
/* SWS_CryIf_91016  */
Std_ReturnType CryIf_KeyCopy(uint32 cryIfKeyId, uint32 targetCryIfKeyId)
{
#if (CRYIF_DEV_ERROR_DETECT == STD_ON)

    if (FALSE == CryinitDone)
    { //[SWS_CryIf_00116]
        Det_ReportError(MODULE_ID_CRYIF, 0, CRYIF_KEY_COPY_ID, CRYIF_E_UNINIT);

        return E_NOT_OK;
    }

    if (FALSE == validateID(cryIfKeyId))
    { //[SWS_CryIf_00117]
        Det_ReportError(MODULE_ID_CRYIF, 0, CRYIF_KEY_COPY_ID, CRYIF_E_PARAM_HANDLE);
        return E_NOT_OK;
    }
    if (FALSE == validateID(targetCryIfKeyId))
    { //[SWS_CryIf_00118]
        Det_ReportError(MODULE_ID_CRYIF, 0, CRYIF_KEY_COPY_ID, CRYIF_E_PARAM_HANDLE);
        return E_NOT_OK;
    }
#endif
    return Crypto_KeyCopy(KEYS[cryIfKeyId].CryptoKey, KEYS[targetCryIfKeyId].CryptoKey);
};
///////////////////////////////////////////////////////////////////////////////////////////////////////
/*SWS_CryIf_91007*/
Std_ReturnType CryIf_RandomSeed(uint32 cryIfKeyId, const uint8 *seedPtr, uint32 seedLength)
{

#if (CRYIF_DEV_ERROR_DETECT == STD_ON)
    if (FALSE == CryinitDone)
    { //[SWS_CryIf_00068]
        Det_ReportError(MODULE_ID_CRYIF, 0, CRYIF_RANDOM_SEED_ID, CRYIF_E_UNINIT);

        return E_NOT_OK;
    }
    if (FALSE == validateID(cryIfKeyId))
    { //[SWS_CryIf_00069]
        Det_ReportError(MODULE_ID_CRYIF, 0, CRYIF_RANDOM_SEED_ID, CRYIF_E_PARAM_HANDLE);
        return E_NOT_OK;
    }
    if (NULL == seedPtr)
    { //[SWS_CryIf_00070]
        Det_ReportError(MODULE_ID_CRYIF, 0, CRYIF_RANDOM_SEED_ID, CRYIF_E_PARAM_POINTER);

        return E_NOT_OK;
    }
    if (0 == seedLength)
    { //[SWS_CryIf_00071]
        Det_ReportError(MODULE_ID_CRYIF, 0, CRYIF_RANDOM_SEED_ID, CRYIF_E_PARAM_VALUE);
        return E_NOT_OK;
    }

#endif
    return Crypto_RandomSeed(KEYS[cryIfKeyId].CryptoKey, seedPtr, seedLength); //[SWS_CryIf_00072]
};
///////////////////////////////////////////////////////////////////////////////////////////////////////
/*SWS_CryIf_91008*/
Std_ReturnType CryIf_KeyGenerate(uint32 cryIfKeyId)
{
#if (CRYIF_DEV_ERROR_DETECT == STD_ON)
    if (FALSE == CryinitDone)
    { //[SWS_CryIf_00073]
        Det_ReportError(MODULE_ID_CRYIF, 0, CRYIF_KEY_GENERATE_ID, CRYIF_E_UNINIT);
        return E_NOT_OK;
    }
    if (FALSE == validateID(cryIfKeyId))
    { //[SWS_CryIf_00074]
        Det_ReportError(MODULE_ID_CRYIF, 0, CRYIF_KEY_GENERATE_ID, CRYIF_E_PARAM_HANDLE);
        return E_NOT_OK;
    }

#endif
    return Crypto_KeyGenerate(KEYS[cryIfKeyId].CryptoKey); //[SWS_CryIf_00075]
};
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*SWS_CryIf_91009 */
Std_ReturnType CryIf_KeyDerive(uint32 cryIfKeyId, uint32 targetCryIfKeyId)
{
#if (CRYIF_DEV_ERROR_DETECT == STD_ON)
    if (FALSE == CryinitDone)
    { //[SWS_CryIf_00076]
        Det_ReportError(MODULE_ID_CRYIF, 0, CRYIF_KEY_DERIVE_ID, CRYIF_E_UNINIT);
        return E_NOT_OK;
    }
    if (FALSE == validateID(cryIfKeyId))
    { //[SWS_CryIf_00077]
        Det_ReportError(MODULE_ID_CRYIF, 0, CRYIF_KEY_DERIVE_ID, CRYIF_E_PARAM_HANDLE);
        return E_NOT_OK;
    }

    if (FALSE == validateID(targetCryIfKeyId))
    { //[SWS_CryIf_00122]
        Det_ReportError(MODULE_ID_CRYIF, 0, CRYIF_KEY_DERIVE_ID, CRYIF_E_PARAM_HANDLE);
        return E_NOT_OK;
    }

#endif

    return Crypto_KeyDerive(KEYS[cryIfKeyId].CryptoKey, KEYS[targetCryIfKeyId].CryptoKey); //[SWS_CryIf_00081]
};
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/* SWS_CryIf_91010 */
Std_ReturnType CryIf_KeyExchangeCalcPubVal(uint32 cryIfKeyId, uint8 *publicValuePtr, uint32 *publicValueLengthPtr)
{
#if (CRYIF_DEV_ERROR_DETECT == STD_ON)
    if (FALSE == CryinitDone)
    { //[SWS_CryIf_00082]
        Det_ReportError(MODULE_ID_CRYIF, 0, CRYIF_KEY_EXCHANGE_CALC_PUBVAL_ID, CRYIF_E_UNINIT);
        return E_NOT_OK;
    }
    if (FALSE == validateID(cryIfKeyId))
    { //[SWS_CryIf_00083]
        Det_ReportError(MODULE_ID_CRYIF, 0, CRYIF_KEY_EXCHANGE_CALC_PUBVAL_ID, CRYIF_E_PARAM_HANDLE);
        return E_NOT_OK;
    }

    if (NULL == publicValuePtr)
    { //[SWS_CryIf_00084]
        Det_ReportError(MODULE_ID_CRYIF, 0, CRYIF_KEY_EXCHANGE_CALC_PUBVAL_ID, CRYIF_E_PARAM_POINTER);

        return E_NOT_OK;
    }
    if (NULL == publicValueLengthPtr)
    {                                                                                                 //[SWS_CryIf_00085]
        Det_ReportError(MODULE_ID_CRYIF, 0, CRYIF_KEY_EXCHANGE_CALC_PUBVAL_ID, CRYIF_E_PARAM_POINTER); //

        return E_NOT_OK;
    }
    if (0 == *publicValueLengthPtr)
    { //[SWS_CryIf_00064]
        Det_ReportError(MODULE_ID_CRYIF, 0, CRYIF_KEY_EXCHANGE_CALC_PUBVAL_ID, CRYIF_E_PARAM_VALUE);
        return E_NOT_OK;
    }
#endif

    return Crypto_KeyExchangeCalcPubVal(KEYS[cryIfKeyId].CryptoKey, publicValuePtr, publicValueLengthPtr); //[SWS_CryIf_00087]
};
///////////////////////////////////////////////////////////////////////////////////////////////////////////
//[SWS_CryIf_91011]
Std_ReturnType CryIf_KeyExchangeCalcSecret(uint32 cryIfKeyId, const uint8 *partnerPublicValuePtr, uint32 partnerPublicValueLength)
{
#if (CRYIF_DEV_ERROR_DETECT == STD_ON)
    if (FALSE == CryinitDone)
    { //[SWS_CryIf_00090]
        Det_ReportError(MODULE_ID_CRYIF, 0, CRYIF_KEY_EXCHANGE_CALC_SECRET_ID, CRYIF_E_UNINIT);
        return E_NOT_OK;
    }
    if (FALSE == validateID(cryIfKeyId))
    { //[SWS_CryIf_00091]
        Det_ReportError(MODULE_ID_CRYIF, 0, CRYIF_KEY_EXCHANGE_CALC_SECRET_ID, CRYIF_E_PARAM_HANDLE);
        return E_NOT_OK;
    }

    if (NULL == partnerPublicValuePtr)
    { //[SWS_CryIf_00092]
        Det_ReportError(MODULE_ID_CRYIF, 0, CRYIF_KEY_EXCHANGE_CALC_SECRET_ID, CRYIF_E_PARAM_POINTER);

        return E_NOT_OK;
    }
    if (0 == partnerPublicValueLength)
    { //[SWS_CryIf_00094]
        Det_ReportError(MODULE_ID_CRYIF, 0, CRYIF_KEY_EXCHANGE_CALC_SECRET_ID, CRYIF_E_PARAM_VALUE);

        return E_NOT_OK;
    }

#endif
    return Crypto_KeyExchangeCalcSecret(KEYS[cryIfKeyId].CryptoKey, partnerPublicValuePtr, partnerPublicValueLength); //[SWS_CryIf_00095]
};
/////////////////////////////////////////////////////////////////////////////////////////////////////////
//[SWS_CryIf_91012]
Std_ReturnType CryIf_CertificateParse(uint32 cryIfKeyId)
{
#if (CRYIF_DEV_ERROR_DETECT == STD_ON)
    if (FALSE == CryinitDone)
    { //[SWS_CryIf_00098]
        Det_ReportError(MODULE_ID_CRYIF, 0, CRYIF_CERTIFICATE_PARSE_ID, CRYIF_E_UNINIT);
        return E_NOT_OK;
    }
    if (FALSE == validateID(cryIfKeyId))
    { //[SWS_CryIf_00099]
        Det_ReportError(MODULE_ID_CRYIF, 0, CRYIF_CERTIFICATE_PARSE_ID, CRYIF_E_PARAM_HANDLE);
        return E_NOT_OK;
    }

#endif

    return Crypto_CertificateParse(KEYS[cryIfKeyId].CryptoKey); //[SWS_CryIf_00104]
};
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//[SWS_CryIf_91017]
Std_ReturnType CryIf_CertificateVerify(uint32 cryIfKeyId, uint32 verifyCryIfKeyId, Crypto_VerifyResultType *verifyPtr)
{
#if (CRYIF_DEV_ERROR_DETECT == STD_ON)
    if (FALSE == CryinitDone)
    { //[SWS_CryIf_00123]
        Det_ReportError(MODULE_ID_CRYIF, 0, CRYIF_CERTIFICATE_VERIFY_ID, CRYIF_E_UNINIT);
        return E_NOT_OK;
    }
    if (FALSE == validateID(cryIfKeyId))
    { //[SWS_CryIf_00124]
        Det_ReportError(MODULE_ID_CRYIF, 0, CRYIF_CERTIFICATE_VERIFY_ID, CRYIF_E_PARAM_HANDLE);
        return E_NOT_OK;
    }

    if (FALSE == validateID(verifyCryIfKeyId))
    { //[SWS_CryIf_00125]
        Det_ReportError(MODULE_ID_CRYIF, 0, CRYIF_CERTIFICATE_VERIFY_ID, CRYIF_E_PARAM_HANDLE);
        return E_NOT_OK;
    }

    if (FALSE == check_Drivers(NO_OF_CHANNELS, NO_OF_CHANNELS, CDs_keys, cryIfKeyId, verifyCryIfKeyId))
    { //[SWS_CryIf_00126]
        Det_ReportError(MODULE_ID_CRYIF, 0, CRYIF_CERTIFICATE_VERIFY_ID, CRYIF_E_PARAM_HANDLE);
        return E_NOT_OK;
    }

    if (NULL == verifyPtr)
    { //[SWS_CryIf_00127]
        Det_ReportError(MODULE_ID_CRYIF, 0, CRYIF_CERTIFICATE_VERIFY_ID, CRYIF_E_PARAM_POINTER);

        return E_NOT_OK;
    }

#endif
    return Crypto_CertificateVerify(KEYS[cryIfKeyId].CryptoKey, KEYS[verifyCryIfKeyId].CryptoKey, verifyPtr); //[SWS_CryIf_00128]
};
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
//[SWS_CryIf_91013]
/*void CryIf_CallbackNotification( const Crypto_JobType* job, Std_ReturnType result){
#if (CRYIF_DEV_ERROR_DETECT ==STD_ON)
 if (FALSE==CryinitDone) {//[SWS_CryIf_00107]
Det_ReportError(MODULE_ID_CRYIF,0,CryIf_Call_back_Notification,CRYIF_E_UNINIT); 
}
if ( NULL==job)  {//[SWS_CryIf_00108]
Det_ReportError(MODULE_ID_CRYIF,0,CryIf_Call_back_Notification,CRYIF_E_PARAM_POINTER);
}

#endif
Crypto_JobType **Const_to_NON=(Crypto_JobType**)((Crypto_JobType*)&job);
Csm_CallbackNotification(*Const_to_NON  ,  result );//[SWS_CryIf_00109]

};
 */
