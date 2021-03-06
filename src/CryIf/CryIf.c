
#include "CryIf.h"
#include "Csm_Cbk.h"
#include "Crypto.h"
#include "Det.h"


/**********************************************************************************************************************
 *  LOCAL CONSTANT MACROS
 *********************************************************************************************************************/
#define ObjID 1
#define  minR  1
#define  maxR  4294967295
/**********************************************************************************************************************
 *  LOCAL FUNCTION MACROS
 *********************************************************************************************************************/


/**********************************************************************************************************************
 *  GLOBAL DATA
 *********************************************************************************************************************/

static boolean  Init_Done=FALSE;

/**********************************************************************************************************************
 *  LOCAL FUNCTION PROTOTYPES
 *********************************************************************************************************************/
boolean validateID ( uint32 ID );


/**********************************************************************************************************************
 *  LOCAL FUNCTION implementation
 *********************************************************************************************************************/
/**********************************************************************************************************************
 *  validateID()
 *********************************************************************************************************************/
/*! \brief         validate the received id
 *  \details       This function is to check if the  min<=received id<=max
 *  \param[in]     ID                      Holds the identifier of channel or key or key element .
 *  \param[in,out] NONE
 *
 *  \param[out]    NONE
 *  \return        1                    valid id.
 *  \return        0                    invalid id.
 *  \pre           NONE .
 *
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *********************************************************************************************************************/
boolean validateID  ( uint32 ID ) {
    if ( ID <minR ||  ID >maxR)
    return FALSE ;
        else
            return TRUE ;
}
/**********************************************************************************************************************
 * CryIf_Init()
 *********************************************************************************************************************/
/*! \brief         Initializes the CRYIF module.
 *  \details
 *  \param[in]     NONE
 *  \param[in,out] NONE
 *
 *  \param[out]    NONE
 *  service id     0x00
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *********************************************************************************************************************/
void CryIf_Init( void ) {
    Init_Done=TRUE;  /*[SWS_CryIf_00015]*/

}
/**********************************************************************************************************************
 * CryIf_GetVersionInf()
 *********************************************************************************************************************/
/*! \brief         get cryif version info.
 *  \details
 *  \param[in]     NONE
 *  \param[in,out] versioninfo
 *
 *  \param[out]    NONE
 *  \service id    0x01
 *  \pre           versioninfo!=NULL       Pointer to where to store the version information of this module.
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *********************************************************************************************************************/
void CryIf_GetVersionInfo(Std_VersionInfoType* versioninfo ) {

   if(FALSE==Init_Done ){  /*[SWS_CryIf_00016]*/

       Det_ReportError(MODULE_ID_CRYIF,0,CRYIF_GET_VERSION_INFO ,CRYIF_E_UNINIT);
   }
   else if(NULL==versioninfo ){ /*[SWS_CryIf_00017]*/

          Det_ReportError(MODULE_ID_CRYIF,0,CRYIF_GET_VERSION_INFO ,CRYIF_E_PARAM_POINTER);
      }

else{

    versioninfo->vendorID=CRYIF_VENDOR_ID ;
    versioninfo->moduleID=CRYIF_MODULE_ID ;
    versioninfo->sw_major_version=CRYIF_AR_MAJOR_VERSION;
    versioninfo->sw_minor_version=CRYIF_AR_MINOR_VERSION;
    versioninfo->sw_patch_version=CRYIF_AR_PATCH_VERSION;
}
}
/**********************************************************************************************************************
 *  CryIf_ProcessJob()
 *********************************************************************************************************************/
/*! \brief         This interface dispatches the received jobs to the configured crypto driver object.
 *  \details       This function unifies all external calls to call Crypto_ProcessJob.
 *  \param[in]     channelId               Holds the identifier of the channel.
 *  \param[in,out] job                     Pointer to the configuration of the job. Contains structures with user and
 *                                         primitive relevant information.
 *  \param[out]    NONE
 *  \service id    0x02
 *  \return        E_OK                    Request successful.
 *  \return        E_NOT_OK                Request failed.
 *  \return        CRYPTO_E_BUSY           Request failed, Crypto Driver Object is busy.
 *  \return        CRYPTO_E_KEY_NOT_VALID  Request failed, the key is not valid.
 *  \return        CRYPTO_E_QUEUE_FULL     Request failed, the queue is full.
 *  \return        CRYPTO_E_KEY_SIZE_MISMATCH Request failed, a key element has the wrong size.
 *  \return        CRYPTO_E_SMALL_BUFFER   Request failed, the provided buffer is too small to store the result.
 *  \return        CRYPTO_E_JOB_CANCELED: The service request failed because the synchronous Job has been canceled.
 *  \pre           Param channelId needs to be a valid index.
 *                 Job must point to a valid job object.
 *
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *********************************************************************************************************************/
Std_ReturnType CryIf_ProcessJob( uint32 channelId, Crypto_JobType* job ){

    Std_ReturnType ret =E_NOT_OK;
    boolean flag =0;
    #if (CRYIF_DEV_ERROR_DETECT ==STD_ON)

if (FALSE==Init_Done) { /*[SWS_CryIf_00027]*/

 Det_ReportError(MODULE_ID_CRYIF,0,CRYIF_PROCESSJOB_ID ,CRYIF_E_UNINIT);
   ret=E_NOT_OK;
}

else if  (FALSE==validateID(channelId) ){ /*[SWS_CryIf_00028]*/

 Det_ReportError(MODULE_ID_CRYIF,0,CRYIF_PROCESSJOB_ID, CRYIF_E_PARAM_HANDLE );
   ret= E_NOT_OK;
}

else if ( NULL==job)  { /*[SWS_CryIf_00029]*/

 Det_ReportError(MODULE_ID_CRYIF,0,CRYIF_PROCESSJOB_ID,CRYIF_E_PARAM_POINTER);
   ret=E_NOT_OK ;

}


else {

   flag=1;
}
   #endif
if((flag==1) || (CRYIF_DEV_ERROR_DETECT ==STD_OFF)){ /*[SWS_CryIf_00044]*/

    ret= Crypto_ProcessJob( CHANNELS [channelId].obj, job );
}
return ret;
}
/**********************************************************************************************************************
 *  CryIf_CancelJob()
 *********************************************************************************************************************/
/*! \brief         cancel the received job.
 *  \details       This interface dispatches the job cancellation function to the configured crypto
 *                 driver object.
 *
 *  \param[in]     channelId               Holds the identifier of the channel.
 *  \param[in,out] job                     Pointer to the configuration of the job. Contains structures with user and
 *                                         primitive relevant information.
 *  \param[out]    NONE
 *  \service id    0x03
 *  \return        E_OK                    Request successful.
 *  \return        E_NOT_OK                Request failed.
 *  \pre           Param channelId  needs to be a valid index.
 *                 Job must point to a valid job object.
 *
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *********************************************************************************************************************/

Std_ReturnType CryIf_CancelJob( uint32 channelId, Crypto_JobType* job )
{
    Std_ReturnType ret =E_NOT_OK;
    boolean flag =0;
#if (CRYIF_DEV_ERROR_DETECT ==STD_ON)

if (FALSE==Init_Done) { /*[SWS_CryIf_00129]*/

  Det_ReportError(MODULE_ID_CRYIF,0,CRYIF_CANCEL_JOB_ID,CRYIF_E_UNINIT);
      ret= E_NOT_OK;
}

else if (FALSE==validateID(channelId) ){/*[SWS_CryIf_00130]*/
  Det_ReportError(MODULE_ID_CRYIF,0,CRYIF_CANCEL_JOB_ID, CRYIF_E_PARAM_HANDLE );
    ret= E_NOT_OK;
}

else if ( NULL==job)  { /*[SWS_CryIf_00131]*/
  Det_ReportError(MODULE_ID_CRYIF,0,CRYIF_CANCEL_JOB_ID,CRYIF_E_PARAM_POINTER);
    ret= E_NOT_OK ;

}


else {

    flag=1;
}
    #endif
if((flag==1) || (CRYIF_DEV_ERROR_DETECT ==STD_OFF)){ /*[SWS_CryIf_00132]*/

    Crypto_JobInfoType **Const_to_NON=(Crypto_JobInfoType**)((Crypto_JobInfoType*)&job->jobInfo);/*pointerTopointer cast to avoid warning */
    ret= Crypto_CancelJob(CHANNELS [channelId].obj,*Const_to_NON);
}
   return ret;
}

/**********************************************************************************************************************
 *  CryIf_KeyElementSet()
 *********************************************************************************************************************/
/*! \brief         set key element .
 *  \details       This function shall dispatch the set key element function to the configured crypto
 *                 driver object.
 *
 *  \param[in]     cryIfKeyId              Holds the identifier of the key whose key element shall be set.
 *                 keyElementId            Holds the identifier of the key element which shall be set.
 *                 keyPtr                  Holds the pointer to the key data which shall be set as key element.
 *                 keyLength               Contains the length of the key element in bytes.
 *  \param[in,out] NONE
 *
 *  \param[out]    NONE
 *  \service id    0x04
 *  \return        E_OK                    Request successful.
 *  \return        E_NOT_OK                Request failed.
 *  \return        CRYPTO_E_BUSY           Request failed, Crypto Driver Object is busy.
 *  \return        CRYPTO_E_KEY_WRITE_FAIL Request failed because write access was denied.
 *  \return        CRYPTO_E_KEY_NOT_AVAILABLE  Request failed because the key is not available.
 *  \return        CRYPTO_E_KEY_SIZE_MISMATCH   Request failed, key element size does not match size of provided data.
 *  \pre           Param cryIfKeyId needs to be a valid index.
 *                 Param keyElementId  needs to be a valid index.
 *                 keyPtr must point to a valid key data.
 *                 *keyLength doensn't equal 0.
 *
 *  \context       TASK
 *  \reentrant     FALSE
 *  \synchronous   TRUE
 *********************************************************************************************************************/

Std_ReturnType CryIf_KeyElementSet( uint32 cryIfKeyId, uint32 keyElementId, const uint8* keyPtr, uint32 keyLength)
{
    Std_ReturnType ret =E_NOT_OK;
    boolean flag =0;
#if (CRYIF_DEV_ERROR_DETECT ==STD_ON)

if (FALSE==Init_Done) { /*[SWS_CryIf_00049]*/

  Det_ReportError(MODULE_ID_CRYIF,0,CRYIF_KEY_ELEMENT_SET_ID ,CRYIF_E_UNINIT);
    ret=E_NOT_OK;
}

else if (FALSE==validateID(cryIfKeyId)) { /*[SWS_CryIf_00050]*/

  Det_ReportError(MODULE_ID_CRYIF,0,CRYIF_KEY_ELEMENT_SET_ID, CRYIF_E_PARAM_HANDLE );
      ret= E_NOT_OK;
}

else if ( NULL==keyPtr )  { /* [SWS_CryIf_00052]*/

  Det_ReportError(MODULE_ID_CRYIF,0,CRYIF_PROCESSJOB_ID,CRYIF_E_PARAM_POINTER);
      ret= E_NOT_OK ;
}

else if(0==keyLength) {  /*[SWS_CryIf_00053]*/

  Det_ReportError(MODULE_ID_CRYIF,0,CRYIF_KEY_ELEMENT_SET_ID,CRYIF_E_PARAM_VALUE );
     ret= E_NOT_OK;
}


else {

  flag=1;

}
#endif
if((flag==1) || (CRYIF_DEV_ERROR_DETECT ==STD_OFF)){  /*[SWS_CryIf_00055]*/

   ret= Crypto_KeyElementSet( KEYS[cryIfKeyId].CryptoKey ,  keyElementId,  keyPtr, keyLength )  ;
}
return ret;
}

/**********************************************************************************************************************
 *  CryIf_Key_SetValid()
 *********************************************************************************************************************/
/*! \brief         validate the received key
 *  \details       This function shall dispatch the set key valid function to the configured cryptodriver object.
 *
 *  \param[in]     cryIfKeyId              Holds the identifier of the key whose key elements shall be set to valid
 *  \param[in,out] NONE
 *
 *  \param[out]    NONE                    Holds the primitive which shall be processed.
 *  \service id    0x05
 *  \return        E_OK                    Request successful.
 *  \return        E_NOT_OK                Request failed.
 *  \pre           Param cryIfKeyId  needs to be a valid index.
 *
 *  \context       TASK
 *  \reentrant     FALSE
 *  \synchronous   TRUE
 *********************************************************************************************************************/
Std_ReturnType CryIf_Key_SetValid( uint32 cryIfKeyId){

    Std_ReturnType ret =E_NOT_OK;
     boolean flag =0;
    #if (CRYIF_DEV_ERROR_DETECT ==STD_ON)

if (FALSE==Init_Done) { /*[SWS_CryIf_00056]*/
  Det_ReportError(MODULE_ID_CRYIF,0,CRYIF_KEY_SET_VALID_ID,CRYIF_E_UNINIT);
    ret= E_NOT_OK;
}

else if (FALSE==validateID(cryIfKeyId)) { /*[SWS_CryIf_00057]*/

  Det_ReportError(MODULE_ID_CRYIF,0,CRYIF_KEY_SET_VALID_ID, CRYIF_E_PARAM_HANDLE );
    ret= E_NOT_OK;
}
else {

  flag=1;
}
#endif
if((flag==1) || (CRYIF_DEV_ERROR_DETECT ==STD_OFF)){ /*[SWS_CryIf_00058]*/

   ret= Crypto_KeySetValid(KEYS[cryIfKeyId].CryptoKey );
}
return ret;
}

/**********************************************************************************************************************
 *  CryIf_KeyElementGet()
 *********************************************************************************************************************/
/*! \brief         get key element of the recieved key
 *  \details       This function shall dispatch the get key element function to the configured crypto driver object.
 *
 *  \param[in]     cryIfKeyId              Holds the identifier of the key whose key element shall be returned.
 *                 keyElementId            Holds the identifier of the key element which shall be returned.
 *
 *  \param[in,out] resultPtr               Holds a pointer to a memory location in which the length
 *                                         information is stored. On calling this function this parameter shall
 *                                          contain the size of the buffer provided by resultPtr. If the key
 *                                          element is configured to allow partial access, this parameter
 *                                          contains the amount of data which should be read from the key
 *                                          element. The size may not be equal to the size of the provided
 *                                         buffer anymore. When the request has finished, the amount of
 *                                         data that has been stored shall be stored.
 *
 *  \param[out]    resultLengthPtr         Holds the pointer of the buffer for the returned key element.
 *  \service id    0x06
 *  \return        E_OK                    Request successful.
 *  \return        E_NOT_OK                Request failed.
 *  \return        CRYPTO_E_BUSY           Request failed, Crypto Driver Object is busy.
 *  \return        CRYPTO_E_KEY_WRITE_FAIL Request failed because write access was denied.
 *  \return        CRYPTO_E_KEY_NOT_AVAILABLE  Request failed because the key is not available.
 *  \return        CRYPTO_E_SMALL_BUFFER   Request failed, the provided buffer is too small to store the result.
 *  \pre           Param cryIfKeyId  needs to be a valid index.
 *                  Param keyElementId needs to be a valid index.
 *                 resultPtr !=NULL
 *                 *resultLengthPtr!=0
 *
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *********************************************************************************************************************/

Std_ReturnType CryIf_KeyElementGet( uint32 cryIfKeyId,uint32 keyElementId, uint8* resultPtr, uint32* resultLengthPtr){

   Std_ReturnType ret =E_NOT_OK;
      boolean flag =0;
    #if (CRYIF_DEV_ERROR_DETECT ==STD_ON)

if (FALSE==Init_Done) { /*[SWS_CryIf_00059]*/

   Det_ReportError(MODULE_ID_CRYIF,0,CRYIF_KEY_ELEMENT_GET_ID ,CRYIF_E_UNINIT);
     ret= E_NOT_OK;
}
else if (FALSE==validateID(cryIfKeyId) ){ /*[SWS_CryIf_00060]*/

   Det_ReportError(MODULE_ID_CRYIF,0,CRYIF_KEY_ELEMENT_GET_ID, CRYIF_E_PARAM_HANDLE );
     ret= E_NOT_OK;}
else if ( NULL== resultPtr)  { /*[SWS_CryIf_00062]*/

   Det_ReportError(MODULE_ID_CRYIF,0,CRYIF_KEY_ELEMENT_GET_ID,CRYIF_E_PARAM_POINTER);
      ret= E_NOT_OK ;
}
else if ( NULL== resultLengthPtr)  { /*[SWS_CryIf_00063]*/

    Det_ReportError(MODULE_ID_CRYIF,0,CRYIF_KEY_ELEMENT_GET_ID,CRYIF_E_PARAM_POINTER);
      ret= E_NOT_OK ;
}

else if ( 0== *resultLengthPtr)  { /*[SWS_CryIf_00064]*/

    Det_ReportError(MODULE_ID_CRYIF,0,CRYIF_KEY_ELEMENT_GET_ID,CRYIF_E_PARAM_VALUE);
        ret= E_NOT_OK ;
}
else {

       flag=1;
}
#endif
if((flag==1) || (CRYIF_DEV_ERROR_DETECT ==STD_OFF)){  /*[SWS_CryIf_00065]*/

    ret= Crypto_KeyElementGet( KEYS[cryIfKeyId].CryptoKey, keyElementId,  resultPtr,  resultLengthPtr );
}
return ret;
}

//TODO implement CryIf_KeyElementCopy()
/**********************************************************************************************************************
 *  CryIf_KeyElementCopy()
 *********************************************************************************************************************/
/*! \brief         copy key element of the recieved key
 *  \details       This function shall copy a key elements from one key to a target key.


 *  \param[in]     cryIfKeyId              Holds the identifier of the key whose key element shall be the source element.
                   keyElementId            Holds the identifier of the key element which shall be the source for the copy operation.
                   targetCryIfKeyId        Holds the identifier of the key whose key element shall be the destination element
                   targetKeyElementId      Holds the identifier of the key element which shall be the destination for the copy operation.


 *  \param[in,out] NONE
 *
 *  \param[out]    NONE
 *  \service id   0x0f
 *  \return        E_OK                    Request successful.
 *  \return        E_NOT_OK                Request failed.
 *  \return        CRYPTO_E_BUSY           Request failed, Crypto Driver Object is busy.
 *  \return        CRYPTO_E_KEY_NOT_AVAILABLE  Request failed because the key is not available.
 *  \return        CRYPTO_E_KEY_READ_FAIL   Request failed, not allowed to extract key element.
 *  \return        CRYPTO_E_KEY_WRITE_FAIL   Request failed, not allowed to write key element.
 *  \return        CRYPTO_E_KEY_SIZE_MISMATCH   Request failed, key element size does not match size of provided data.

 *  \pre           Param queueIdx needs to be a valid index.
 *                 Job must point to a valid job object.
 *  \context       TASK
 *  \reentrant     TRUE,but not for the same cryIfKeyId.
 *  \synchronous   TRUE
 *********************************************************************************************************************/
Std_ReturnType CryIf_KeyElementCopy( uint32 cryIfKeyId, uint32 keyElementId, uint32 targetCryIfKeyId, uint32 targetKeyElementId ){

     Std_ReturnType ret =E_NOT_OK;
     boolean flag =0;

#if (CRYIF_DEV_ERROR_DETECT ==STD_ON)

if (FALSE==Init_Done) { /*[SWS_CryIf_00110]*/

   Det_ReportError(MODULE_ID_CRYIF,0,CRYIF_KEY_ELEMENT_COPY_ID ,CRYIF_E_UNINIT);
        ret= E_NOT_OK;
}

else if (FALSE==validateID(cryIfKeyId) ){ /*[SWS_CryIf_00111]*/

   Det_ReportError(MODULE_ID_CRYIF,0,CRYIF_KEY_ELEMENT_COPY_ID, CRYIF_E_PARAM_HANDLE );
      ret= E_NOT_OK;
}

else if (FALSE==validateID(targetCryIfKeyId)){ /*[SWS_CryIf_00112]*/

   Det_ReportError(MODULE_ID_CRYIF,0,CRYIF_KEY_ELEMENT_COPY_ID, CRYIF_E_PARAM_HANDLE );
      ret= E_NOT_OK;
}

else {

    flag=1;

}
    #endif

if((flag==1) || (CRYIF_DEV_ERROR_DETECT ==STD_OFF)){ /*[SWS_CryIf_00113]*/
  ret= Crypto_KeyCopy(KEYS[cryIfKeyId].CryptoKey , KEYS[targetCryIfKeyId].CryptoKey);
  /*cryIfKeyId and targetCryIfKeyId are located in the same Crypto Driver*/
}
/*TODO [SWS_CryIf_00114]
*cryIfKeyId and targetCryIfKeyId are located in different Crypto Drivers,
*the service CryIf_KeyElementCopy() shall copy the provided key element by getting the element with Crypto_<vi>_<ai>_KeyElementGet()
*and setting the target key element via Crypto_<vi>_<ai>_KeyElementSet().
*/

/*TODO [SWS_CryIf_00115]
*If a key element of cryIfKeyId is not available in targetCryIfKeyId,
*the key element shall not be copied and no error code shall be returned.
*If the source element size does not match the target key elements size,
*If CryIf_KeyElementCopy()shall report CRYIF_E_KEY_SIZE_MISMATCH to the DET and return E_NOT_OK.
*/
return ret ;
}
/**********************************************************************************************************************
 *   CryIf_KeyCopy()
 *********************************************************************************************************************/
/*! \brief         copy key elements of the recieved key.
 *  \details       This function shall copy all key elements from the source key to a target key.
 *  \param[in]     cryIfKeyId             Holds the identifier of the key whose key element shall be the source element.
 *                 targetCryIfKeyId       Holds the identifier of the key whose key element shall be the destination element.
 *
 *  \param[in,out] NONE
 *  \param[out]    NONE
 *  \service id    0x10
 *  \return        E_OK                    Request successful.
 *  \return        E_NOT_OK                Request failed.
 *  \return        CRYPTO_E_BUSY           Request failed, Crypto Driver Object is busy.
 *  \return        CRYPTO_E_KEY_NOT_AVAILABLE  Request failed because the key is not available.
 *  \return        CRYPTO_E_KEY_READ_FAIL   Request failed, not allowed to extract key element.
 *  \return        CRYPTO_E_KEY_WRITE_FAIL   Request failed, not allowed to write key element.
 *  \return        CRYPTO_E_KEY_SIZE_MISMATCH   Request failed, key element size does not match size of provided data.
 *  \pre           Param  cryIfKeyId needs to be a valid index.
 *                 Param  targetCryIfKeyId needs to be a valid index.
 *
 *  \context       TASK
 *  \reentrant     TRUE, but not for the same cryIfKeyId
 *  \synchronous   TRUE
 *********************************************************************************************************************/
Std_ReturnType CryIf_KeyCopy( uint32 cryIfKeyId, uint32 targetCryIfKeyId ){

    Std_ReturnType ret=E_NOT_OK;
    boolean flag =0;
#if (CRYIF_DEV_ERROR_DETECT ==STD_ON)

if (FALSE==Init_Done) {  /*[SWS_CryIf_00116]*/

   Det_ReportError(MODULE_ID_CRYIF,0,CRYIF_KEY_COPY_ID ,CRYIF_E_UNINIT);
    ret= E_NOT_OK;
}

else if (FALSE==validateID(cryIfKeyId) ){ /*[SWS_CryIf_00117]*/

   Det_ReportError(MODULE_ID_CRYIF,0,CRYIF_KEY_COPY_ID, CRYIF_E_PARAM_HANDLE );
    ret= E_NOT_OK;
}
else if (FALSE==validateID(targetCryIfKeyId)){ /*[SWS_CryIf_00118]*/

   Det_ReportError(MODULE_ID_CRYIF,0,CRYIF_KEY_COPY_ID, CRYIF_E_PARAM_HANDLE );
    ret= E_NOT_OK;
}
else{

    flag=1;

}
    #endif
if((flag==1) || (CRYIF_DEV_ERROR_DETECT ==STD_OFF)){ /*[SWS_CryIf_00119]*/
    ret= Crypto_KeyCopy(KEYS[cryIfKeyId].CryptoKey , KEYS[targetCryIfKeyId].CryptoKey);
    /*cryIfKeyId and targetCryIfKeyId are located in the same Crypto Driver*/
}
/*TODO [SWS_CryIf_00120]
*cryIfKeyId and targetCryIfKeyId are located in different Crypto Drivers,
*the service CryIf_KeyCopy() shall copy the provided key element by getting
*the the element with Crypto_<vi>_<ai>_KeyElementGet() and
*the setting the target key element via Crypto_<vi>_<ai>_KeyElementSet().
*/

/*TODO [SWS_CryIf_00121]
*If a key element of cryIfKeyId is not available in targetCryIfKeyId,
*the key element shall not be copied and no error code shall be returned.
*If the source element size does not match the target key elements size,
*If CryIf_Copy()shall report CRYIF_E_KEY_SIZE_MISMATCH to the DET and return E_NOT_OK.
*/
  return ret ;

}


/**********************************************************************************************************************
 *  CryIf_RandomSeed()
 *********************************************************************************************************************/
/*! \brief         passing RandomSeed to CryIf
 *  \details       This function shall dispatch the random seed function to the configured crypto driver object.
 *  \param[in]     cryIfKeyId              Holds the identifier of the key for which a new seed shall be generated.
 *                 seedPtr                 Holds a pointer to the memory location which contains the data to feed the seed.
 *                 seedLength              Contains the length of the seed in bytes.
 *
 *  \param[in,out] NONE
 *
 *  \param[out]    NONE
 *  \service id    0x07
 *  \return        E_OK                    Request successful.
 *  \return        E_NOT_OK                Request failed.
 *
 *
 *  \pre           Param cryIfKeyId needs to be a valid index.
 *                 seedPtr !=NULL.
 *                 *seedLength !=0
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *********************************************************************************************************************/

Std_ReturnType CryIf_RandomSeed( uint32 cryIfKeyId, const uint8* seedPtr, uint32 seedLength){

 boolean flag =0;
 Std_ReturnType ret=E_NOT_OK;
#if (CRYIF_DEV_ERROR_DETECT ==STD_ON)

if (FALSE==Init_Done) { /*[SWS_CryIf_00068]*/

   Det_ReportError(MODULE_ID_CRYIF,0,CRYIF_RANDOM_SEED_ID,CRYIF_E_UNINIT);
      ret= E_NOT_OK;
}
if (FALSE==validateID(cryIfKeyId) ){  /*[SWS_CryIf_00069]*/

   Det_ReportError(MODULE_ID_CRYIF,0,CRYIF_RANDOM_SEED_ID, CRYIF_E_PARAM_HANDLE );
     ret= E_NOT_OK;
    }

else if ( NULL== seedPtr)  {  /*[SWS_CryIf_00070]*/

  Det_ReportError(MODULE_ID_CRYIF,0,CRYIF_RANDOM_SEED_ID,CRYIF_E_PARAM_POINTER);
    ret= E_NOT_OK ;
}
else if(0==seedLength) {  /*[SWS_CryIf_00071]*/

  Det_ReportError(MODULE_ID_CRYIF,0,CRYIF_RANDOM_SEED_ID,CRYIF_E_PARAM_VALUE );
      ret= E_NOT_OK ;
}
else{
   flag=1;
}
    #endif
if((flag==1) || (CRYIF_DEV_ERROR_DETECT ==STD_OFF)){  /*[SWS_CryIf_00072]*/

   ret= Crypto_RandomSeed( KEYS[cryIfKeyId].CryptoKey,  seedPtr,  seedLength);
}
return ret;}

/**********************************************************************************************************************
 * CryIf_KeyGenerate()
 *********************************************************************************************************************/
/*! \brief         update key with generated value .
 *  \details       This function shall dispatch the key generate function to the configured crypto driver object
 *  \param[in]     cryIfKeyId              Holds the identifier of the key for which to be updated with the generated value..
 *
 *  \param[in,out] NONE
 *
 *  \param[out]     NONE
 *  \service id     0x08
 *  \return        E_OK                    Request successful.
 *  \return        E_NOT_OK                Request failed.
 *  \return        E_BUSY                   Request Failed, Crypto Driver Object is Busy
 *  \pre           Param cryIfKeyId  needs to be a valid index.
 *
 *
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *********************************************************************************************************************/
Std_ReturnType CryIf_KeyGenerate( uint32 cryIfKeyId){

    Std_ReturnType ret=E_NOT_OK;
     boolean flag =0;
   #if (CRYIF_DEV_ERROR_DETECT ==STD_ON)
if (FALSE==Init_Done) {  /*[SWS_CryIf_00073]*/

   Det_ReportError(MODULE_ID_CRYIF,0,CRYIF_KEY_GENERATE_ID,CRYIF_E_UNINIT);
    ret= E_NOT_OK;
}
else if (FALSE==validateID(cryIfKeyId) ){  /*[SWS_CryIf_00074]*/
  Det_ReportError(MODULE_ID_CRYIF,0,CRYIF_KEY_GENERATE_ID, CRYIF_E_PARAM_HANDLE );
    ret= E_NOT_OK;
}
else {

       flag=1;
}
  #endif
if((flag==1) || (CRYIF_DEV_ERROR_DETECT ==STD_OFF)){  /*[SWS_CryIf_00075]*/

    ret= Crypto_KeyGenerate(  KEYS[cryIfKeyId].CryptoKey);
}
return ret;
}
/**********************************************************************************************************************
 *CryIf_KeyDerive()
 *********************************************************************************************************************/
/*! \brief         derive key ..
 *  \details       This function shall dispatch the key derive function to the configured crypto driver object.
 *  \param[in]     cryIfKeyId              Holds the identifier of the key which is used for key derivation.
                   targetCryIfKeyId        Holds the identifier of the key which is used to store the derived key.
 *  \param[in,out] NONE
 *
 *  \param[out]     NONE
 *  \service id    0x09
 *
 *  \return        E_OK                    Request successful.
 *  \return        E_NOT_OK                Request failed.
 *
 *  \pre           Param cryIfKeyId  needs to be a valid index.
 *                 Param targetCryIfKeyId  needs to be a valid index.
 *
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *********************************************************************************************************************/

Std_ReturnType CryIf_KeyDerive( uint32 cryIfKeyId, uint32 targetCryIfKeyId){

    boolean flag =0;
    Std_ReturnType ret=E_NOT_OK;
  #if (CRYIF_DEV_ERROR_DETECT ==STD_ON)

if (FALSE==Init_Done) {  /*[SWS_CryIf_00076]*/

   Det_ReportError(MODULE_ID_CRYIF,0,CRYIF_KEY_DERIVE_ID,CRYIF_E_UNINIT);
    ret= E_NOT_OK;
}
else if (FALSE==validateID(cryIfKeyId) ){  /*[SWS_CryIf_00077]*/

   Det_ReportError(MODULE_ID_CRYIF,0,CRYIF_KEY_DERIVE_ID, CRYIF_E_PARAM_HANDLE );
    ret= E_NOT_OK;
}

else if (FALSE==validateID(targetCryIfKeyId) ){  /*[SWS_CryIf_00122]*/
    Det_ReportError(MODULE_ID_CRYIF,0,CRYIF_KEY_DERIVE_ID, CRYIF_E_PARAM_HANDLE );
     ret= E_NOT_OK;
}
else{

    flag=1;
}

  #endif
if((flag==1) || (CRYIF_DEV_ERROR_DETECT ==STD_OFF)){  /*[SWS_CryIf_00081]*/

    ret= Crypto_KeyDerive(KEYS[cryIfKeyId].CryptoKey,KEYS[targetCryIfKeyId].CryptoKey);
}
return ret;
}

/**********************************************************************************************************************
 *  CryIf_KeyExchangeCalcPubValt()
 *********************************************************************************************************************/
/*! \brief
 *  \detailsThis function shall dispatch the key exchange public value calculation function to the configured crypto driver object.
 *
 *  \param[in]     cryIfKeyId              Holds the identifier of the key whose key element shall be  be used for the key exchange protocol.
 *
 *  \param[in,out] publicValueLengthPtr    Holds a pointer to the memory location in which the public value length information is stored.
 *                                         On calling this function,this parameter shall contain the size of the buffer provided
 *                                         by publicValuePtr. When the request has finished, the actual
 *                                         length of the returned value shall be stored.
 *
 *  \param[out]    publicValuePtr          Contains the pointer to the data where the public value shall be stored.
 *  \service id    0x0a
 *
 *  \return        E_OK                    Request successful.
 *  \return        E_NOT_OK                Request failed.
 *  \return        CRYPTO_E_BUSY           Request failed, Crypto Driver Object is busy.
  *  \return       CRYPTO_E_SMALL_BUFFER   Request failed, the provided buffer is too small to store the result.
 *  \pre           Param cryIfKeyId needs to be a valid index.
 *                 publicValuePtr !=NULL
 *                 publicValueLengthPtr!=NULL
 *                 *publicValueLengthPtr doensn't equal 0.
 *
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *********************************************************************************************************************/

Std_ReturnType CryIf_KeyExchangeCalcPubVal( uint32 cryIfKeyId, uint8* publicValuePtr, uint32* publicValueLengthPtr){

    boolean flag =0;
    Std_ReturnType ret=E_NOT_OK;

#if (CRYIF_DEV_ERROR_DETECT ==STD_ON)

if (FALSE==Init_Done) { /*[SWS_CryIf_00082]*/

  Det_ReportError(MODULE_ID_CRYIF,0,CRYIF_KEY_EXCHANGE_CALC_PUBVAL_ID,CRYIF_E_UNINIT);
    ret=E_NOT_OK;
}
else if (FALSE==validateID(cryIfKeyId) ){ /*[SWS_CryIf_00083]*/

  Det_ReportError(MODULE_ID_CRYIF,0,CRYIF_KEY_EXCHANGE_CALC_PUBVAL_ID, CRYIF_E_PARAM_HANDLE );
    ret=E_NOT_OK;}

else if ( NULL==publicValuePtr)  { /*[SWS_CryIf_00084]*/

  Det_ReportError(MODULE_ID_CRYIF,0,CRYIF_KEY_EXCHANGE_CALC_PUBVAL_ID,CRYIF_E_PARAM_POINTER);
    ret= E_NOT_OK ;
}
else if ( NULL==publicValueLengthPtr)  { /*[SWS_CryIf_00085]*/

   Det_ReportError(MODULE_ID_CRYIF,0,CRYIF_KEY_EXCHANGE_CALC_PUBVAL_ID,CRYIF_E_PARAM_POINTER);
     ret= E_NOT_OK ;
}
else if ( 0== *publicValueLengthPtr)  { /*[SWS_CryIf_00086]*/
Det_ReportError(MODULE_ID_CRYIF,0,CRYIF_KEY_EXCHANGE_CALC_PUBVAL_ID,CRYIF_E_PARAM_VALUE);
     ret= E_NOT_OK ;}
else {

    flag=1;
}
  #endif

if((flag==1) || (CRYIF_DEV_ERROR_DETECT ==STD_OFF)){ /*[SWS_CryIf_00087]*/
  ret= Crypto_KeyExchangeCalcPubVal(KEYS[cryIfKeyId].CryptoKey,publicValuePtr, publicValueLengthPtr);
}
         return ret;
}
/**********************************************************************************************************************
 *  CryIf_KeyExchangeCalcSecret()
 *********************************************************************************************************************/
/*! \brief
 *  \details       This function shall dispatch the key exchange common shared secret calculation
                   function to the configured crypto driver object
 *
 *  \param[in]     cryIfKeyId             Holds the identifier of the key which shall be used for the key exchange protocol.
 *                 partnerPublicValuePtr  Holds the pointer to the memory location which contains the partner's public value.
 *                 partnerPublicValueLength Contains the length of the partner's public value in bytes.
 *  \param[in,out] NONE
 *
 *  \param[out]    NONE          .
 *  \service id     0x0b
 *  \return        E_OK                    Request successful.
 *  \return        E_NOT_OK                Request failed.
 *  \return        CRYPTO_E_BUSY           Request failed, Crypto Driver Object is busy.
 *  \return       CRYPTO_E_SMALL_BUFFER   Request failed, the provided buffer is too small to store the result.
 *  \pre           Param cryIfKeyId needs to be a valid index.
 *                 publicValuePtr !=NULL
 *                 partnerPublicValuePtr!=NULL
 *                 partnerPublicValueLength doensn't equal 0.
 *
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *********************************************************************************************************************/

Std_ReturnType CryIf_KeyExchangeCalcSecret( uint32 cryIfKeyId, const uint8* partnerPublicValuePtr, uint32* partnerPublicValueLength){
    boolean flag =0;
    Std_ReturnType ret=E_NOT_OK;

#if (CRYIF_DEV_ERROR_DETECT ==STD_ON)

 if (FALSE==Init_Done) { /*[SWS_CryIf_00090]*/

   Det_ReportError(MODULE_ID_CRYIF,0,CRYIF_KEY_EXCHANGE_CALC_SECRET_ID,CRYIF_E_UNINIT);
    ret= E_NOT_OK;
}
else if (FALSE==validateID(cryIfKeyId) ){ /*[SWS_CryIf_00091]*/

   Det_ReportError(MODULE_ID_CRYIF,0,CRYIF_KEY_EXCHANGE_CALC_SECRET_ID, CRYIF_E_PARAM_HANDLE );
    ret= E_NOT_OK;
}

else if ( NULL==partnerPublicValuePtr)  { /*[SWS_CryIf_00092]*/

   Det_ReportError(MODULE_ID_CRYIF,0,CRYIF_KEY_EXCHANGE_CALC_SECRET_ID,CRYIF_E_PARAM_POINTER);
     ret= E_NOT_OK ;
}

else if ( NULL==partnerPublicValueLength)  { /*[SWS_CryIf_00093]*/

   Det_ReportError(MODULE_ID_CRYIF,0,CRYIF_KEY_EXCHANGE_CALC_SECRET_ID,CRYIF_E_PARAM_POINTER);
     ret= E_NOT_OK ;
}
else if(0==partnerPublicValueLength) { /*[SWS_CryIf_00093]*/

   Det_ReportError(MODULE_ID_CRYIF,0,CRYIF_KEY_EXCHANGE_CALC_SECRET_ID,CRYIF_E_PARAM_VALUE );
    ret= E_NOT_OK ;
}
else {

     flag=1;
}

#endif
if((flag==1) || (CRYIF_DEV_ERROR_DETECT ==STD_OFF)){ /*[SWS_CryIf_00095]*/
  ret= Crypto_KeyExchangeCalcSecret(KEYS[cryIfKeyId].CryptoKey, partnerPublicValuePtr, partnerPublicValueLength ) ;
}
return ret;
}
/**********************************************************************************************************************
 * CryIf_CertificateParse()
 *********************************************************************************************************************/
/*! \brief         parse Certificate .
 *  \details       This function shall dispatch the certificate parse function to the configured crypto driver object.
 *  \param[in]     cryIfKeyId             Holds the identifier of the key which shall be parsed.
 *
 *  \param[in,out] NONE
 *
 *  \param[out]    NONE
 *  \service id    0x0c
 *
 *  \return        E_OK                    Request successful.
 *  \return        E_NOT_OK                Request failed.
 *  \return        E_BUSY: Request Failed, Crypto Driver Object is Busy.
 *  \pre           Param cryIfKeyId  needs to be a valid index.
 *
 *
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *********************************************************************************************************************/

Std_ReturnType CryIf_CertificateParse( uint32 cryIfKeyId){

       boolean flag =0;
      Std_ReturnType ret=E_NOT_OK;

#if (CRYIF_DEV_ERROR_DETECT ==STD_ON)

 if (FALSE==Init_Done) { /*[SWS_CryIf_00098]*/

   Det_ReportError(MODULE_ID_CRYIF,0,CRYIF_CERTIFICATE_PARSE_ID,CRYIF_E_UNINIT);
     ret= E_NOT_OK;
}
else if (FALSE==validateID(cryIfKeyId) ){ /*[SWS_CryIf_00099]*/

   Det_ReportError(MODULE_ID_CRYIF,0,CRYIF_CERTIFICATE_PARSE_ID, CRYIF_E_PARAM_HANDLE );
     ret= E_NOT_OK;
}
else {

     flag=1;
}
#endif
if((flag==1) || (CRYIF_DEV_ERROR_DETECT ==STD_OFF)){ /*[SWS_CryIf_00104]*/

  ret= Crypto_CertificateParse(KEYS[cryIfKeyId].CryptoKey);
}
return ret;

}
/**********************************************************************************************************************
 *  CryIf_CertificateVerify()
 *********************************************************************************************************************/
/*! \brief         verify Certificate .
 *  \details       Verifies the certificate stored in the key referenced by verifyCryIfKeyId with the
 *                 certificate stored in the key referenced by cryIfKeyId.
 *
 *
 *  \param[in]     cryIfKeyId              Holds the identifier of the key which shall be used to validate the certificate.
 *                 verifyCryIfKeyId        Holds the identifier of the key containing the certificate to be verified.
 *               .
 *  \param[in,out] NONE
 *
 *  \param[out]    verifyPtr          .    Holds a pointer to the memory location which will contain the result of the certificate verification.
 *  \service id    0x011
 *  \return        E_OK                    Request successful.
 *  \return        E_NOT_OK                Request failed.
 *  \pre           Param cryIfKeyId needs to be a valid index.
 *                 Param verifyCryIfKeyId needs to be a valid index.
 *                 verifyPtrr !=NULL
 *
 *
 *  \context       TASK
 *  \reentrant     TRUE ,but not for the same cryIfKeyId
 *  \synchronous   TRUE
 *********************************************************************************************************************/


Std_ReturnType CryIf_CertificateVerify( uint32 cryIfKeyId, uint32 verifyCryIfKeyId, Crypto_VerifyResultType* verifyPtr){

    boolean flag =0;
    Std_ReturnType ret=E_NOT_OK;

#if (CRYIF_DEV_ERROR_DETECT ==STD_ON)
 if (FALSE==Init_Done) { /*[SWS_CryIf_00123]*/

  Det_ReportError(MODULE_ID_CRYIF,0,CRYIF_CERTIFICATE_VERIFY_ID,CRYIF_E_UNINIT);
   ret= E_NOT_OK;
}
else if (FALSE==validateID(cryIfKeyId)) { /*[SWS_CryIf_00124]*/

   Det_ReportError(MODULE_ID_CRYIF,0,CRYIF_CERTIFICATE_VERIFY_ID, CRYIF_E_PARAM_HANDLE );
   ret= E_NOT_OK;
}

else if (FALSE==validateID(verifyCryIfKeyId) ){ /*[SWS_CryIf_00125]*/

   Det_ReportError(MODULE_ID_CRYIF,0,CRYIF_CERTIFICATE_VERIFY_ID, CRYIF_E_PARAM_HANDLE );
    ret= E_NOT_OK;
}
/*
TODO [SWS_CryIf_00126]
*If development error detection for the CRYIF module is enabled:
*If  The function CryIf_CertificateVerify shall report CRYIF_E_PARAM_HANDLE to the DET and return E_NOT_OK
*If  if the keys identified by validateCryIfKeyId and cryIfKeyId are not located in the same Crypto Driver.
*/
else if ( NULL==verifyPtr)  { /*[SWS_CryIf_00127]*/

  Det_ReportError(MODULE_ID_CRYIF,0,CRYIF_CERTIFICATE_VERIFY_ID,CRYIF_E_PARAM_POINTER);
   ret= E_NOT_OK ;
}
else {

    flag=1;
}
#endif
if((flag==1) || (CRYIF_DEV_ERROR_DETECT ==STD_OFF)){  /*[SWS_CryIf_00127]*/

  ret= Crypto_CertificateVerify(KEYS[cryIfKeyId].CryptoKey,KEYS[verifyCryIfKeyId].CryptoKey, verifyPtr);
}
return ret;
}

