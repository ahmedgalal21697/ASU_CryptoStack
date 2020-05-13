/*
 *  -------------------------------------------------------------------------------------------------------------------
 *  FILE DESCRIPTION
 *  -----------------------------------------------------------------------------------------------------------------*/
/*!        \file  Csm_Cfg.c
 *        \brief  MICROSAR Crypto Service Manager (CSM)
 *
 *      \details  Implementation of the MICROSAR Crypto Service Manager configuration (CSM)
 *
 *********************************************************************************************************************/
 
 /**********************************************************************************************************************
 *  INCLUDES
 *********************************************************************************************************************/
#include "Csm_Cfg.h"



//CsmEncryptConfig job1_CsmEncryptConfig ={ CRYPTO_ALGOFAMi_DES,8,NoMode,CSM_SYNCHRONOUS};
//CsmJob job1_CsmJob ={1,FALSE,1,FALSE,0,0,0,0};

CsmHashConfig job_CsmHashConfig [hash_jobs] ={
{CRYPTO_ALGOFAM_SHA1,8,20,CRYPTO_PROCESSING_SYNC},
{CRYPTO_ALGOFAM_SHA2_224,8,28,CRYPTO_PROCESSING_SYNC}                                         
};

/*CsmJob job_CsmJob[hash_jobs]={

{0,FALSE,1,FALSE,0,0,0,0},{1,FALSE,1,FALSE,0,0,0,0}
};
*/

//CsmKeys job_CsmKeys[hash_jobs]={{1,FALSE,2},{2,FALSE,3}};//csm key -cryif key}
CsmEncryptConfig job_CsmEncryptConfig[enc_jobs]={
{CRYPTO_ALGOFAM_3DES,8,8,CRYPTO_PROCESSING_SYNC},
{CRYPTO_ALGOFAM_AES,8,8,CRYPTO_PROCESSING_SYNC}

};
CsmEncryptConfig job_CsmDecryptConfig[enc_jobs]={
{CRYPTO_ALGOFAM_3DES,8,8,CRYPTO_PROCESSING_SYNC,8},
{CRYPTO_ALGOFAM_AES,8,8,CRYPTO_PROCESSING_SYNC,8}

};
