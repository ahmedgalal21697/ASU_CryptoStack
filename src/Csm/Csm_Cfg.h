/*
 *  -------------------------------------------------------------------------------------------------------------------
 *  FILE DESCRIPTION
 *  -----------------------------------------------------------------------------------------------------------------*/
/*!        \file  Csm_Cfg.h
 *        \brief  MICROSAR Crypto Service Manager (CSM)
 *
 *      \details  Implementation of the MICROSAR Crypto Service Manager configuration (CSM)
 *
 *********************************************************************************************************************/
 
 
#ifndef CSM_CFG_H
#define CSM_CFG_H


/**********************************************************************************************************************
 *  INCLUDES
 *********************************************************************************************************************/
#include "Platform_Types.h"
#include "Csm_Types.h"

/**********************************************************************************************************************
 *  LOCAL CONSTANT MACROS
 *********************************************************************************************************************/
 #define DIO_DEV_ERROR_DETECT (STD_ON)

 
#define hash_jobs 2
#define enc_jobs 2

#define CsmJobs_no 100

/* Container for configuration of CSM job. The container name
serves as a symbolic name for the identifier of a job
configuration. */
typedef struct {
/* Identifier of the CSM job. The set of actually configured identifiers shall be
consecutive and gapless. */
const uint32 CsmJobId ;
/* This parameter indicates, whether the callback function shall be called, if
the UPDATE operation has been finished. */
unsigned char CsmJobPrimitiveCallbackUpdateNotification;
/* Priority of the job.
The higher the value, the higher the job's priority. */
const uint32 CsmJobPriority;
/* Does the job need RTE interfaces?
True: the job needs RTE interfaces
False: the job needs no RTE interfaces */
unsigned char CsmJobUsePort;
/* This parameter refers to the key which shall be used for the CsmPrimitive.
It's possible to use a CsmKey for different jobs */
uint16 CsmJobKeyRef; 
/* This parameter refers to the used CsmCallback.
The referred CsmCallback is called when the crypto job has been finished */
uint16 CsmJobPrimitiveCallbackRef; 
/* This parameter refers to the used CsmPrimitive.
Different jobs may refer to one CsmPrimitive. The referred CsmPrimitive
provides detailed information on the actual cryptographic routine. */
uint16 CsmJobPrimitiveRef;
/* This parameter refers to the queue.
The queue is used if the underlying crypto driver object is busy. The queue
refers also to the channel which is used. */
uint16 CsmJobQueueRef;
}CsmJob;

 CsmJob CsmJobs[CsmJobs_no];
/* Container for configuration of a CSM key. The container name serves as a
symbolic name for the identifier of a key configuration. */
typedef struct {
/* Identifier of the CsmKey. The set of actually configured identifiers shall be
consecutive and gapless. */
uint16 CsmKeyId;
/* Does the key need RTE interfaces?
True: RTE interfaces used for this key
False: No RTE interfaces used for this key */
unsigned char CsmKeyUsePort;
/* This parameter refers to the used CryIfKey. The underlying CryIfKey refers
to a specific CryptoKey in the Crypto Driver. */
uint16 CsmKeyRef; 
}CsmKey;
/* Container for configuration of a CSM queue. The container
name serves as a symbolic name for the identifier of a queue
configuration.
A queue has two tasks:
1. queue jobs which cannot be processed since the underlying
hardware is busy and
2. refer to channel which shall be used */
typedef struct{
/* Size of the CsmQueue. If jobs cannot be processed by the underlying
hardware since the hardware is busy, the jobs stay in the prioritized queue.
If the queue is full, the next job will be rejected. */
uint16 CsmQueueSize;
/* Refers to the underlying Crypto Interface channel. */
uint16 CsmChannelRef;
}CsmQueue;


/* Container for configuration of a CSM hash. The container
name serves as a symbolic name for the identifier of a key
configuration. */
typedef struct {
/* Determines the algorithm family used for the crypto service. This parameter defines
the most significant part of the algorithm. */
Crypto_AlgorithmFamilyType CsmAlgorithmFamily;
/* Max size of the input data length in bytes */
uint8 CsmHashDataMaxLength;
/* Determines how the interface shall be used for that primitive. Synchronous
processing returns with the result while asynchronous processing returns without
processing the job. The caller will be notified by the corresponding callback. */
Crypto_ProcessingType CsmHashProcessing;
/* Size of the output hash length in bytes */
uint8 CsmHashResultLength;
}CsmHashConfig	;





/* Container for configuration of a CSM mac generation interface.
The container name serves as a symbolic name for the
identifier of a MAC generation interface. */
typedef struct {
uint8 priority;
/* Determines the algorithm family used for the crypto service. This parameter defines
the most significant part of the algorithm. */
Crypto_AlgorithmFamilyType CsmMacGenerateAlgorithmFamily;
/* Size of the MAC key in bytes */
uint16 CsmMacGenerateAlgorithmKeyLength;
/* Max size of the input data length in bytes */
uint16 CsmMacGenerateDataMaxLength;
/* Determines how the interface shall be used for that primitive. Synchronous
processing returns with the result while asynchronous processing returns without
processing the job. The caller will be notified by the corresponding callback. */
Crypto_ProcessingType CsmMacGenerateProcessing;
/* Size of the output MAC length in bytes */
uint16 CsmMacGenerateResultLength;

}CsmMacGenerateConfig	;

/* Container for configuration of a CSM encryption interface. The container
name serves as a symbolic name for the identifier of an encryption
interface. */
typedef struct {
uint8 priority;
/* Determines the algorithm family used for the crypto service. This parameter defines
the most significant part of the algorithm. */
Crypto_AlgorithmFamilyType CsmEncryptAlgorithmFamily;
/* Size of the encryption key in bytes */
uint8 CsmEncryptAlgorithmKeyLength;
/* Max size of the input plaintext length in bytes */
uint8 CsmEncryptDataMaxLength;
/* Determines how the interface shall be used for that primitive. Synchronous
processing returns with the result while asynchronous processing returns without
processing the job. The caller will be notified by the corresponding callback */
Crypto_ProcessingType CsmEncryptProcessing;
/* Max size of the output cipher length in bytes */
uint8 CsmEncryptResultMaxLength;
	
}CsmEncryptConfig;

/* Container for configuration of a CSM decryption interface. The
container name serves as a symbolic name for the identifier of
an decryption interface. */
typedef struct {
uint8 priority;
/* Determines the algorithm family used for the crypto service. This parameter defines
the most significant part of the algorithm. */
Crypto_AlgorithmFamilyType CsmDecryptAlgorithmFamily;
/* Size of the encryption key in bytes */
uint8 CsmDecryptAlgorithmKeyLength;
/* Max size of the input ciphertext length in bytes */
uint8 CsmDecryptDataMaxLength;
/* Determines how the interface shall be used for that primitive. Synchronous
processing returns with the result while asynchronous processing returns without
processing the job. The caller will be notified by the corresponding callback */
Crypto_ProcessingType CsmDecryptProcessing;
/* Max size of the output plaintext length in bytes */
uint8 CsmDecryptResultMaxLength; 
	
}CsmDecryptConfig;


// why counter secure 
/*
CsmSecureCounterQueueRef Parent Container
CsmSecureCounterConfig Description
This parameter refers to the queue used for that secure counter
*/


#endif //CSM_CFG_H
