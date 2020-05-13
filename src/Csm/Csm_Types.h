/*
 *  -------------------------------------------------------------------------------------------------------------------
 *  FILE DESCRIPTION
 *  -----------------------------------------------------------------------------------------------------------------*/
/*!        \file  Csm_Types.h
 *        \brief  MICROSAR Crypto Service Manager (CSM)
 *
 *      \details  Implementation of the MICROSAR Crypto Service Manager types (CSM)
 *
 *********************************************************************************************************************/

#ifndef CSM_TYPES_H
#define CSM_TYPES_H

/**********************************************************************************************************************
 *  INCLUDES
 *********************************************************************************************************************/
#include "Std_Types.h"

/**********************************************************************************************************************
 *  LOCAL CONSTANT MACROS
 *********************************************************************************************************************/
#define CRYPTO_E_BUSY ((Std_ReturnType)0x02U)				/* The service request failed because the service is still busy */
#define CRYPTO_E_SMALL_BUFFER ((Std_ReturnType)0x03U)		/* The service request failed because the provided buffer is too small to store the result */
#define CRYPTO_E_ENTROPY_EXHAUSTION ((Std_ReturnType)0x04U) /* The service request failed because the entropy of the random number generator is exhausted */
#define CRYPTO_E_QUEUE_FULL ((Std_ReturnType)0x05U)			/* The service request failed because the queue is full */
#define CRYPTO_E_KEY_READ_FAIL ((Std_ReturnType)0x06U)		/* The service request failed because read access was denied */
#define CRYPTO_E_KEY_WRITE_FAIL ((Std_ReturnType)0x07U)		/* The service request failed because the writing access failed */
#define CRYPTO_E_KEY_NOT_AVAILABLE ((Std_ReturnType)0x08U)	/* The service request failed because the key is not available */
#define CRYPTO_E_KEY_NOT_VALID ((Std_ReturnType)0x09U)		/* The service request failed because the key is invalid */
#define CRYPTO_E_KEY_SIZE_MISMATCH ((Std_ReturnType)0x0AU)	/* The service request failed because the key size does not match */
#define CRYPTO_E_COUNTER_OVERFLOW ((Std_ReturnType)0x0BU)	/* The service request failed because the counter is overflowed */
#define CRYPTO_E_JOB_CANCELED ((Std_ReturnType)0x0CU)		/* The service request failed because the Job has been canceled */

typedef Std_ReturnType Csm_ResultType;

#define E_SMALL_BUFFER ((Csm_ResultType)0x02U)		 /* The service request failed because the provided buffer is too small to store the result. */
#define E_ENTROPY_EXHAUSTION ((Csm_ResultType)0x03U) /* The service request failed because the entropy of random number generator is exhausted. */
#define E_KEY_READ_FAIL ((Csm_ResultType)0x04U)		 /* The service request failed because read access was denied. */
#define E_KEY_NOT_AVAILABLE ((Csm_ResultType)0x05U)	 /* The service request failed because the key is not available. */
#define E_KEY_NOT_VALID ((Csm_ResultType)0x06U)		 /* The service request failed because key was not valid. */
#define E_JOB_CANCELED ((Csm_ResultType)0x07U)		 /* The service request failed because the job was canceled */

/* Enumeration of the algorithm family */
typedef enum
{
	CRYPTO_ALGOFAM_NOT_SET,		  /*  Algorithm family is not set */
	CRYPTO_ALGOFAM_SHA1,		  /* SHA1 hash */
	CRYPTO_ALGOFAM_SHA2_224,	  /* SHA2-224 hash */
	CRYPTO_ALGOFAM_SHA2_256,	  /* SHA2-256 hash */
	CRYPTO_ALGOFAM_SHA2_384,	  /* SHA2-384 hash */
	CRYPTO_ALGOFAM_SHA2_512,	  /* SHA2-512 hash */
	CRYPTO_ALGOFAM_SHA2_512_224,  /* SHA2-512/224 hash */
	CRYPTO_ALGOFAM_SHA2_512_256,  /* SHA2-512/256 hash */
	CRYPTO_ALGOFAM_SHA3_224,	  /* SHA3-224 hash */
	CRYPTO_ALGOFAM_SHA3_256,	  /* SHA3-256 hash */
	CRYPTO_ALGOFAM_SHA3_384,	  /* SHA3-384 hash */
	CRYPTO_ALGOFAM_SHA3_512,	  /* SHA3-512 hash */
	CRYPTO_ALGOFAM_SHAKE128,	  /* SHAKE128 hash */
	CRYPTO_ALGOFAM_SHAKE256,	  /* SHAKE256 hash */
	CRYPTO_ALGOFAM_RIPEMD160,	  /* RIPEMD hash */
	CRYPTO_ALGOFAM_BLAKE_1_256,	  /* BLAKE-1-256 hash */
	CRYPTO_ALGOFAM_BLAKE_1_512,	  /* BLAKE-1-512 hash */
	CRYPTO_ALGOFAM_BLAKE_2s_256,  /* BLAKE-2s-256 hash */
	CRYPTO_ALGOFAM_BLAKE_2s_512,  /* BLAKE-2s-512 hash */
	CRYPTO_ALGOFAM_3DES,		  /* 3DES cipher */
	CRYPTO_ALGOFAM_AES,			  /* AES cipher */
	CRYPTO_ALGOFAM_CHACHA,		  /* ChaCha cipher */
	CRYPTO_ALGOFAM_RSA,			  /* RSA cipher */
	CRYPTO_ALGOFAM_ED25519,		  /* ED22518 elliptic curve */
	CRYPTO_ALGOFAM_BRAINPOOL,	  /* Brainpool elliptic curve */
	CRYPTO_ALGOFAM_ECCNIST,		  /* NIST ECC elliptic curves */
	CRYPTO_ALGOFAM_SECURECOUNTER, /* Secure Counter */
	CRYPTO_ALGOFAM_RNG,			  /* Random Number Generator */
	CRYPTO_ALGOFAM_SIPHASH,		  /* SipHash */
	CRYPTO_ALGOFAM_ECIES,		  /* ECIES Cipher */
	CRYPTO_ALGOFAM_CUSTOM,		  /* Custom algorithm family */
} Crypto_AlgorithmFamilyType;
/* Enumeration of the algorithm mode */
typedef enum
{
	CRYPTO_ALGOMODE_NOT_SET,		   /* Algorithm key is not set */
	CRYPTO_ALGOMODE_ECB,			   /* Blockmode: Electronic Code Book */
	CRYPTO_ALGOMODE_CBC,			   /* Blockmode: Cipher Block Chaining */
	CRYPTO_ALGOMODE_CFB,			   /* Blockmode: Cipher Feedback Mode */
	CRYPTO_ALGOMODE_OFB,			   /* Blockmode: Output Feedback Mode */
	CRYPTO_ALGOMODE_CTR,			   /* Blockmode: Counter Mode */
	CRYPTO_ALGOMODE_GCM,			   /* Blockmode: Galois/Counter Mode */
	CRYPTO_ALGOMODE_XTS,			   /* XOR-encryption-based tweaked-codebook mode with ciphertext stealing */
	CRYPTO_ALGOMODE_RSAES_OAEP,		   /* RSA Optimal Asymmetric Encryption Padding */
	CRYPTO_ALGOMODE_RSAES_PKCS1_v1_5,  /* RSA encryption/decryption with PKCS#1 v1.5 padding */
	CRYPTO_ALGOMODE_RSASSA_PSS,		   /* RSA Probabilistic Signature Scheme */
	CRYPTO_ALGOMODE_RSASSA_PKCS1_v1_5, /* RSA signature with PKCS#1 v1.5 */
	CRYPTO_ALGOMODE_8ROUNDS,		   /* 8 rounds (e.g. ChaCha8) */
	CRYPTO_ALGOMODE_12ROUNDS,		   /* 12 rounds (e.g. ChaCha12) */
	CRYPTO_ALGOMODE_20ROUNDS,		   /* 20 rounds (e.g. ChaCha20) */
	CRYPTO_ALGOMODE_HMAC,			   /* Hashed-based MAC */
	CRYPTO_ALGOMODE_CMAC,			   /* Cipher-based MAC */
	CRYPTO_ALGOMODE_GMAC,			   /* Galois MAC */
	CRYPTO_ALGOMODE_CTRDRBG,		   /* Counter-based Deterministic Random Bit Generator */
	CRYPTO_ALGOMODE_SIPHASH_2_4,	   /* Siphash-2-4 CRYPTO_ALGOMODE_SIPHASH_4_8 0x14 Siphash-4-8 */
	CRYPTO_ALGOMODE_CUSTOM,			   /* Custom algorithm mode */
} Crypto_AlgorithmModeType;

/* Enumeration of the current job state */
typedef enum
{
	CRYPTO_JOBSTATE_IDLE,	/*Job is in the state "idle". This state is reached after
                                                   	Csm_Init() or when the "Finish" state is finished*/
	CRYPTO_JOBSTATE_ACTIVE, /*Job is in the state "active". There was already some input
                                                        	or there are intermediate results. This state is reached,
                                                          	when the "update" or "start" operation finishes*/
} Crypto_JobStateType;
/* Enumeration of the kind of the service */
typedef enum
{
	CRYPTO_HASH,				/* Hash Service */
	CRYPTO_MACGENERATE,			/* MacGenerate Service */
	CRYPTO_MACVERIFY,			/*  MacVerify Service */
	CRYPTO_ENCRYPT,				/*  Encrypt Service */
	CRYPTO_DECRYPT,				/*  Decrypt Service */
	CRYPTO_AEADENCRYPT,			/*  AEADEncrypt Service */
	CRYPTO_AEADDECRYPT,			/*  AEADDecrypt Service */
	CRYPTO_SIGNATUREGENERATE,	/*  SignatureGenerate Service */
	CRYPTO_SIGNATUREVERIFY,		/*  SignatureVerify Service */
	CRYPTO_SECCOUNTERINCREMENT, /*  SecureCounterIncrement Service */
	CRYPTO_SECCOUNTERREAD,		/*  SecureCounterRead Service */
	CRYPTO_RANDOMGENERATE,		/*  RandomGenerate Service */
} Crypto_ServiceInfoType;
/*Enumeration which operation shall be performed. This enumeration is constructed from a bit mask,
  where the first bit indicates "Start", the second "Update" and the third "Finish"*/
typedef enum
{
	CRYPTO_OPERATIONMODE_START,		  /* Operation Mode is "Start". The job's state shall be reset, i.e. previous input data and intermediate results shall be deleted. */
	CRYPTO_OPERATIONMODE_UPDATE,	  /* Operation Mode is "Update". Used to calculate intermediate results. */
	CRYPTO_OPERATIONMODE_STREAMSTART, /* Operation Mode is "Stream Start". Mixture of "Start" and "Update". Used for streaming. */
	CRYPTO_OPERATIONMODE_FINISH,	  /* Operation Mode is "Finish". The calculations shall be finalized. */
	CRYPTO_OPERATIONMODE_SINGLECALL,  /* Operation Mode is "Single Call". Mixture of "Start", "Update" and "Finish" */
} Crypto_OperationModeType;
/* Structure which determines the exact algorithm. Note, not every algorithm needs to specify all fields. AUTOSAR shall only allow valid combinations */
typedef struct
{
	Crypto_AlgorithmFamilyType family;			/* The family of the algorithm */
	Crypto_AlgorithmFamilyType secondaryFamily; /* The secondary family of the algorithm */
	uint32 keyLength;							/* The key length in bits to be used with that algorithm */
	Crypto_AlgorithmModeType mode;				/* The operation mode to be used with that algorithm */
} Crypto_AlgorithmInfoType;
/* Enumeration of the processing type */
typedef enum
{
	CRYPTO_PROCESSING_ASYNC, /*  Asynchronous job processing */
	CRYPTO_PROCESSING_SYNC,	 /*  Synchronous job processing */
} Crypto_ProcessingType;
/* Enumeration of the result type of verification operations */
typedef enum
{
	CRYPTO_E_VER_OK,	 /* The result of the verification is "true", i.e. the two compared elements are identical. This return code shall be given as value "0" */
	CRYPTO_E_VER_NOT_OK, /* The result of the verification is "false", i.e. the two compared elements are not identical. This return code shall be given as value "1". */
} Crypto_VerifyResultType;
/* Structure which contains input and output information depending on the job and the crypto primitive */
typedef struct
{
	const uint8 *inputPtr;				/* Pointer to the input data. */
	uint32 inputLength;					/* Contains the input length in bytes. */
	const uint8 *secondaryInputPtr;		/* Pointer to the secondary input data (for MacVerify, SignatureVerify) */
	uint32 secondaryInputLength;		/* Contains the secondary input length in bytes. */
	const uint8 *tertiaryInputPtr;		/* Pointer to the tertiary input data (for MacVerify, SignatureVerify). */
	uint32 tertiaryInputLength;			/* Contains the tertiary input length in bytes. */
	uint8 *outputPtr;					/* Pointer to the output data. */
	uint32 *outputLengthPtr;			/* Holds a pointer to a memory location containing the output length in bytes. */
	uint8 *secondaryOutputPtr;			/* Pointer to the secondary output data. */
	uint32 *secondaryOutputLengthPtr;	/* Holds a pointer to a memory location containing the secondary output length in bytes. */
	uint64 input64;						/* versatile input parameter */
	Crypto_VerifyResultType *verifyPtr; /* Output pointer to a memory location holding a Crypto_VerifyResultType */
	uint64 *output64Ptr;				/* Output pointer to a memory location holding a uint64. */
	Crypto_OperationModeType mode;		/* Indicator of the mode(s)/operation(s) to be performed */
} Crypto_JobPrimitiveInputOutputType;
/* Structure which contains job information (job ID and job priority) */
typedef struct
{
	const uint32 jobId;		  /* The family of the algorithm */
	const uint32 jobPriority; /* Specifies the importance of the job (the higher, the more important) */
} Crypto_JobInfoType;
/* Structure which contains basic information about the crypto primitive */
typedef struct
{
	const uint32 resultLength;				  /* Contains the result length in bytes. */
	const Crypto_ServiceInfoType service;	  /* Contains the enum of the used service, e.g. Encrypt */
	const Crypto_AlgorithmInfoType algorithm; /* Contains the information of the used  algorithm */
} Crypto_PrimitiveInfoType;
/* Structure which contains further information, which depends on the job and the crypto primitive */
typedef struct
{
	const uint32 callbackId;					   /* Identifier of the callback function, to be called, if the configured service finished */
	const Crypto_PrimitiveInfoType *primitiveInfo; /* Pointer to a structure containing further configuration of the crypto primitives */
	const uint32 secureCounterId;				   /* Identifier of a secure counter */
	const uint32 cryIfKeyId;					   /* Identifier of the CryIf key */
	const Crypto_ProcessingType processingType;	   /* Determines the synchronous or asynchronous behavior */
	const boolean callbackUpdateNotification;	   /* Indicates, whether the callback function shall be called, if the UPDATE operation has finished */
} Crypto_JobPrimitiveInfoType;
/* Structure which contains further information, which depends on the job and the crypto primitive */
typedef struct
{
	const uint32 jobId;											/* Identifier for the job structure */
	Crypto_JobStateType jobState;								/* Determines the current job state */
	Crypto_JobPrimitiveInputOutputType jobPrimitiveInputOutput; /* Structure containing input and output information depending on the job and the crypto primitive. */
	const Crypto_JobPrimitiveInfoType *jobPrimitiveInfo;		/* Pointer to a structure containing further information, which depends on the job and the crypto primitive */
	const Crypto_JobInfoType *jobInfo;							/* Pointer to a structure containing further information, which depends on the job and the crypto primitive */
	uint32 cryptoKeyId;											/* Identifier of the Crypto Driver key. The identifier shall be written by the Crypto Interface */
} Crypto_JobType;


#endif /* CSM_TYPES_H */
