#include "adaptor.h"


/**********************************************************************************************************************
 * AlgoSHA1_adaptor()
 *********************************************************************************************************************/
/*! \brief         adaptor between crypto_processJob() and sha1 functions.
 *  \details       This function creates buffer to store hash_final function output then its o/p pointer hash points to
 *                 the buffer.
 *
 *  \param[in]     data                    Pointer to i/p data
 *  \param[in]     len                     Param len holds the length of i/p data.
 *  \param[in,out] NONE
 *
 *  \param[out]    hash                    Pointer to pointer buf1 which stores hash o/p.
 *  \pre           NONE
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *********************************************************************************************************************/

void AlgoSHA1_adaptor( const uint8 data[],uint32 len,uint8** hash)

{
    SHA1_CTX *ctx;
    uint8 buf1[SHA1_BLOCK_SIZE];
	sha1_init(ctx);
	sha1_update(ctx, data, len);
	sha1_final(ctx,buf1 );
	
	   *hash=&buf1[0];
}
/**********************************************************************************************************************
 * AlgoSHA244_adaptor()
 *********************************************************************************************************************/
/*! \brief         adaptor between crypto_processJob() and sha224 functions.
 *  \details       This function creates buffer to store hash_final function output then its o/p pointer hash points to
 *                 the buffer.
 *
 *  \param[in]     data                    Pointer to i/p data
 *  \param[in]     len                     Param len holds the length of i/p data.
 *  \param[in,out] NONE
 *
 *  \param[out]    hash                    Pointer to pointer buf1 which stores hash o/p.
 *  \pre           NONE
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *********************************************************************************************************************/
void AlgoSHA224_adaptor( const uint8 data[],uint32 len,uint8** hash)
{
    SHA224_CTX *ctx;
    uint8 buf1[SHA224_BLOCK_SIZE];
	sha224_init(ctx);
	sha224_update(ctx, data, len);
	sha224_final(ctx, buf1);
   *hash=&buf1[0];
}
/**********************************************************************************************************************
 * AlgoSHA256_adaptor()
 *********************************************************************************************************************/
/*! \brief         adaptor between crypto_processJob() and sha256 functions.
 *  \details       This function creates buffer to store hash_final function output then its o/p pointer hash points to
 *                 the buffer.
 *
 *  \param[in]     data                    Pointer to i/p data
 *  \param[in]     len                     Param len holds the length of i/p data.
 *
 *  \param[out]    hash                    Pointer to pointer buf1 which stores hash o/p.
 *  \pre           NONE
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *********************************************************************************************************************/
void AlgoSHA256_adaptor( const uint8 data[],uint32 len,uint8** hash)
{
    SHA256_CTX *ctx;
    uint8 buf1[SHA256_BLOCK_SIZE];
	sha256_init(ctx);
	sha256_update(ctx, data, len);
	sha256_final(ctx, buf1);
    *hash=&buf1[0];
}

/**********************************************************************************************************************
 * AlgoSHA384_adaptor()
 *********************************************************************************************************************/
/*! \brief         adaptor between crypto_processJob() and sha384 functions.
 *  \details       This function creates buffer to store hash_final function output then its o/p pointer hash points to
 *                 the buffer.
 *
 *  \param[in]     data                    Pointer to i/p data
 *  \param[in]     len                     Param len holds the length of i/p data.
 *
 *  \param[out]    hash                    Pointer to pointer buf1 which stores hash o/p.
 *  \pre           NONE
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *********************************************************************************************************************/
void AlgoSHA384_adaptor( const uint8 data[],uint32 len,uint8 ** hash)
{
    SHA384_CTX *ctx;
    uint8 buf1[SHA384_BLOCK_SIZE];
	sha384_init(ctx);
	sha384_update(ctx, data, len);
	sha384_final(ctx, buf1);
	*hash=&buf1[0];

}
/**********************************************************************************************************************
 * AlgoSHA512_adaptor()
 *********************************************************************************************************************/
/*! \brief         adaptor between crypto_processJob() and sha512 functions.
 *  \details       This function creates buffer to store hash_final function output then its o/p pointer hash points to
 *                 the buffer.
 *
 *  \param[in]     data                    Pointer to i/p data
 *  \param[in]     len                     Param len holds the length of i/p data.
 *
 *  \param[out]    hash                    Pointer to pointer buf1 which stores hash o/p.
 *  \pre           NONE
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *********************************************************************************************************************/
void AlgoSHA512_adaptor( const uint8 data[],uint32 len,uint8 ** hash)

{   SHA512_CTX *ctx;
    uint8 buf1[SHA512_BLOCK_SIZE];
	sha512_init(ctx);
	sha512_update(ctx, data, len);
	sha512_final(ctx, buf1);
	*hash=&buf1[0];
  
}
/**********************************************************************************************************************
 * AlgoMD5_adaptor()
 *********************************************************************************************************************/
/*! \brief         adaptor between crypto_processJob() and MD5 functions.
 *  \details       This function creates buffer to store md5_final function output then its o/p pointer hash points to
 *                 the buffer.
 *
 *  \param[in]     data                    Pointer to i/p data
 *  \param[in]     len                     Param len holds the length of i/p data.
 *
 *  \param[out]    hash                    Pointer to pointer buf1 which stores MD5 o/p.
 *  \pre           NONE
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *********************************************************************************************************************/

void AlgoMD5_adaptor( const uint8 data[],uint32 len,uint8** hash)
{
    MD5_CTX *ctx;
    uint8 buf1[MD5_BLOCK_SIZE];
	md5_init(ctx);
	md5_update(ctx, data, len);
	md5_final(ctx, buf1);
	*hash= &buf1[0];

}



