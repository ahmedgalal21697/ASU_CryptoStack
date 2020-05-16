 #ifndef ADAPTOR_H
 #define ADAPTOR_H
 
#include "SHA224.h"
#include "MD5.h"
#include "SHA1.h"
#include "SHA256.h"
#include "SHA384.h"
#include "SHA512.h"

 
void AlgoSHA1_adaptor( const uint8 data[],uint32 len,uint8** hash);
void AlgoSHA224_adaptor( const uint8 data[],uint32 len,uint8** hash);
void AlgoSHA256_adaptor( const uint8 data[],uint32 len,uint8** hash);
void AlgoSHA384_adaptor( const uint8 data[],uint32 len,uint8 ** hash);
void AlgoSHA512_adaptor( const uint8 data[],uint32 len,uint8 ** hash);
void AlgoMD5_adaptor( const uint8 data[],uint32 len,uint8 ** hash);
 
 
 
 
 
 
 
 
 
#endif
