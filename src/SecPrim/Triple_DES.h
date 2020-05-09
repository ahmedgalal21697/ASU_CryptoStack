/*
 * Triple_DES.h
 *
 *  Created on: Apr 24, 2020
 *      Author: lenovo
 */

#ifndef TRIPLE_DES_H_
#define TRIPLE_DES_H_

#define uint64_t unsigned long long
#define uint32_t unsigned int
#define uint8_t unsigned char
#define LB32 0x00000001             //32 BT MASKELEME sol bit 32
#define LB64 0x0000000000000001     //64 BT MASKELEME sol bit 64
#define L64_MASK 0x00000000ffffffff //SMETR sol bit simetri alma
#define H64_MASK 0xffffffff00000000 //SMETR son hal

uint64_t triple_des_decrypt(uint8_t input[], uint64_t key[]);
uint64_t triple_des_encrypt(uint8_t input[], uint64_t key[]);

#endif /* TRIPLE_DES_H_ */
