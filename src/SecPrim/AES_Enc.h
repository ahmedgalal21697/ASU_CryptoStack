// Include stdio.h for standard input/output.
// Used for giving output to the screen.
#include<stdio.h>

#define AES_Enc_BLOCK_SIZE 16               // AES outputs a 16 byte

// The number of columns comprising a state in AES. This is a constant in AES. Value=4
#define Nb 4

// in - it is the array that holds the plain text to be encrypted.
// out - it is the array that holds the key for encryption.
// state - the array that holds the intermediate results during encryption.
unsigned char in[16], out[16], state[4][4];



void encrypt_AES(const unsigned char in[],int data_len,unsigned char out[]);
