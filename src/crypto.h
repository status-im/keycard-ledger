#ifndef _CRYPTO_H_
#define _CRYPTO_H_

#include <stdint.h>
#include <stdlib.h>

int aes_cbc_iso9797m2_encrypt(uint8_t* key, uint8_t* iv, uint8_t* data, int data_len, uint8_t* out);
int aes_cbc_iso9797m2_decrypt(uint8_t* key, uint8_t* iv, uint8_t* data, int data_len, uint8_t* out);

int aes_encrypt_block(uint8_t* key, uint8_t* data, uint8_t* out);
int aes_cmac_compute(uint8_t* key, uint8_t* iv, uint8_t* data, int data_len, uint8_t* out);

#endif
