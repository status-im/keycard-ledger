#ifdef SECURE_CHANNEL
#include "crypto.h"
#include "ctaes.h"

int aes_cbc_iso9797m2_encrypt(uint8_t* key, uint8_t* iv, uint8_t* data, int data_len, uint8_t* out) {
  int padded_len = data_len + ((data_len + 1) % 16) + 1;

  data[data_len++] = 0x80;

  while(padded_len > data_len) {
    data[data_len++] = 0x00;
  }

  AES256_ctx aes256;
  AES256_init(&aes256, key);

  int block_count = (padded_len / 16);

  uint8_t block[16];

  for (int i = 0; i < 16; i++) {
    block[i] = iv[i] ^ data[i];
  }

  data += 16;

  AES256_encrypt_block(&aes256, block, out);

  while (--block_count) {
    for (int i = 0; i < 16; i++) {
      block[i] = out[i] ^ data[i];
    }

    data += 16;
    out += 16;

    AES256_encrypt_block(&aes256, out, block);
  }

  return padded_len;
}

int aes_cbc_iso9797m2_decrypt(uint8_t* key, uint8_t* iv, uint8_t* data, int data_len, uint8_t* out) {
  if (data_len % 16) {
    return -1;
  }

  AES256_ctx aes256;
  AES256_init(&aes256, key);

  uint8_t* cipher = data + data_len;
  uint8_t* plain = out + data_len;

  while (cipher > (data + 16)) {
    AES256_decrypt_block(&aes256, plain, cipher);
    cipher -= 16;

    for (int i = 0; i < 16; i++) {
      plain[i] = plain[i] ^ cipher[i];
    }

    plain -= 16;
  }

  AES256_decrypt_block(&aes256, plain, cipher);

  for (int i = 0; i < 16; i++) {
    plain[i] = plain[i] ^ iv[i];
  }

  while(data_len > 1 && out[--data_len] != 0x80) ;

  return data_len;
}

int aes_cmac_sign(uint8_t* key, uint8_t* data, int data_len, uint8_t* out) {

}

uint8_t aes_cmac_verify(uint8_t* key, uint8_t* data, int data_len, uint8_t* signature) {

}
#endif
