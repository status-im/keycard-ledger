#ifdef SECURE_CHANNEL
#include "crypto.h"
#include "ctaes.h"

AES256_ctx aes256;

static void aes_cbc_encrypt(uint8_t* key, uint8_t* iv, uint8_t* data, int data_len, uint8_t* out, uint8_t out_increment) {
  AES256_init(&aes256, key);

  int block_count = (data_len / 16);

  uint8_t block[16];

  for (int i = 0; i < 16; i++) {
    block[i] = iv[i] ^ data[i];
  }

  data += 16;

  AES256_encrypt_block(&aes256, out, block);

  while (--block_count) {
    for (int i = 0; i < 16; i++) {
      block[i] = out[i] ^ data[i];
    }

    data += 16;
    out += out_increment;

    AES256_encrypt_block(&aes256, out, block);
  }
}

int aes_encrypt_block(uint8_t* key, uint8_t* data, uint8_t* out) {
  AES256_init(&aes256, key);
  AES256_encrypt_block(&aes256, out, data);

  return 16;
}

int aes_cbc_iso9797m2_encrypt(uint8_t* key, uint8_t* iv, uint8_t* data, int data_len, uint8_t* out) {
  int padded_len = data_len + (16 - ((data_len + 1) % 16)) + 1;

  data[data_len++] = 0x80;

  while(padded_len > data_len) {
    data[data_len++] = 0x00;
  }

  aes_cbc_encrypt(key, iv, data, padded_len, out, 16);

  return padded_len;
}

int aes_cbc_iso9797m2_decrypt(uint8_t* key, uint8_t* iv, uint8_t* data, int data_len, uint8_t* out) {
  if (data_len % 16) {
    return -1;
  }

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

int aes_cmac_compute(uint8_t* key, uint8_t* iv, uint8_t* data, int data_len, uint8_t* out) {
  if (data_len % 16) {
    return -1;
  }

  aes_cbc_encrypt(key, iv, data, data_len, out, 0);
  return 16;
}

#endif
