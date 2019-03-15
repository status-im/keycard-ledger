#ifndef _SECURE_CHANNEL_H_
#define _SECURE_CHANNEL_H_

#include <stdint.h>
#include <stdlib.h>

#define SC_IV_LEN 16
#define SC_SECRET_LENGTH 32
#define SC_MAX_PAIRINGS 5
#define SC_PAIRING_KEY_LEN (SC_SECRET_LENGTH + 1)
#define SC_PAIRING_ARRAY_LEN (SC_PAIRING_KEY_LEN * SC_MAX_PAIRINGS)
#define SC_PAIRING_PASS_LEN 6

#define SC_STATE_CLOSED 0
#define SC_STATE_OPENING 1
#define SC_STATE_OPEN 2

#if defined(SECURE_CHANNEL)
#define ASSERT_OPEN_SECURE_CHANNEL() if (sc_get_status() != SC_STATE_OPEN) THROW(0x6985);
#else
#define ASSERT_OPEN_SECURE_CHANNEL()
#endif

void sc_nvm_init();
void sc_init();

void sc_preprocess_apdu(unsigned char* apdu);
void sc_postprocess_apdu(unsigned char* apdu, volatile unsigned int *tx);

void sc_generate_pairing_password(unsigned int ignored);

void sc_pair(uint8_t p1, uint8_t p2, uint8_t lc, unsigned char* apdu_data, unsigned char* apdu_out, volatile unsigned int *flags, volatile unsigned int *tx);
void sc_unpair(uint8_t p1, uint8_t p2, uint8_t lc, unsigned char* apdu_data, unsigned char* apdu_out, volatile unsigned int *flags, volatile unsigned int *tx);

void sc_open_secure_channel(uint8_t p1, uint8_t p2, uint8_t lc, unsigned char* apdu_data, unsigned char* apdu_out, volatile unsigned int *flags, volatile unsigned int *tx);
void sc_mutually_authenticate(uint8_t p1, uint8_t p2, uint8_t lc, unsigned char* apdu_data, unsigned char* apdu_out, volatile unsigned int *flags, volatile unsigned int *tx);

uint8_t sc_get_status();
uint8_t sc_available_pairings();
void sc_close();
void sc_copy_public_key(uint8_t* dst);
#endif
