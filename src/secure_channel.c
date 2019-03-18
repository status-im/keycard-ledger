#ifdef SECURE_CHANNEL

#include "secure_channel.h"
#include "defines.h"
#include "crypto.h"
#include "os.h"
#include "cx.h"
#include "os_io_seproxyhal.h"

#define PAIR_P1_FIRST_STEP 0x00
#define PAIR_P1_LAST_STEP 0x01

uint8_t N_pairings_real[SC_PAIRING_ARRAY_LEN];
#define N_pairings ((uint8_t*) PIC(&N_pairings_real))

cx_ecfp_private_key_t G_sc_private_key;
cx_ecfp_public_key_t G_sc_public_key;
uint8_t G_sc_secret[SC_SECRET_LENGTH];
char G_sc_pairing_password[SC_PAIRING_PASS_LEN + 1];
int8_t G_sc_preallocated_offset;
uint8_t G_sc_open;
uint8_t G_sc_session_data[SC_SECRET_LENGTH];
uint8_t G_sc_keys[SC_SECRET_LENGTH * 2];
uint8_t* G_sc_enc_key = G_sc_keys;
uint8_t* G_sc_mac_key = &G_sc_keys[SC_SECRET_LENGTH];

ux_menu_entry_t *G_main_menu;

#if defined(TARGET_BLUE)
//TODO: BLUE GUI
#elif defined(TARGET_NANOS)
const bagl_element_t ui_pair_nanos[] = {
  // {{type, userid, x, y, width, height, stroke, radius, fill, fgcolor, bgcolor, font_id, icon_id}, text, touch_area_brim, overfgcolor, overbgcolor, tap, out, over }
  {{BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF, 0, 0}, NULL, 0, 0, 0, NULL, NULL, NULL},

  {{BAGL_LABELINE, 0x00, 0, 12, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000, BAGL_FONT_OPEN_SANS_EXTRABOLD_11px|BAGL_FONT_ALIGNMENT_CENTER, 0  }, "Pairing password", 0, 0, 0, NULL, NULL, NULL},
  {{BAGL_LABELINE, 0x00, 0, 26, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000, BAGL_FONT_OPEN_SANS_EXTRABOLD_11px|BAGL_FONT_ALIGNMENT_CENTER, 0  }, G_sc_pairing_password, 0, 0, 0, NULL, NULL, NULL},
};

unsigned int ui_pair_nanos_button(unsigned int button_mask, unsigned int button_mask_counter) {
  UNUSED(button_mask);
  UNUSED(button_mask_counter);

  UX_MENU_DISPLAY(0, G_main_menu, NULL);
  return 0;
}
#endif

void sc_nvm_init() {
  uint8_t pairings[SC_PAIRING_ARRAY_LEN];
  os_memset(pairings, 0, SC_PAIRING_ARRAY_LEN);
  nvm_write(N_pairings, pairings, SC_PAIRING_ARRAY_LEN);
}

void sc_init(ux_menu_entry_t *main_menu) {
  G_main_menu = main_menu;
  cx_rng(G_sc_secret, SC_SECRET_LENGTH);
  cx_ecfp_generate_pair(CX_CURVE_256K1, &G_sc_public_key, &G_sc_private_key, 0);
  sc_close();
}

uint8_t sc_preallocate_pairing_index() {
  G_sc_preallocated_offset = -1;

  for (int i = 0; i < SC_PAIRING_ARRAY_LEN; i += SC_PAIRING_KEY_LEN) {
    if (N_pairings[i] == 0) {
      G_sc_preallocated_offset = i;
      return 1;
    }
  }

  return 0;
}

void sc_postprocess_apdu(unsigned char* apdu, volatile unsigned int *tx) {
  *tx = aes_cbc_iso9797m2_encrypt(G_sc_enc_key, G_sc_session_data, &apdu[SC_IV_LEN], *tx, &apdu[SC_IV_LEN]);
  uint8_t tmp[SC_IV_LEN];
  tmp[0] = *tx + SC_IV_LEN;
  os_memset(&tmp[OFFSET_CDATA], 0, SC_IV_LEN - 1);
  aes_encrypt_block(G_sc_mac_key, tmp, apdu);
  aes_cmac_compute(G_sc_mac_key, apdu, &apdu[SC_IV_LEN], *tx, apdu);
  os_memmove(G_sc_session_data, apdu, SC_IV_LEN);
  *tx += SC_IV_LEN;
}

void sc_preprocess_apdu(unsigned char* apdu) {
  int data_len = apdu[OFFSET_LC] - SC_IV_LEN;

  uint8_t mac[SC_IV_LEN];
  uint8_t tmp[SC_IV_LEN];

  os_memmove(tmp, apdu, OFFSET_CDATA);
  os_memset(&tmp[OFFSET_CDATA], 0, SC_IV_LEN - OFFSET_CDATA);

  aes_encrypt_block(G_sc_mac_key, tmp, mac);
  aes_cmac_compute(G_sc_mac_key, mac, &apdu[OFFSET_CDATA + SC_IV_LEN], data_len, mac);

  if (os_secure_memcmp(mac, &apdu[OFFSET_CDATA], SC_IV_LEN) != 0) {
    sc_close();
    THROW(0x6982);
  }

  int res = aes_cbc_iso9797m2_decrypt(G_sc_enc_key, G_sc_session_data, &apdu[OFFSET_CDATA + SC_IV_LEN], data_len, &apdu[OFFSET_CDATA + SC_IV_LEN]);

  if (res < 0) {
    sc_close();
    THROW(0x6982);
  }

  apdu[OFFSET_LC] = res;
  os_memmove(G_sc_session_data, &apdu[OFFSET_CDATA], SC_IV_LEN);
}

// This implementation assumes that the output size matches the key size.
void sc_pbkdf2_sha256(const char *pass, size_t pass_len, uint8_t *asalt, size_t salt_len, unsigned int rounds, uint8_t obuf[HASH_LEN]) {
	uint8_t d1[HASH_LEN];
  uint8_t d2[HASH_LEN];

	cx_hmac_sha256((unsigned char *) pass, pass_len, asalt, salt_len, d1);
	os_memmove(obuf, d1, HASH_LEN);

	for (unsigned int i = 1; i < rounds; i++) {
		cx_hmac_sha256((unsigned char *) pass, pass_len, d1, HASH_LEN, d2);
		os_memmove(d1, d2, HASH_LEN);
		for (unsigned int j = 0; j < HASH_LEN; j++) {
			obuf[j] ^= d1[j];
    }
	}

	os_memset(d1, 0, HASH_LEN);
  os_memset(d2, 0, HASH_LEN);
}

void sc_generate_pairing_password(unsigned int ignored) {
  cx_rng((unsigned char *) G_sc_pairing_password, SC_PAIRING_PASS_LEN);

  for (int i = 0; i < SC_PAIRING_PASS_LEN; i++) {
    G_sc_pairing_password[i] = '0' + (G_sc_pairing_password[i] % 10);
  }

  G_sc_pairing_password[SC_PAIRING_PASS_LEN] = '\0';

  uint8_t salt[] = "Keycard Pairing Password Salt\0\0\0\1";
  sc_pbkdf2_sha256(G_sc_pairing_password, SC_PAIRING_PASS_LEN, salt, sizeof(salt) - 1, 256, G_sc_secret);

  #if defined(TARGET_BLUE)
  // TODO: implement Ledger Blue UI
  #elif defined(TARGET_NANOS)
  UX_DISPLAY(ui_pair_nanos, NULL);
  #endif
}

void sc_pair_step1(unsigned char* apdu_data, unsigned char* apdu_out, volatile unsigned int *flags, volatile unsigned int *tx) {
  if (!sc_preallocate_pairing_index()) {
    THROW(0x6A84);
  }

  cx_sha256_t sha256;
  cx_sha256_init(&sha256);
  cx_hash((cx_hash_t *) &sha256, 0, G_sc_secret, SC_SECRET_LENGTH, NULL);
  cx_hash((cx_hash_t *) &sha256, CX_LAST, apdu_data, SC_SECRET_LENGTH, apdu_out);
  cx_rng(&apdu_out[HASH_LEN], HASH_LEN);
  *tx = (HASH_LEN * 2);

  cx_sha256_init(&sha256);
  cx_hash((cx_hash_t *) &sha256, 0, G_sc_secret, SC_SECRET_LENGTH, NULL);
  cx_hash((cx_hash_t *) &sha256, CX_LAST, &apdu_out[HASH_LEN], SC_SECRET_LENGTH, G_sc_session_data);
}

void sc_pair_step2(unsigned char* apdu_data, unsigned char* apdu_out, volatile unsigned int *flags, volatile unsigned int *tx) {
  if (G_sc_preallocated_offset == -1) {
    THROW(0x6A86);
  }

  if (os_memcmp(apdu_data, G_sc_session_data, SC_SECRET_LENGTH) != 0) {
    G_sc_preallocated_offset = -1;
    THROW(0x6982);
  }

  apdu_out[0] = (G_sc_preallocated_offset / SC_PAIRING_KEY_LEN);
  uint8_t pairing[SC_PAIRING_KEY_LEN];
  pairing[0] = 1;

  cx_rng(&apdu_out[1], HASH_LEN);

  cx_sha256_t sha256;
  cx_sha256_init(&sha256);
  cx_hash((cx_hash_t *) &sha256, 0, G_sc_secret, SC_SECRET_LENGTH, NULL);
  cx_hash((cx_hash_t *) &sha256, CX_LAST, &apdu_out[1], SC_SECRET_LENGTH, &pairing[1]);

  nvm_write(&N_pairings[G_sc_preallocated_offset], pairing, SC_PAIRING_KEY_LEN);
  G_sc_preallocated_offset = -1;
  *tx = SC_PAIRING_KEY_LEN;
}

void sc_pair(uint8_t p1, uint8_t p2, uint8_t lc, unsigned char* apdu_data, unsigned char* apdu_out, volatile unsigned int *flags, volatile unsigned int *tx) {
  if (G_sc_open != SC_STATE_CLOSED) {
    THROW(0x6985);
  }

  if (lc != SC_SECRET_LENGTH) {
    THROW(0x6A80);
  }

  switch(p1) {
    case PAIR_P1_FIRST_STEP:
      sc_pair_step1(apdu_data, apdu_out, flags, tx);
      break;
    case PAIR_P1_LAST_STEP:
      sc_pair_step2(apdu_data, apdu_out, flags, tx);
      break;
    default:
      THROW(0x6A86);
      break;
  }

  THROW(0x9000);
}

uint8_t sc_available_pairings() {
  uint8_t count = 0;

  for (int i = 0; i < SC_PAIRING_ARRAY_LEN; i += SC_PAIRING_KEY_LEN) {
    if (N_pairings[i] == 0) {
      count++;
    }
  }

  return count;
}

void sc_close() {
  G_sc_open = SC_STATE_CLOSED;
  G_sc_preallocated_offset = -1;
}

uint8_t sc_get_status() {
  return G_sc_open;
}

void sc_copy_public_key(uint8_t* dst) {
  os_memmove(dst, G_sc_public_key.W, EC_PUB_KEY_LEN);
}

void sc_unpair(uint8_t p1, uint8_t p2, uint8_t lc, unsigned char* apdu_data, unsigned char* apdu_out, volatile unsigned int *flags, volatile unsigned int *tx) {
  ASSERT_OPEN_SECURE_CHANNEL();

  if (p1 >= SC_MAX_PAIRINGS) {
    THROW(0x6A86);
  }

  if (N_pairings[p1 * SC_PAIRING_KEY_LEN] == 1) {
    uint8_t pairing[SC_PAIRING_KEY_LEN];
    os_memset(pairing, 0, SC_PAIRING_KEY_LEN);
    nvm_write(&N_pairings[p1 * SC_PAIRING_KEY_LEN], pairing, SC_PAIRING_KEY_LEN);
  }

  THROW(0x9000);
}

void sc_open_secure_channel(uint8_t p1, uint8_t p2, uint8_t lc, unsigned char* apdu_data, unsigned char* apdu_out, volatile unsigned int *flags, volatile unsigned int *tx) {
  if (lc != EC_PUB_KEY_LEN) {
    THROW(0x6A80);
  }

  if ((p1 >= SC_MAX_PAIRINGS) || (N_pairings[p1 * SC_PAIRING_KEY_LEN] != 1)) {
    THROW(0x6A86);
  }

  sc_close();

  uint8_t secret[EC_COMPONENT_LEN];

  cx_ecdh(&G_sc_private_key, CX_ECDH_X, apdu_data, secret);

  cx_rng(apdu_out, (HASH_LEN + SC_IV_LEN));
  os_memmove(G_sc_session_data, &apdu_out[HASH_LEN], SC_IV_LEN);

  cx_sha512_t sha512;
  cx_sha512_init(&sha512);
  cx_hash((cx_hash_t *) &sha512, 0, secret, SC_SECRET_LENGTH, NULL);
  cx_hash((cx_hash_t *) &sha512, 0, &N_pairings[(p1 * SC_PAIRING_KEY_LEN) + 1], SC_SECRET_LENGTH, NULL);
  cx_hash((cx_hash_t *) &sha512, CX_LAST, apdu_out, SC_SECRET_LENGTH, G_sc_keys);

  *tx = (HASH_LEN + SC_IV_LEN);
  G_sc_open = SC_STATE_OPENING;

  THROW(0x9000);
}

void sc_mutually_authenticate(uint8_t p1, uint8_t p2, uint8_t lc, unsigned char* apdu_data, unsigned char* apdu_out, volatile unsigned int *flags, volatile unsigned int *tx) {
  if (G_sc_open != SC_STATE_OPENING) {
    THROW(0x6985);
  }

  cx_rng(apdu_out, SC_SECRET_LENGTH);
  *tx = SC_SECRET_LENGTH;

  G_sc_open = SC_STATE_OPEN;
}

#endif
