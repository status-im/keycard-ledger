/*******************************************************************************
*   Status Keycard Application
*   (c) 2019 Status Research & Development GmbH
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

#include "os.h"
#include "cx.h"

#include "glyphs.h"

#include "os_io_seproxyhal.h"

#define OFFSET_CLA 0
#define OFFSET_INS 1
#define OFFSET_P1 2
#define OFFSET_P2 3
#define OFFSET_LC 4
#define OFFSET_CDATA 5

#define INS_SELECT 0xA4
#define INS_GET_STATUS 0xF2
#define INS_SET_NDEF 0xF3
#define INS_INIT 0xFE
#define INS_VERIFY_PIN 0x20
#define INS_CHANGE_PIN 0x21
#define INS_UNBLOCK_PIN 0x22
#define INS_LOAD_KEY 0xD0
#define INS_DERIVE_KEY 0xD1
#define INS_GENERATE_MNEMONIC 0xD2
#define INS_REMOVE_KEY 0xD3
#define INS_GENERATE_KEY 0xD4
#define INS_DUPLICATE_KEY 0xD5
#define INS_SIGN 0xC0
#define INS_SET_PINLESS_PATH 0xC1
#define INS_EXPORT_KEY 0xC2

#define INS_OPEN_SECURE_CHANNEL 0x10
#define INS_MUTUALLY_AUTHENTICATE 0x11
#define INS_PAIR 0x12
#define INS_UNPAIR 0x13

#define DERIVE_KEY_P1_MASTER 0x00
#define DERIVE_KEY_P1_PARENT 0x40
#define DERIVE_KEY_P1_CURRENT 0x80
#define DERIVE_KEY_P1_MASK 0xC0

#define EXPORT_KEY_P1_CURRENT 0x00
#define EXPORT_KEY_P1_DERIVE 0x01
#define EXPORT_KEY_P1_DERIVE_AND_MAKE_CURRENT 0x02
#define EXPORT_KEY_P2_FULL 0x00
#define EXPORT_KEY_P2_PUBLIC_ONLY 0x01

#define GET_STATUS_P1_APP_STATUS 0x00
#define GET_STATUS_P1_APP_KEYPATH 0x01

#define PAIR_P1_FIRST_STEP 0x00
#define PAIR_P1_LAST_STEP 0x01

#define TLV_SIGNATURE_TEMPLATE 0xA0
#define TLV_KEY_TEMPLATE 0xA1
#define TLV_PUB_KEY 0x80
#define TLV_PRIV_KEY 0x81
#define TLV_CHAIN_CODE 0x82
#define TLV_APPLICATION_STATUS_TEMPLATE 0xA3
#define TLV_INT 0x02
#define TLV_BOOL 0x01

#define TLV_APPLICATION_INFO_TEMPLATE 0xA4
#define TLV_UID 0x8F
#define TLV_KEY_UID 0x8E
#define TLV_CAPABILITIES 0x8D

#define CAPABILITIES_SECURE_CHANNEL 0x01

#if defined(SECURE_CHANNEL)
#define CAPABILITIES CAPABILITIES_SECURE_CHANNEL
#else
#define CAPABILITIES 0x00
#endif

#define UID_LENGTH 16
#define MAX_BIP32_PATH 10
#define HASH_LEN 32
#define EC_COMPONENT_LEN 32
#define EC_PUB_KEY_LEN (1 + (EC_COMPONENT_LEN * 2))

#define SC_IV_LEN 16
#define SC_SECRET_LENGTH 32
#define SC_MAX_PAIRINGS 5
#define SC_PAIRING_KEY_LEN (SC_SECRET_LENGTH + 1)
#define SC_PAIRING_ARRAY_LEN (SC_PAIRING_KEY_LEN * SC_MAX_PAIRINGS)
#define SC_PAIRING_PASS_LEN 6

#define SC_STATE_CLOSED 0
#define SC_STATE_OPENING 1
#define SC_STATE_OPEN 2

#define EVT_SIGN 0
#define EVT_EXPORT 1

#define INSTANCE_AID_LEN 9

typedef struct internalStorage_t {
#if defined(SECURE_CHANNEL)
  uint8_t pairings[SC_PAIRING_ARRAY_LEN];
#endif
  uint8_t instance_uid[UID_LENGTH];
  uint8_t initialized;
} internalStorage_t;

internalStorage_t N_storage_real;
#define N_storage (*(internalStorage_t*) PIC(&N_storage_real))

const uint8_t C_instance_aid[] = { 0xA0, 0x00, 0x00, 0x08, 0x04, 0x00, 0x01, 0x01, 0x01 };

unsigned char G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];

uint8_t G_key_uid[HASH_LEN];

#if defined(SECURE_CHANNEL)
cx_ecfp_private_key_t G_sc_private_key;
cx_ecfp_public_key_t G_sc_public_key;
uint8_t G_sc_secret[SC_SECRET_LENGTH];
char G_sc_pairing_password[SC_PAIRING_PASS_LEN + 1];
int8_t G_sc_preallocated_offset;
uint8_t G_sc_open;
uint8_t G_sc_session_data[SC_SECRET_LENGTH];
cx_aes_key_t G_sc_enc_key;
cx_aes_key_t G_sc_mac_key;
#endif

uint32_t G_bip32_path[MAX_BIP32_PATH];
int G_bip32_path_len;

uint32_t G_tmp_bip32_path[MAX_BIP32_PATH];
int G_tmp_bip32_path_len;
uint8_t G_tmp_export_public_only;
uint8_t G_tmp_export_make_current;

uint8_t G_tmp_hash[HASH_LEN];

static void ui_idle(void);

ux_state_t ux;

void keycard_derive_key(uint32_t* path, int path_len, cx_ecfp_private_key_t* private_key, cx_ecfp_public_key_t* public_key) {
  uint8_t private_key_data[EC_COMPONENT_LEN];

  os_perso_derive_node_bip32(CX_CURVE_256K1, path, path_len, private_key_data, NULL);
  cx_ecfp_init_private_key(CX_CURVE_256K1, private_key_data, EC_COMPONENT_LEN, private_key);

  if (public_key != NULL) {
    cx_ecfp_generate_pair(CX_CURVE_256K1, public_key, private_key, 1);
  }

  os_memset(private_key_data, 0, sizeof(private_key_data));
}

unsigned short keycard_do_sign(unsigned char* apdu, volatile unsigned int *tx) {
  cx_ecfp_private_key_t private_key;
  cx_ecfp_public_key_t public_key;

  keycard_derive_key(G_bip32_path, G_bip32_path_len, &private_key, &public_key);

  apdu[(*tx)++] = TLV_SIGNATURE_TEMPLATE;
  apdu[(*tx)++] = 0x81;
  apdu[(*tx)++] = 4 + EC_PUB_KEY_LEN;
  apdu[(*tx)++] = TLV_PUB_KEY;
  apdu[(*tx)++] = EC_PUB_KEY_LEN;

  os_memmove(&apdu[*tx], public_key.W, EC_PUB_KEY_LEN);
  *tx += EC_PUB_KEY_LEN;

  int signature_len = cx_ecdsa_sign(&private_key, CX_RND_RFC6979 | CX_LAST, CX_SHA256, G_tmp_hash, HASH_LEN, &apdu[*tx], NULL);
  os_memset(&private_key, 0, sizeof(private_key));

  apdu[2] += signature_len;
  *tx += signature_len;

  return 0x9000;
}

unsigned short keycard_do_export(unsigned char* apdu, volatile unsigned int *tx) {
  cx_ecfp_private_key_t private_key;
  cx_ecfp_public_key_t public_key;

  keycard_derive_key(G_tmp_bip32_path, G_tmp_bip32_path_len, &private_key, &public_key);

  apdu[(*tx)++] = TLV_KEY_TEMPLATE;
  apdu[(*tx)++] = 2 + EC_PUB_KEY_LEN;

  if (!G_tmp_export_public_only) {
    apdu[1] += 2 + EC_COMPONENT_LEN;

    apdu[(*tx)++] = TLV_PRIV_KEY;
    apdu[(*tx)++] = EC_COMPONENT_LEN;
    os_memmove(&apdu[*tx], private_key.d, EC_COMPONENT_LEN);
    *tx += EC_COMPONENT_LEN;
  }

  os_memset(&private_key, 0, sizeof(private_key));

  apdu[(*tx)++] = TLV_PUB_KEY;
  apdu[(*tx)++] = EC_PUB_KEY_LEN;
  os_memmove(&apdu[*tx], public_key.W, EC_PUB_KEY_LEN);
  *tx += EC_PUB_KEY_LEN;

  if (G_tmp_export_make_current) {
    os_memmove(G_bip32_path, G_tmp_bip32_path, (G_tmp_bip32_path_len * 4));
    G_bip32_path_len = G_tmp_bip32_path_len;
  }

  return 0x9000;
}

static const bagl_element_t* io_seproxyhal_touch_ok(const bagl_element_t *e) {
  unsigned int tx = 0;
  unsigned short sw;

  switch (e->component.userid) {
    case EVT_SIGN:
      sw = keycard_do_sign(G_io_apdu_buffer, &tx);
      break;
    case EVT_EXPORT:
      sw = keycard_do_export(G_io_apdu_buffer, &tx);
      break;
    default:
      sw = 0x6F00;
      break;
  }

  G_io_apdu_buffer[tx++] = sw >> 8;
  G_io_apdu_buffer[tx++] = sw;

  // Send back the response, do not restart the event loop
  io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);

  ui_idle();

  return NULL;
}

static const bagl_element_t* io_seproxyhal_touch_cancel(const bagl_element_t *e) {
  UNUSED(e);

  G_io_apdu_buffer[0] = 0x69;
  G_io_apdu_buffer[1] = 0x85;

  io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);

  ui_idle();

  return NULL;
}

#if defined(TARGET_BLUE)

static const bagl_element_t *io_seproxyhal_touch_exit(const bagl_element_t *e) {
  // Go back to the dashboard
  os_sched_exit(0);
  return NULL;
}

// ********************************************************************************
// Ledger Blue specific UI
// ********************************************************************************

static const bagl_element_t ui_idle_blue[] = {
  // {{type, userid, x, y, width, height, stroke, radius, fill, fgcolor, bgcolor, font_id, icon_id}, text, touch_area_brim, overfgcolor, overbgcolor, tap, out, over }
  {{BAGL_RECTANGLE, 0x00, 0, 60, 320, 420, 0, 0, BAGL_FILL, 0xf9f9f9, 0xf9f9f9, 0, 0}, NULL, 0, 0, 0, NULL, NULL, NULL},
  {{BAGL_RECTANGLE, 0x00, 0, 0, 320, 60, 0, 0, BAGL_FILL, 0x1d2028, 0x1d2028, 0, 0}, NULL, 0, 0, 0, NULL, NULL, NULL},
  {{BAGL_LABEL, 0x00, 20, 0, 320, 60, 0, 0, BAGL_FILL, 0xFFFFFF, 0x1d2028, BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_MIDDLE, 0}, "Keycard", 0, 0, 0, NULL, NULL, NULL},
  {{BAGL_BUTTON | BAGL_FLAG_TOUCHABLE, 0x00, 165, 225, 120, 40, 0, 6, BAGL_FILL, 0x41ccb4, 0xF9F9F9, BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_CENTER | BAGL_FONT_ALIGNMENT_MIDDLE, 0}, "EXIT", 0, 0x37ae99, 0xF9F9F9, io_seproxyhal_touch_exit, NULL, NULL},
};

static unsigned int ui_idle_blue_button(unsigned int button_mask, unsigned int button_mask_counter) {
  return 0;
}

#elif defined(TARGET_NANOS)
// ********************************************************************************
// Ledger Nano S specific UI
// ********************************************************************************

const ux_menu_entry_t menu_main[];

const ux_menu_entry_t menu_about[] = {
  {NULL, NULL, 0, NULL, "Version", APPVERSION , 0, 0},
  {menu_main, NULL, 2, &C_icon_back, "Back", NULL, 61, 40},
  UX_MENU_END
};

const ux_menu_entry_t menu_main[] = {
  {NULL, NULL, 0, NULL, "Keycard", "by Status", 0, 0},
  {menu_about, NULL, 0, NULL, "About", NULL, 0, 0},
  #if defined(SECURE_CHANNEL)
  {NULL, sc_generate_pairing_password, 0, NULL, "Pairing password", NULL, 0, 0},
  #endif
  {NULL, os_sched_exit, 0, &C_icon_dashboard, "Quit app", NULL, 50, 29},
  UX_MENU_END
};

unsigned int ui_nanos_button_handler(unsigned int button_mask, const bagl_element_t* element) {
  switch(button_mask) {
    case BUTTON_EVT_RELEASED | BUTTON_LEFT:
      io_seproxyhal_touch_cancel(element);
      break;

    case BUTTON_EVT_RELEASED | BUTTON_RIGHT: {
      io_seproxyhal_touch_ok(element);
      break;
    }
  }

  return 0;
}

const bagl_element_t ui_sign_nanos[] = {
  // {{type, userid, x, y, width, height, stroke, radius, fill, fgcolor, bgcolor, font_id, icon_id}, text, touch_area_brim, overfgcolor, overbgcolor, tap, out, over }
  {{BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF, 0, 0}, NULL, 0, 0, 0, NULL, NULL, NULL},
  {{BAGL_ICON, 0x00, 3, 12, 7, 7, 0, 0, 0, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_CROSS }, NULL, 0, 0, 0, NULL, NULL, NULL},
  {{BAGL_ICON, 0x00, 117,  13, 8, 6, 0, 0, 0, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_CHECK }, NULL, 0, 0, 0, NULL, NULL, NULL},

  {{BAGL_LABELINE, EVT_SIGN, 0, 12, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000, BAGL_FONT_OPEN_SANS_EXTRABOLD_11px|BAGL_FONT_ALIGNMENT_CENTER, 0  }, "Sign", 0, 0, 0, NULL, NULL, NULL},
  {{BAGL_LABELINE, EVT_SIGN, 0, 26, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000, BAGL_FONT_OPEN_SANS_EXTRABOLD_11px|BAGL_FONT_ALIGNMENT_CENTER, 0  }, "transaction?", 0, 0, 0, NULL, NULL, NULL},
};

unsigned int ui_sign_nanos_button(unsigned int button_mask, unsigned int button_mask_counter) {
  UNUSED(button_mask_counter);
  return ui_nanos_button_handler(button_mask, &ui_sign_nanos[3]);
}

const bagl_element_t ui_export_key_nanos[] = {
  // {{type, userid, x, y, width, height, stroke, radius, fill, fgcolor, bgcolor, font_id, icon_id}, text, touch_area_brim, overfgcolor, overbgcolor, tap, out, over }
  {{BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF, 0, 0}, NULL, 0, 0, 0, NULL, NULL, NULL},
  {{BAGL_ICON, 0x00, 3, 12, 7, 7, 0, 0, 0, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_CROSS }, NULL, 0, 0, 0, NULL, NULL, NULL},
  {{BAGL_ICON, 0x00, 117,  13, 8, 6, 0, 0, 0, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_CHECK }, NULL, 0, 0, 0, NULL, NULL, NULL},

  {{BAGL_LABELINE, EVT_EXPORT, 0, 12, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000, BAGL_FONT_OPEN_SANS_EXTRABOLD_11px|BAGL_FONT_ALIGNMENT_CENTER, 0  }, "Export", 0, 0, 0, NULL, NULL, NULL},
  {{BAGL_LABELINE, EVT_EXPORT, 0, 26, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000, BAGL_FONT_OPEN_SANS_EXTRABOLD_11px|BAGL_FONT_ALIGNMENT_CENTER, 0  }, "EIP-1581 key?", 0, 0, 0, NULL, NULL, NULL},
};

unsigned int ui_export_key_nanos_button(unsigned int button_mask, unsigned int button_mask_counter) {
  UNUSED(button_mask_counter);
  return ui_nanos_button_handler(button_mask, &ui_export_key_nanos[3]);
}

#if defined(SECURE_CHANNEL)
void sc_generate_pairing_password();

const bagl_element_t ui_pair_nanos[] = {
  // {{type, userid, x, y, width, height, stroke, radius, fill, fgcolor, bgcolor, font_id, icon_id}, text, touch_area_brim, overfgcolor, overbgcolor, tap, out, over }
  {{BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF, 0, 0}, NULL, 0, 0, 0, NULL, NULL, NULL},

  {{BAGL_LABELINE, 0x00, 0, 12, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000, BAGL_FONT_OPEN_SANS_EXTRABOLD_11px|BAGL_FONT_ALIGNMENT_CENTER, 0  }, "Pairing password", 0, 0, 0, NULL, NULL, NULL},
  {{BAGL_LABELINE, 0x00, 0, 26, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000, BAGL_FONT_OPEN_SANS_EXTRABOLD_11px|BAGL_FONT_ALIGNMENT_CENTER, 0  }, G_sc_pairing_password, 0, 0, 0, NULL, NULL, NULL},
};

unsigned int ui_pair_nanos_button(unsigned int button_mask, unsigned int button_mask_counter) {
  UNUSED(button_mask);
  UNUSED(button_mask_counter);

  UX_MENU_DISPLAY(0, menu_main, NULL);
  return 0;
}
#endif
#endif

unsigned short io_exchange_al(unsigned char channel, unsigned short tx_len) {
  switch (channel & ~(IO_FLAGS)) {
    case CHANNEL_KEYBOARD:
    break;

    // multiplexed io exchange over a SPI channel and TLV encapsulated protocol
    case CHANNEL_SPI:
    if (tx_len) {
      io_seproxyhal_spi_send(G_io_apdu_buffer, tx_len);

      if (channel & IO_RESET_AFTER_REPLIED) {
        reset();
      }
      return 0; // nothing received from the master so far (it's a tx
      // transaction)
    } else {
      return io_seproxyhal_spi_recv(G_io_apdu_buffer, sizeof(G_io_apdu_buffer), 0);
    }

    default:
    THROW(INVALID_PARAMETER);
  }
  return 0;
}

static void ui_idle(void) {
  #if defined(TARGET_BLUE)
  UX_DISPLAY(ui_idle_blue, NULL);
  #elif defined(TARGET_NANOS)
  UX_MENU_DISPLAY(0, menu_main, NULL);
  #endif
}

#if defined(SECURE_CHANNEL)
uint8_t sc_available_pairings() {
  uint8_t count = 0;

  for (int i = 0; i < SC_PAIRING_ARRAY_LEN; i += SC_PAIRING_KEY_LEN) {
    if (N_storage.pairings[i] == 0) {
      count++;
    }
  }

  return count;
}

uint8_t sc_preallocate_pairing_index() {
  G_sc_preallocated_offset = -1;

  for (int i = 0; i < SC_PAIRING_ARRAY_LEN; i += SC_PAIRING_KEY_LEN) {
    if (N_storage.pairings[i] == 0) {
      G_sc_preallocated_offset = i;
      return 1;
    }
  }

  return 0;
}

uint8_t sc_verify_mac(unsigned char* apdu) {

}

uint8_t sc_decrypt_data(unsigned char* apdu) {

}

void sc_postprocess_apdu(unsigned char* apdu) {

}

void sc_preprocess_apdu(unsigned char* apdu) {
  if (!sc_verify_mac(apdu)) {
    THROW(0x6982);
  }

  sc_decrypt_data(apdu);
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

void sc_generate_pairing_password() {
  cx_rng((unsigned char *) G_sc_pairing_password, SC_PAIRING_PASS_LEN);

  for (int i = 0; i < SC_PAIRING_PASS_LEN; i++) {
    G_sc_pairing_password[i] = '0' + (G_sc_pairing_password[i] % 10);
  }

  G_sc_pairing_password[SC_PAIRING_PASS_LEN] = '\0';

  uint8_t salt[] = "Keycard Pairing Password Salt\0\0\0\1";
  sc_pbkdf2_sha256(G_sc_pairing_password, SC_PAIRING_PASS_LEN, salt, sizeof(salt), 500, G_sc_secret);

  //PRINTF("Secret:\n %.*H \n\n", SC_SECRET_LENGTH, G_sc_secret);

  #if defined(TARGET_BLUE)
  // TODO: implement Ledger Blue UI
  #elif defined(TARGET_NANOS)
  UX_DISPLAY(ui_pair_nanos, NULL);
  #endif
}

void sc_pair_step1(unsigned char* apdu, volatile unsigned int *flags, volatile unsigned int *tx) {
  if (!sc_preallocate_pairing_index()) {
    THROW(0x6A84);
  }

  cx_sha256_t sha256;
  cx_sha256_init(&sha256);
  cx_hash((cx_hash_t *) &sha256, 0, G_sc_secret, SC_SECRET_LENGTH, NULL);
  cx_hash((cx_hash_t *) &sha256, CX_LAST, &apdu[OFFSET_CDATA], SC_SECRET_LENGTH, apdu);
  cx_rng(&apdu[HASH_LEN], HASH_LEN);
  *tx = (HASH_LEN * 2);

  cx_sha256_init(&sha256);
  cx_hash((cx_hash_t *) &sha256, 0, G_sc_secret, SC_SECRET_LENGTH, NULL);
  cx_hash((cx_hash_t *) &sha256, CX_LAST, &apdu[HASH_LEN], SC_SECRET_LENGTH, G_sc_session_data);
}

void sc_pair_step2(unsigned char* apdu, volatile unsigned int *flags, volatile unsigned int *tx) {
  if (G_sc_preallocated_offset == -1) {
    THROW(0x6A86);
  }

  if (os_memcmp(&apdu[OFFSET_CDATA], C_instance_aid, INSTANCE_AID_LEN) != 0) {
    THROW(0x6982);
  }

  apdu[0] = (G_sc_preallocated_offset / SC_PAIRING_KEY_LEN);
  uint8_t pairing[SC_PAIRING_KEY_LEN];
  pairing[0] = 1;

  cx_rng(&apdu[1], HASH_LEN);

  cx_sha256_t sha256;
  cx_sha256_init(&sha256);
  cx_hash((cx_hash_t *) &sha256, 0, G_sc_secret, SC_SECRET_LENGTH, NULL);
  cx_hash((cx_hash_t *) &sha256, CX_LAST, &apdu[1], SC_SECRET_LENGTH, &pairing[1]);

  nvm_write(&N_storage.pairings[G_sc_preallocated_offset], pairing, SC_PAIRING_KEY_LEN);
  G_sc_preallocated_offset = 0;
}

void sc_pair(unsigned char* apdu, volatile unsigned int *flags, volatile unsigned int *tx) {
  if (G_sc_open != SC_STATE_CLOSED) {
    THROW(0x6985);
  }

  if (apdu[OFFSET_LC] != SC_SECRET_LENGTH) {
    THROW(0x6A80);
  }

  switch(apdu[OFFSET_P1]) {
    case PAIR_P1_FIRST_STEP:
      sc_pair_step1(apdu, flags, tx);
      break;
    case PAIR_P1_LAST_STEP:
      sc_pair_step2(apdu, flags, tx);
      break;
    default:
      THROW(0x6A86);
      break;
  }

  THROW(0x9000);
}

void sc_close() {
  G_sc_open = SC_STATE_CLOSED;
  G_sc_preallocated_offset = -1;
}

void sc_unpair(unsigned char* apdu, volatile unsigned int *flags, volatile unsigned int *tx) {
}

void sc_open_secure_channel(unsigned char* apdu, volatile unsigned int *flags, volatile unsigned int *tx) {
  if (apdu[OFFSET_LC] != EC_PUB_KEY_LEN) {
    THROW(0x6A80);
  }

  if ((apdu[OFFSET_P1] >= SC_MAX_PAIRINGS) || (N_storage.pairings[apdu[OFFSET_P1] * SC_PAIRING_KEY_LEN] != 1)) {
    THROW(0x6A86);
  }

  sc_close();

  uint8_t secret[EC_COMPONENT_LEN];

  cx_ecdh(&G_sc_private_key, CX_ECDH_X, &apdu[OFFSET_CDATA], secret);

  cx_rng(apdu, (HASH_LEN + SC_IV_LEN));

  uint8_t tmp[SC_SECRET_LENGTH * 2];

  cx_sha512_t sha512;
  cx_sha512_init(&sha512);
  cx_hash((cx_hash_t *) &sha512, 0, secret, SC_SECRET_LENGTH, NULL);
  cx_hash((cx_hash_t *) &sha512, 0, &N_storage.pairings[(apdu[OFFSET_P1] * SC_PAIRING_KEY_LEN) + 1], SC_SECRET_LENGTH, NULL);
  cx_hash((cx_hash_t *) &sha512, CX_LAST, apdu, SC_SECRET_LENGTH, tmp);

  cx_aes_init_key(tmp, SC_SECRET_LENGTH, &G_sc_enc_key);
  cx_aes_init_key(&tmp[SC_SECRET_LENGTH], SC_SECRET_LENGTH, &G_sc_mac_key);

  *tx = (HASH_LEN + SC_IV_LEN);
  G_sc_open = SC_STATE_OPENING;

  THROW(0x9000);
}

void sc_mutually_authenticate(unsigned char* apdu, volatile unsigned int *flags, volatile unsigned int *tx) {
  if (G_sc_open != SC_STATE_OPENING) {
    THROW(0x6985);
  }

  cx_rng(apdu, SC_SECRET_LENGTH);
  *tx = SC_SECRET_LENGTH;

  G_sc_open = SC_STATE_OPEN;
}
#endif

void keycard_get_status_app(unsigned char* apdu, volatile unsigned int *tx) {
  apdu[(*tx)++] = TLV_APPLICATION_STATUS_TEMPLATE;
  apdu[(*tx)++] = 9;
  apdu[(*tx)++] = TLV_INT;
  apdu[(*tx)++] = 1;
  apdu[(*tx)++] = 0xff;
  apdu[(*tx)++] = TLV_INT;
  apdu[(*tx)++] = 1;
  apdu[(*tx)++] = 0xff;
  apdu[(*tx)++] = TLV_BOOL;
  apdu[(*tx)++] = 1;
  apdu[(*tx)++] = 0xff;
}

void keycard_get_status_keypath(unsigned char* apdu, volatile unsigned int *tx) {
  for (int i = 0; i < G_bip32_path_len; i++) {
    apdu[(*tx)++] = ((G_bip32_path[i] >> 24) & 0xff);
    apdu[(*tx)++] = ((G_bip32_path[i] >> 16) & 0xff);
    apdu[(*tx)++] = ((G_bip32_path[i] >> 8) & 0xff);
    apdu[(*tx)++] = (G_bip32_path[i] & 0xff);
  }
}

void keycard_get_status(unsigned char* apdu, volatile unsigned int *flags, volatile unsigned int *tx) {
  UNUSED(flags);

  switch (apdu[OFFSET_P1]) {
    case GET_STATUS_P1_APP_STATUS:
      keycard_get_status_app(apdu, tx);
      break;
    case GET_STATUS_P1_APP_KEYPATH:
      keycard_get_status_keypath(apdu, tx);
      break;
    default:
      THROW(0x6A86);
      break;
  }

  THROW(0x9000);
}

void keycard_copy_path(uint8_t mode, const uint8_t* src, int src_len, uint32_t* dst, int* dst_len) {
  int bip32_offset;

  switch (mode) {
    case DERIVE_KEY_P1_MASTER:
      bip32_offset = 0;
      break;
    case DERIVE_KEY_P1_PARENT:
      bip32_offset = (*dst_len) - 1;
      break;
    case DERIVE_KEY_P1_CURRENT:
      bip32_offset = *dst_len;
      break;
    default:
      THROW(0x6A86);
      break;
  }

  if (bip32_offset < 0) {
    THROW(0x6B00);
  }

  if (((bip32_offset + (src_len / 4)) > MAX_BIP32_PATH) || ((src_len % 4) != 0)) {
    THROW(0x6A80);
  }

  for (int i = 0; i < src_len; i += 4) {
    dst[bip32_offset++] = U4BE(src, i);
  }

  *dst_len = bip32_offset;
}

void keycard_select(unsigned char* apdu, volatile unsigned int *flags, volatile unsigned int *tx) {
  UNUSED(flags);

  if (apdu[OFFSET_P1] != 0x04 || apdu[OFFSET_P2] != 0x00) {
    THROW(0x6A81);
  }

  if (apdu[OFFSET_LC] != INSTANCE_AID_LEN || os_memcmp(&apdu[OFFSET_CDATA], C_instance_aid, INSTANCE_AID_LEN) != 0) {
    THROW(0x6A84);
  }

  #if defined(SECURE_CHANNEL)
  sc_close();
  #endif

  apdu[(*tx)++] = TLV_APPLICATION_INFO_TEMPLATE;
  #if defined(SECURE_CHANNEL)
  apdu[(*tx)++] = 0x81;
  apdu[(*tx)++] = UID_LENGTH + HASH_LEN + EC_PUB_KEY_LEN + 16;
  #else
  apdu[(*tx)++] = UID_LENGTH + HASH_LEN + 16;
  #endif

  apdu[(*tx)++] = TLV_UID;
  apdu[(*tx)++] = UID_LENGTH;
  os_memmove(&apdu[*tx], N_storage.instance_uid, UID_LENGTH);
  *tx += UID_LENGTH;

  apdu[(*tx)++] = TLV_PUB_KEY;

  #if defined(SECURE_CHANNEL)
  apdu[(*tx)++] = EC_PUB_KEY_LEN;
  os_memmove(&apdu[*tx], G_sc_public_key.W, EC_PUB_KEY_LEN);
  *tx += EC_PUB_KEY_LEN;
  #else
  apdu[(*tx)++] = 0x00;
  #endif

  apdu[(*tx)++] = TLV_INT;
  apdu[(*tx)++] = 2;
  apdu[(*tx)++] = APPMAJOR;
  apdu[(*tx)++] = APPMINOR;

  apdu[(*tx)++] = TLV_INT;
  apdu[(*tx)++] = 1;
  #if defined(SECURE_CHANNEL)
  apdu[(*tx)++] = sc_available_pairings();
  #else
  apdu[(*tx)++] = 0xff;
  #endif

  apdu[(*tx)++] = TLV_KEY_UID;
  apdu[(*tx)++] = HASH_LEN;
  os_memmove(&apdu[*tx], G_key_uid, HASH_LEN);
  *tx += HASH_LEN;

  apdu[(*tx)++] = TLV_CAPABILITIES;
  apdu[(*tx)++] = 1;
  apdu[(*tx)++] = CAPABILITIES;

  THROW(0x9000);
}

void keycard_derive(unsigned char* apdu, volatile unsigned int *flags, volatile unsigned int *tx) {
  UNUSED(flags);
  UNUSED(tx);

  keycard_copy_path(apdu[OFFSET_P1], &apdu[OFFSET_CDATA], apdu[OFFSET_LC], G_bip32_path, &G_bip32_path_len);

  THROW(0x9000);
}

 void keycard_sign(unsigned char* apdu, volatile unsigned int *flags, volatile unsigned int *tx) {
  UNUSED(tx);

  if (apdu[OFFSET_LC] != HASH_LEN) {
    THROW(0x6A80);
  }

  os_memmove(G_tmp_hash, &apdu[OFFSET_CDATA], HASH_LEN);

  #if defined(TARGET_BLUE)
  // TODO: implement Ledger Blue UI
  #elif defined(TARGET_NANOS)
  UX_DISPLAY(ui_sign_nanos, NULL);
  #endif

  *flags |= IO_ASYNCH_REPLY;
}

inline void validate_eip_1581_path(const uint32_t* path, int len) {
  if (len < 5 || !((path[0] == 0x8000002B) && (path[1] == 0x8000003C) && (path[2] == 0x8000062D))) {
    THROW(0x6985);
  }
}

void keycard_set_pinless_path(unsigned char* apdu, volatile unsigned int *flags, volatile unsigned int *tx) {
  // A pinless path does not make sense on the Ledger, since the Ledger requires PIN entry only to turn on, not on every transaction.
  if (((apdu[OFFSET_LC] / 4) > MAX_BIP32_PATH) || apdu[OFFSET_LC] % 4 != 0) {
    THROW(0x6A80);
  } else {
    THROW(0x9000);
  }
}

void keycard_export(unsigned char* apdu, volatile unsigned int *flags, volatile unsigned int *tx) {
  os_memmove(G_tmp_bip32_path, G_bip32_path, (G_bip32_path_len * 4));
  G_tmp_bip32_path_len = G_bip32_path_len;

  G_tmp_export_make_current = 0;

  switch (apdu[OFFSET_P1] & ~DERIVE_KEY_P1_MASK) {
    case EXPORT_KEY_P1_CURRENT:
      break;
    case EXPORT_KEY_P1_DERIVE_AND_MAKE_CURRENT:
      G_tmp_export_make_current = 1;
    case EXPORT_KEY_P1_DERIVE:
      keycard_copy_path((apdu[OFFSET_P1] & DERIVE_KEY_P1_MASK), &apdu[OFFSET_CDATA], apdu[OFFSET_LC], G_tmp_bip32_path, &G_tmp_bip32_path_len);
      break;
    default:
      THROW(0x6A86);
      break;
  }

  switch (apdu[OFFSET_P2]) {
    case EXPORT_KEY_P2_FULL:
      validate_eip_1581_path(G_tmp_bip32_path, G_tmp_bip32_path_len);
      G_tmp_export_public_only = 0;
      break;
    case EXPORT_KEY_P2_PUBLIC_ONLY:
      G_tmp_export_public_only = 1;
      break;
    default:
      THROW(0x6A86);
      break;
  }

  if (G_tmp_export_public_only) {
    unsigned short sw = keycard_do_export(apdu, tx);
    THROW(sw);
  } else {
    #if defined(TARGET_BLUE)
    // TODO: implement Ledger Blue UI
    #elif defined(TARGET_NANOS)
    UX_DISPLAY(ui_export_key_nanos, NULL);
    #endif

    *flags |= IO_ASYNCH_REPLY;
  }
}

void keycard_generate_key_uid() {
  cx_ecfp_private_key_t private_key;
  cx_ecfp_public_key_t public_key;

  keycard_derive_key(G_tmp_bip32_path, 0, &private_key, &public_key);
  os_memset(&private_key, 0, sizeof(private_key));

  cx_hash_sha256(public_key.W, EC_PUB_KEY_LEN, G_key_uid);
}

void keycard_init_nvm() {
  G_bip32_path_len = 0;
  G_tmp_bip32_path_len = 0;
  G_tmp_export_public_only = 0;
  G_tmp_export_make_current = 0;

  if (N_storage.initialized != 0x01) {
    internalStorage_t storage;
    #if defined(SECURE_CHANNEL)
    os_memset(storage.pairings, 0, SC_PAIRING_ARRAY_LEN);
    #endif
    cx_rng(storage.instance_uid, UID_LENGTH);
    storage.initialized = 0x01;
    nvm_write(&N_storage, (void*)&storage, sizeof(internalStorage_t));
  }
}

static void runloop(void) {
  volatile unsigned int rx = 0;
  volatile unsigned int tx = 0;
  volatile unsigned int flags = 0;

  // DESIGN NOTE: the bootloader ignores the way APDU are fetched. The only
  // goal is to retrieve APDU.
  // When APDU are to be fetched from multiple IOs, like NFC+USB+BLE, make
  // sure the io_event is called with a
  // switch event, before the apdu is replied to the bootloader. This avoid
  // APDU injection faults.
  for (;;) {
    volatile unsigned short sw = 0;

    BEGIN_TRY {
      TRY {
        rx = tx;
        tx = 0; // ensure no race in catch_other if io_exchange throws
        // an error
        rx = io_exchange(CHANNEL_APDU | flags, rx);
        flags = 0;

        // no apdu received, well, reset the session, and reset the
        // bootloader configuration
        if (rx == 0) {
          THROW(0x6982);
        }

        #if defined(SECURE_CHANNEL)
        if (G_sc_open != SC_STATE_CLOSED) {
          sc_preprocess_apdu(G_io_apdu_buffer);
        }
        #endif

        switch (G_io_apdu_buffer[OFFSET_INS]) {
          #if defined(SECURE_CHANNEL)
          case INS_PAIR:
            sc_pair(G_io_apdu_buffer, &flags, &tx);
            break;
          case INS_UNPAIR:
            sc_unpair(G_io_apdu_buffer, &flags, &tx);
            break;
          case INS_OPEN_SECURE_CHANNEL:
            sc_open_secure_channel(G_io_apdu_buffer, &flags, &tx);
            break;
          case INS_MUTUALLY_AUTHENTICATE:
            sc_mutually_authenticate(G_io_apdu_buffer, &flags, &tx);
            break;
          #else
          case INS_PAIR:
          case INS_UNPAIR:
          case INS_OPEN_SECURE_CHANNEL:
          case INS_MUTUALLY_AUTHENTICATE:
            THROW(0x6A81);
            break;
          #endif
          case INS_SELECT:
            keycard_select(G_io_apdu_buffer, &flags, &tx);
            break;
          case INS_GET_STATUS:
            keycard_get_status(G_io_apdu_buffer, &flags, &tx);
            break;
          case INS_DERIVE_KEY:
            keycard_derive(G_io_apdu_buffer, &flags, &tx);
            break;
          case INS_SIGN:
            keycard_sign(G_io_apdu_buffer, &flags, &tx);
            break;
          case INS_SET_PINLESS_PATH:
          keycard_set_pinless_path(G_io_apdu_buffer, &flags, &tx);
            break;
          case INS_EXPORT_KEY:
            keycard_export(G_io_apdu_buffer, &flags, &tx);
            break;
          case INS_INIT:
          case INS_VERIFY_PIN:
          case INS_CHANGE_PIN:
          case INS_UNBLOCK_PIN:
          case INS_LOAD_KEY:
          case INS_GENERATE_MNEMONIC:
          case INS_REMOVE_KEY:
          case INS_GENERATE_KEY:
          case INS_DUPLICATE_KEY:
          case INS_SET_NDEF:
            THROW(0x6A81);
            break;
          default:
            THROW(0x6D00);
            break;
        }
      }
      CATCH_OTHER(e) {
        switch (e & 0xF000) {
          case 0x6000:
          case 0x9000:
          sw = e;
          break;
          default:
          sw = 0x6800 | (e & 0x7FF);
          break;
        }
        // Unexpected exception => report
        G_io_apdu_buffer[tx] = sw >> 8;
        G_io_apdu_buffer[tx + 1] = sw;
        tx += 2;
      }
      FINALLY {
      }
    }
    END_TRY;
  }

  return;
}

void io_seproxyhal_display(const bagl_element_t *element) {
  io_seproxyhal_display_default((bagl_element_t *)element);
}

unsigned char io_event(unsigned char channel) {
  // nothing done with the event, throw an error on the transport layer if
  // needed

  // can't have more than one tag in the reply, not supported yet.
  switch (G_io_seproxyhal_spi_buffer[0]) {
    case SEPROXYHAL_TAG_FINGER_EVENT:
    UX_FINGER_EVENT(G_io_seproxyhal_spi_buffer);
    break;

    case SEPROXYHAL_TAG_BUTTON_PUSH_EVENT: // for Nano S
    UX_BUTTON_PUSH_EVENT(G_io_seproxyhal_spi_buffer);
    break;

    case SEPROXYHAL_TAG_DISPLAY_PROCESSED_EVENT:
    if (UX_DISPLAYED()) {
      // TODO perform actions after all screen elements have been
      // displayed
    } else {
      UX_DISPLAYED_EVENT();
    }
    break;

    // unknown events are acknowledged
    default:
    break;
  }

  // close the event if not done previously (by a display or whatever)
  if (!io_seproxyhal_spi_is_status_sent()) {
    io_seproxyhal_general_status();
  }

  // command has been processed, DO NOT reset the current APDU transport
  return 1;
}

__attribute__((section(".boot"))) int main(void) {
  // exit critical section
  __asm volatile("cpsie i");

  UX_INIT();

  // ensure exception will work as planned
  os_boot();

  BEGIN_TRY {
    TRY {
      io_seproxyhal_init();

      #if defined(SECURE_CHANNEL)
      sc_close();
      cx_rng(G_sc_secret, SC_SECRET_LENGTH);
      cx_ecfp_generate_pair(CX_CURVE_256K1, &G_sc_public_key, &G_sc_private_key, 0);
      #endif

      keycard_generate_key_uid();
      keycard_init_nvm();

      #ifdef LISTEN_BLE
      if (os_seph_features() & SEPROXYHAL_TAG_SESSION_START_EVENT_FEATURE_BLE) {
        BLE_power(0, NULL);
        BLE_power(1, NULL);
      }
      #endif

      USB_power(0);
      USB_power(1);

      ui_idle();

      runloop();
    }
    CATCH_OTHER(e) {
    }
    FINALLY {
    }
  }
  END_TRY;
}
