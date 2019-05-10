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
#include "secure_channel.h"
#include "defines.h"

#include <string.h>

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

#define SIGN_P1_CURRENT 0x00
#define SIGN_P1_DERIVE 0x01
#define SIGN_P1_DERIVE_AND_MAKE_CURRENT 0x02
#define SIGN_P1_PINLESS 0x03

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

#define EVT_SIGN 0
#define EVT_EXPORT 1

typedef struct internalStorage_t {
  uint8_t instance_uid[UID_LENGTH];
  uint32_t pinless_path[MAX_BIP32_PATH + 1];
  uint8_t confirm_export;
  uint8_t confirm_sign;
  uint8_t initialized;
} internalStorage_t;

internalStorage_t N_storage_real;
#define N_storage (*(internalStorage_t*) PIC(&N_storage_real))

const uint8_t C_instance_aid[] = { 0xA0, 0x00, 0x00, 0x08, 0x04, 0x00, 0x01, 0x01, 0x01 };

unsigned char G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];

uint8_t G_key_uid[HASH_LEN];

uint32_t G_bip32_path[MAX_BIP32_PATH];
int G_bip32_path_len;

uint32_t G_tmp_bip32_path[MAX_BIP32_PATH];
int G_tmp_bip32_path_len;
uint8_t G_tmp_export_public_only;
uint8_t G_make_current;

uint8_t G_tmp_hash[HASH_LEN];

#ifdef TARGET_NANOX
#include "ux.h"
ux_state_t G_ux;
bolos_ux_params_t G_ux_params;
#else
ux_state_t ux;
#endif

void keycard_check_and_make_current() {
  if (G_make_current) {
    os_memmove(G_bip32_path, G_tmp_bip32_path, (G_tmp_bip32_path_len * 4));
    G_bip32_path_len = G_tmp_bip32_path_len;
  }
}

void keycard_derive_key(uint32_t* path, int path_len, cx_ecfp_private_key_t* private_key, cx_ecfp_public_key_t* public_key) {
  uint8_t private_key_data[EC_COMPONENT_LEN];

  os_perso_derive_node_bip32(CX_CURVE_256K1, path, path_len, private_key_data, NULL);
  cx_ecfp_init_private_key(CX_CURVE_256K1, private_key_data, EC_COMPONENT_LEN, private_key);

  if (public_key != NULL) {
    cx_ecfp_generate_pair(CX_CURVE_256K1, public_key, private_key, 1);
  }

  os_memset(private_key_data, 0, sizeof(private_key_data));
}

unsigned short keycard_do_sign(unsigned char* out, volatile unsigned int *tx) {
  cx_ecfp_private_key_t private_key;
  cx_ecfp_public_key_t public_key;

  keycard_derive_key(G_tmp_bip32_path, G_tmp_bip32_path_len, &private_key, &public_key);

  out[(*tx)++] = TLV_SIGNATURE_TEMPLATE;
  out[(*tx)++] = 0x81;
  out[(*tx)++] = 4 + EC_PUB_KEY_LEN;
  out[(*tx)++] = TLV_PUB_KEY;
  out[(*tx)++] = EC_PUB_KEY_LEN;

  os_memmove(&out[*tx], public_key.W, EC_PUB_KEY_LEN);
  *tx += EC_PUB_KEY_LEN;

  int signature_len = cx_ecdsa_sign(&private_key, CX_RND_RFC6979 | CX_LAST, CX_SHA256, G_tmp_hash, HASH_LEN, &out[*tx], 80, NULL);
  os_memset(&private_key, 0, sizeof(private_key));

  out[2] += signature_len;
  *tx += signature_len;

  keycard_check_and_make_current();

  return 0x9000;
}

unsigned short keycard_do_export(unsigned char* out, volatile unsigned int *tx) {
  cx_ecfp_private_key_t private_key;
  cx_ecfp_public_key_t public_key;

  keycard_derive_key(G_tmp_bip32_path, G_tmp_bip32_path_len, &private_key, &public_key);

  out[(*tx)++] = TLV_KEY_TEMPLATE;
  out[(*tx)++] = 2 + EC_PUB_KEY_LEN;

  if (!G_tmp_export_public_only) {
    out[1] += 2 + EC_COMPONENT_LEN;

    out[(*tx)++] = TLV_PRIV_KEY;
    out[(*tx)++] = EC_COMPONENT_LEN;
    os_memmove(&out[*tx], private_key.d, EC_COMPONENT_LEN);
    *tx += EC_COMPONENT_LEN;
  }

  os_memset(&private_key, 0, sizeof(private_key));

  out[(*tx)++] = TLV_PUB_KEY;
  out[(*tx)++] = EC_PUB_KEY_LEN;
  os_memmove(&out[*tx], public_key.W, EC_PUB_KEY_LEN);
  *tx += EC_PUB_KEY_LEN;

  keycard_check_and_make_current();

  return 0x9000;
}

static void io_seproxyhal_touch_ok_real(int evt) {
  unsigned int tx = 0;
  unsigned short sw;

  uint8_t data_offset = 0;

  #if defined(SECURE_CHANNEL)
  if (sc_get_status() == SC_STATE_OPEN) {
    data_offset = SC_IV_LEN;
  }
  #endif

  switch (evt) {
    case EVT_SIGN:
      sw = keycard_do_sign(&G_io_apdu_buffer[data_offset], &tx);
      break;
    case EVT_EXPORT:
      sw = keycard_do_export(&G_io_apdu_buffer[data_offset], &tx);
      break;
    default:
      sw = 0x6F00;
      break;
  }

  G_io_apdu_buffer[data_offset + tx] = sw >> 8;
  G_io_apdu_buffer[data_offset + tx + 1] = sw;

  tx += 2;

  #if defined(SECURE_CHANNEL)
  if (sc_get_status() == SC_STATE_OPEN) {
    sc_postprocess_apdu(G_io_apdu_buffer, &tx);
  }
  #endif

  // Send back the response, do not restart the event loop
  io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);

  ui_idle();
}

#if defined(TARGET_BLUE) || defined(TARGET_NANOS)
static const bagl_element_t* io_seproxyhal_touch_ok(const bagl_element_t *e) {
  io_seproxyhal_touch_ok_real(e->component.userid);
  return NULL;
}
#endif

static const bagl_element_t* io_seproxyhal_touch_cancel(const bagl_element_t *e) {
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
const ux_menu_entry_t menu_settings[];
const ux_menu_entry_t menu_settings_export[];
const ux_menu_entry_t menu_settings_sign[];

void menu_settings_export_change(unsigned int enabled) {
  uint8_t confirm_export = enabled;
  nvm_write(&N_storage.confirm_export, (void*)&confirm_export, sizeof(uint8_t));
  UX_MENU_DISPLAY(0, menu_settings, NULL);
}

void menu_settings_sign_change(unsigned int enabled) {
  uint8_t confirm_sign = enabled;
  nvm_write(&N_storage.confirm_sign, (void*)&confirm_sign, sizeof(uint8_t));
  UX_MENU_DISPLAY(0, menu_settings, NULL);
}

void menu_settings_export_init(unsigned int ignored) {
  UX_MENU_DISPLAY(N_storage.confirm_export ? 1 : 0, menu_settings_export, NULL);
}

void menu_settings_sign_init(unsigned int ignored) {
  UX_MENU_DISPLAY(N_storage.confirm_sign ? 1 : 0, menu_settings_sign, NULL);
}

const ux_menu_entry_t menu_settings_export[] = {
  {NULL, menu_settings_export_change, 0, NULL, "No", NULL, 0, 0},
  {NULL, menu_settings_export_change, 1, NULL, "Yes", NULL, 0, 0},
  UX_MENU_END
};

const ux_menu_entry_t menu_settings_sign[] = {
  {NULL, menu_settings_sign_change, 0, NULL, "No", NULL, 0, 0},
  {NULL, menu_settings_sign_change, 1, NULL, "Yes", NULL, 0, 0},
  UX_MENU_END
};

const ux_menu_entry_t menu_settings[] = {
  {NULL, menu_settings_export_init, 0, NULL, "Ask confirmation", "on export" , 0, 0},
  {NULL, menu_settings_sign_init, 0, NULL, "Ask confirmation", "on sign" , 0, 0},
  {menu_main, NULL, 2, &C_icon_back, "Back", NULL, 61, 40},
  UX_MENU_END
};

const ux_menu_entry_t menu_about[] = {
  {NULL, NULL, 0, NULL, "Version", APPVERSION , 0, 0},
  {menu_main, NULL, 2, &C_icon_back, "Back", NULL, 61, 40},
  UX_MENU_END
};

const ux_menu_entry_t menu_main[] = {
  #if defined (TEST_BUILD)
  {NULL, NULL, 0, NULL, "Keycard", "TEST BUILD", 0, 0},
  #else
  {NULL, NULL, 0, NULL, "Keycard", "by Status", 0, 0},
  #endif
  {menu_about, NULL, 0, NULL, "About", NULL, 0, 0},
  {menu_settings, NULL, 0, NULL, "Settings", NULL, 0, 0},
  #if defined(SECURE_CHANNEL)
  {NULL, sc_generate_pairing_password, 0, NULL, "Pairing password", NULL, 0, 0},
  {NULL, sc_clear_pairings, 0, NULL, "Clear pairings", NULL, 0, 0},
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

  {{BAGL_LABELINE, EVT_SIGN, 0, 12, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000, BAGL_FONT_OPEN_SANS_EXTRABOLD_11px|BAGL_FONT_ALIGNMENT_CENTER, 0 }, "Sign", 0, 0, 0, NULL, NULL, NULL},
  {{BAGL_LABELINE, EVT_SIGN, 0, 26, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000, BAGL_FONT_OPEN_SANS_EXTRABOLD_11px|BAGL_FONT_ALIGNMENT_CENTER, 0 }, "transaction?", 0, 0, 0, NULL, NULL, NULL},
};

unsigned int ui_sign_nanos_button(unsigned int button_mask, unsigned int button_mask_counter) {
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
  return ui_nanos_button_handler(button_mask, &ui_export_key_nanos[3]);
}
#elif defined(TARGET_NANOX)
void display_settings();
void switch_settings_confirm_export();
void switch_settings_confirm_sign();

// Main menu

UX_STEP_NOCB(
  ux_idle_flow_1_step,
  pnn,
  {
    &C_icon_dashboard, //&C_icon,
    "Keycard",
    #if defined (TEST_BUILD)
    "TEST BUILD"
    #else
    "by Status"
    #endif
  });

UX_STEP_NOCB(
  ux_idle_flow_2_step,
  bn,
  {
    "Version",
    APPVERSION,
  });

UX_STEP_VALID(
  ux_idle_flow_3_step,
  pb,
  display_settings(),
  {
    &C_icon_dashboard, //&C_icon_eye,
    "Settings",
  });

#if defined(SECURE_CHANNEL)
UX_STEP_VALID(
  ux_idle_flow_4_step,
  pb,
  sc_generate_pairing_password(0),
  {
    &C_icon_dashboard, // change
    "Pairing password",
  });

UX_STEP_VALID(
  ux_idle_flow_5_step,
  pb,
  sc_clear_pairings(0),
  {
    &C_icon_dashboard, //change
    "Pairings",
  });
#endif

UX_STEP_VALID(
  ux_idle_flow_6_step,
  pb,
  os_sched_exit(-1),
  {
    &C_icon_dashboard,
    "Quit",
  });

UX_FLOW(ux_idle_flow,
  &ux_idle_flow_1_step,
  &ux_idle_flow_2_step,
  &ux_idle_flow_3_step,
#if defined(SECURE_CHANNEL)
  &ux_idle_flow_4_step,
  &ux_idle_flow_5_step,
#endif
  &ux_idle_flow_6_step
);

// Confirm sign

UX_STEP_NOCB(
    ux_sign_flow_1_step,
    nn,
    {
      "Sign",
      "transaction?"
    });

UX_FLOW_DEF_VALID(
  ux_sign_flow_2_step,
  pb,
  io_seproxyhal_touch_ok_real(EVT_SIGN),
  {
    &C_icon_dashboard, //change
    "Approve",
  });

UX_FLOW_DEF_VALID(
  ux_sign_flow_3_step,
  pb,
  io_seproxyhal_touch_cancel(NULL),
  {
    &C_icon_dashboard, //change
    "Reject",
  });

UX_FLOW(ux_sign_flow,
  &ux_sign_flow_1_step,
  &ux_sign_flow_2_step,
  &ux_sign_flow_3_step
  );

// Confirm export

UX_STEP_NOCB(
  ux_export_flow_1_step,
  nn,
  {
    "Export",
    "EIP-1581 key?"
  });

UX_FLOW_DEF_VALID(
  ux_export_flow_2_step,
  pb,
  io_seproxyhal_touch_ok_real(EVT_EXPORT),
  {
    &C_icon_dashboard, //change
    "Approve",
  });

UX_FLOW_DEF_VALID(
  ux_export_flow_3_step,
  pb,
  io_seproxyhal_touch_cancel(NULL),
  {
    &C_icon_dashboard, //change
    "Reject",
  });

UX_FLOW(ux_export_flow,
  &ux_export_flow_1_step,
  &ux_export_flow_2_step,
  &ux_export_flow_3_step
  );

// Settings

UX_FLOW_DEF_VALID(
  ux_settings_flow_1_step,
  bnn,
  switch_settings_confirm_export(),
  {
    "Confirmation",
    "Ask confirmation",
    "on export?",
    (char *) G_tmp_hash
  });

UX_FLOW_DEF_VALID(
  ux_settings_flow_2_step,
  bnn,
  switch_settings_confirm_sign(),
  {
    "Confirmation",
    "Ask confirmation",
    "on sign?",
    (char *) &G_tmp_hash[4]
  });

UX_FLOW_DEF_VALID(
  ux_settings_flow_3_step,
  pb,
  ui_idle(),
  {
    &C_icon_back,
    "Back",
  });

UX_FLOW(ux_settings_flow,
  &ux_settings_flow_1_step,
  &ux_settings_flow_2_step,
  &ux_settings_flow_3_step
  );

void display_settings() {
  strcpy((char *)G_tmp_hash, (N_storage.confirm_export ? "Yes" : "No"));
  strcpy((char *)&G_tmp_hash[4], (N_storage.confirm_sign ? "Yes" : "No"));
  ux_flow_init(0, ux_settings_flow, NULL);
}

void switch_settings_confirm_export() {
  uint8_t confirm_export = (N_storage.confirm_export ? 0 : 1);
  nvm_write(&N_storage.confirm_export, (void*)&confirm_export, sizeof(uint8_t));
  display_settings();
}

void switch_settings_confirm_sign() {
  uint8_t confirm_sign = (N_storage.confirm_sign ? 0 : 1);
  nvm_write(&N_storage.confirm_export, (void*)&confirm_sign, sizeof(uint8_t));
  display_settings();
}
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

void ui_idle(void) {
  #if defined(TARGET_BLUE)
  UX_DISPLAY(ui_idle_blue, NULL);
  #elif defined(TARGET_NANOS)
  UX_MENU_DISPLAY(0, menu_main, NULL);
  #elif defined(TARGET_NANOX)
  if(G_ux.stack_count == 0) {
      ux_stack_push();
  }

  ux_flow_init(0, ux_idle_flow, NULL);
  #endif
}

void keycard_get_status_app(unsigned char* out, volatile unsigned int *tx) {
  out[(*tx)++] = TLV_APPLICATION_STATUS_TEMPLATE;
  out[(*tx)++] = 9;
  out[(*tx)++] = TLV_INT;
  out[(*tx)++] = 1;
  out[(*tx)++] = 0xff;
  out[(*tx)++] = TLV_INT;
  out[(*tx)++] = 1;
  out[(*tx)++] = 0xff;
  out[(*tx)++] = TLV_BOOL;
  out[(*tx)++] = 1;
  out[(*tx)++] = 0xff;
}

void keycard_get_status_keypath(unsigned char* out, volatile unsigned int *tx) {
  for (int i = 0; i < G_bip32_path_len; i++) {
    out[(*tx)++] = ((G_bip32_path[i] >> 24) & 0xff);
    out[(*tx)++] = ((G_bip32_path[i] >> 16) & 0xff);
    out[(*tx)++] = ((G_bip32_path[i] >> 8) & 0xff);
    out[(*tx)++] = (G_bip32_path[i] & 0xff);
  }
}

void keycard_get_status(uint8_t p1, uint8_t p2, uint8_t lc, unsigned char* apdu_data, unsigned char* apdu_out, volatile unsigned int *flags, volatile unsigned int *tx) {
  ASSERT_OPEN_SECURE_CHANNEL();

  switch (p1) {
    case GET_STATUS_P1_APP_STATUS:
      keycard_get_status_app(apdu_out, tx);
      break;
    case GET_STATUS_P1_APP_KEYPATH:
      keycard_get_status_keypath(apdu_out, tx);
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

void keycard_select(uint8_t p1, uint8_t p2, uint8_t lc, unsigned char* apdu_data, unsigned char* apdu_out, volatile unsigned int *flags, volatile unsigned int *tx) {
  if (p1 != 0x04 || p2 != 0x00) {
    THROW(0x6A81);
  }

  if (lc != INSTANCE_AID_LEN || os_memcmp(apdu_data, C_instance_aid, INSTANCE_AID_LEN) != 0) {
    THROW(0x6A84);
  }

  #if defined(SECURE_CHANNEL)
  sc_close();
  #endif

  apdu_out[(*tx)++] = TLV_APPLICATION_INFO_TEMPLATE;
  #if defined(SECURE_CHANNEL)
  apdu_out[(*tx)++] = 0x81;
  apdu_out[(*tx)++] = UID_LENGTH + HASH_LEN + EC_PUB_KEY_LEN + 16;
  #else
  apdu_out[(*tx)++] = UID_LENGTH + HASH_LEN + 16;
  #endif

  apdu_out[(*tx)++] = TLV_UID;
  apdu_out[(*tx)++] = UID_LENGTH;
  os_memmove(&apdu_out[*tx], N_storage.instance_uid, UID_LENGTH);
  *tx += UID_LENGTH;

  apdu_out[(*tx)++] = TLV_PUB_KEY;

  #if defined(SECURE_CHANNEL)
  apdu_out[(*tx)++] = EC_PUB_KEY_LEN;
  sc_copy_public_key(&apdu_out[*tx]);
  *tx += EC_PUB_KEY_LEN;
  #else
  apdu_out[(*tx)++] = 0x00;
  #endif

  apdu_out[(*tx)++] = TLV_INT;
  apdu_out[(*tx)++] = 2;
  apdu_out[(*tx)++] = APPMAJOR;
  apdu_out[(*tx)++] = APPMINOR;

  apdu_out[(*tx)++] = TLV_INT;
  apdu_out[(*tx)++] = 1;
  #if defined(SECURE_CHANNEL)
  apdu_out[(*tx)++] = sc_available_pairings();
  #else
  apdu_out[(*tx)++] = 0xff;
  #endif

  apdu_out[(*tx)++] = TLV_KEY_UID;
  apdu_out[(*tx)++] = HASH_LEN;
  os_memmove(&apdu_out[*tx], G_key_uid, HASH_LEN);
  *tx += HASH_LEN;

  apdu_out[(*tx)++] = TLV_CAPABILITIES;
  apdu_out[(*tx)++] = 1;
  apdu_out[(*tx)++] = CAPABILITIES;

  THROW(0x9000);
}

void keycard_derive(uint8_t p1, uint8_t p2, uint8_t lc, unsigned char* apdu_data, unsigned char* apdu_out, volatile unsigned int *flags, volatile unsigned int *tx) {
  ASSERT_OPEN_SECURE_CHANNEL();

  keycard_copy_path(p1, apdu_data, lc, G_bip32_path, &G_bip32_path_len);

  THROW(0x9000);
}

 void keycard_sign(uint8_t p1, uint8_t p2, uint8_t lc, unsigned char* apdu_data, unsigned char* apdu_out, volatile unsigned int *flags, volatile unsigned int *tx) {
   uint8_t usePinless = 0;
   uint8_t derive = 0;

   G_make_current = 0;

   switch(p1 & ~DERIVE_KEY_P1_MASK) {
     case SIGN_P1_CURRENT:
       break;
     case SIGN_P1_DERIVE_AND_MAKE_CURRENT:
       G_make_current = 1;
     case SIGN_P1_DERIVE:
       derive = 1;
       break;
    case SIGN_P1_PINLESS:
       usePinless = 1;
       break;
     default:
       THROW(0x6A86);
       break;
   }

   if ((derive && lc < (HASH_LEN + 4)) || (!derive && lc != HASH_LEN)) {
     THROW(0x6A80);
   }

   if (!usePinless) {
     ASSERT_OPEN_SECURE_CHANNEL();

     os_memmove(G_tmp_bip32_path, G_bip32_path, (G_bip32_path_len * 4));
     G_tmp_bip32_path_len = G_bip32_path_len;

     if (derive) {
       keycard_copy_path((p1 & DERIVE_KEY_P1_MASK), &apdu_data[HASH_LEN], (lc - HASH_LEN), G_tmp_bip32_path, &G_tmp_bip32_path_len);
     }
   } else {
     G_tmp_bip32_path_len = N_storage.pinless_path[0];

     if (G_tmp_bip32_path_len == 0) {
       THROW(0x6A88);
     }

     os_memmove(G_tmp_bip32_path, &N_storage.pinless_path[1], (G_tmp_bip32_path_len * 4));
   }

   os_memmove(G_tmp_hash, apdu_data, HASH_LEN);

   if (usePinless || !N_storage.confirm_sign) {
     unsigned short sw = keycard_do_sign(apdu_out, tx);
     THROW(sw);
   } else {
     #if defined(TARGET_BLUE)
     // TODO: implement Ledger Blue UI
     #elif defined(TARGET_NANOS)
     UX_DISPLAY(ui_sign_nanos, NULL);
     #elif defined(TARGET_NANOX)
     ux_flow_init(0, ux_sign_flow, NULL);
     #endif

     *flags |= IO_ASYNCH_REPLY;
   }
}

inline void validate_eip_1581_path(const uint32_t* path, int len) {
  if (len < 5 || !((path[0] == 0x8000002B) && (path[1] == 0x8000003C) && (path[2] == 0x8000062D))) {
    THROW(0x6985);
  }
}

void keycard_set_pinless_path(uint8_t p1, uint8_t p2, uint8_t lc, unsigned char* apdu_data, unsigned char* apdu_out, volatile unsigned int *flags, volatile unsigned int *tx) {
  ASSERT_OPEN_SECURE_CHANNEL();

  uint32_t data[MAX_BIP32_PATH + 1];

  keycard_copy_path(DERIVE_KEY_P1_MASTER, apdu_data, lc, &data[1], (int *) &data[0]);

  nvm_write(&N_storage.pinless_path, data, ((MAX_BIP32_PATH + 1) * 4));

  THROW(0x9000);
}

void keycard_export(uint8_t p1, uint8_t p2, uint8_t lc, unsigned char* apdu_data, unsigned char* apdu_out, volatile unsigned int *flags, volatile unsigned int *tx) {
  ASSERT_OPEN_SECURE_CHANNEL();

  os_memmove(G_tmp_bip32_path, G_bip32_path, (G_bip32_path_len * 4));
  G_tmp_bip32_path_len = G_bip32_path_len;

  G_make_current = 0;

  switch (p1 & ~DERIVE_KEY_P1_MASK) {
    case EXPORT_KEY_P1_CURRENT:
      break;
    case EXPORT_KEY_P1_DERIVE_AND_MAKE_CURRENT:
      G_make_current = 1;
    case EXPORT_KEY_P1_DERIVE:
      keycard_copy_path((p1 & DERIVE_KEY_P1_MASK), apdu_data, lc, G_tmp_bip32_path, &G_tmp_bip32_path_len);
      break;
    default:
      THROW(0x6A86);
      break;
  }

  switch (p2) {
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

  if (G_tmp_export_public_only || !N_storage.confirm_export) {
    unsigned short sw = keycard_do_export(apdu_out, tx);
    THROW(sw);
  } else {
    #if defined(TARGET_BLUE)
    // TODO: implement Ledger Blue UI
    #elif defined(TARGET_NANOS)
    UX_DISPLAY(ui_export_key_nanos, NULL);
    #elif defined(TARGET_NANOX)
    ux_flow_init(0, ux_export_flow, NULL);
    #endif

    *flags |= IO_ASYNCH_REPLY;
  }
}

void keycard_generate_key_uid() {
  cx_ecfp_private_key_t private_key;
  cx_ecfp_public_key_t public_key;

  keycard_derive_key(G_tmp_bip32_path, 0, &private_key, &public_key);
  os_memset(&private_key, 0, sizeof(private_key));

  cx_hash_sha256(public_key.W, EC_PUB_KEY_LEN, G_key_uid, HASH_LEN);
}

void keycard_init_nvm() {
  G_bip32_path_len = 0;
  G_tmp_bip32_path_len = 0;
  G_tmp_export_public_only = 0;
  G_make_current = 0;

  if (N_storage.initialized != 0x01) {
    internalStorage_t storage;
    #if defined(SECURE_CHANNEL)
    sc_nvm_init();
    #endif
    cx_rng(storage.instance_uid, UID_LENGTH);
    storage.pinless_path[0] = 0;

    #if defined(TEST_BUILD)
    storage.confirm_export = 0x00;
    storage.confirm_sign = 0x00;
    #else
    storage.confirm_export = 0x01;
    storage.confirm_sign = 0x01;
    #endif

    storage.initialized = 0x01;
    nvm_write(&N_storage, (void*)&storage, sizeof(internalStorage_t));
  }
}

static void runloop(void) {
  volatile unsigned int rx = 0;
  volatile unsigned int tx = 0;
  volatile unsigned int flags = 0;
  volatile unsigned int data_offset = 0;

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
        data_offset = 0;

        // no apdu received, well, reset the session, and reset the
        // bootloader configuration
        if (rx == 0) {
          THROW(0x6982);
        }

        switch (G_io_apdu_buffer[OFFSET_INS]) {
          case INS_SELECT:
            keycard_select(G_io_apdu_buffer[OFFSET_P1], G_io_apdu_buffer[OFFSET_P2], G_io_apdu_buffer[OFFSET_LC], &G_io_apdu_buffer[OFFSET_CDATA + data_offset], &G_io_apdu_buffer[data_offset], &flags, &tx);
            break;
          #if defined(SECURE_CHANNEL)
          case INS_OPEN_SECURE_CHANNEL:
            sc_open_secure_channel(G_io_apdu_buffer[OFFSET_P1], G_io_apdu_buffer[OFFSET_P2], G_io_apdu_buffer[OFFSET_LC], &G_io_apdu_buffer[OFFSET_CDATA + data_offset], &G_io_apdu_buffer[data_offset], &flags, &tx);
            break;
          default:
            if (sc_get_status() == SC_STATE_OPEN || (sc_get_status() == SC_STATE_OPENING && G_io_apdu_buffer[OFFSET_INS] == INS_MUTUALLY_AUTHENTICATE)) {
              sc_preprocess_apdu(G_io_apdu_buffer);
              data_offset = SC_IV_LEN;
            }
            break;
          #else
          case INS_OPEN_SECURE_CHANNEL:
            THROW(0x6A81);
            break;
          default:
            break;
          #endif
        }

        switch (G_io_apdu_buffer[OFFSET_INS]) {
          #if defined(SECURE_CHANNEL)
          case INS_PAIR:
            sc_pair(G_io_apdu_buffer[OFFSET_P1], G_io_apdu_buffer[OFFSET_P2], G_io_apdu_buffer[OFFSET_LC], &G_io_apdu_buffer[OFFSET_CDATA + data_offset], &G_io_apdu_buffer[data_offset], &flags, &tx);
            break;
          case INS_UNPAIR:
            sc_unpair(G_io_apdu_buffer[OFFSET_P1], G_io_apdu_buffer[OFFSET_P2], G_io_apdu_buffer[OFFSET_LC], &G_io_apdu_buffer[OFFSET_CDATA + data_offset], &G_io_apdu_buffer[data_offset], &flags, &tx);
            break;
          case INS_MUTUALLY_AUTHENTICATE:
            sc_mutually_authenticate(G_io_apdu_buffer[OFFSET_P1], G_io_apdu_buffer[OFFSET_P2], G_io_apdu_buffer[OFFSET_LC], &G_io_apdu_buffer[OFFSET_CDATA + data_offset], &G_io_apdu_buffer[data_offset], &flags, &tx);
            break;
          #else
          case INS_PAIR:
          case INS_UNPAIR:
          case INS_MUTUALLY_AUTHENTICATE:
            THROW(0x6A81);
            break;
          #endif
          case INS_GET_STATUS:
            keycard_get_status(G_io_apdu_buffer[OFFSET_P1], G_io_apdu_buffer[OFFSET_P2], G_io_apdu_buffer[OFFSET_LC], &G_io_apdu_buffer[OFFSET_CDATA + data_offset], &G_io_apdu_buffer[data_offset], &flags, &tx);
            break;
          case INS_DERIVE_KEY:
            keycard_derive(G_io_apdu_buffer[OFFSET_P1], G_io_apdu_buffer[OFFSET_P2], G_io_apdu_buffer[OFFSET_LC], &G_io_apdu_buffer[OFFSET_CDATA + data_offset], &G_io_apdu_buffer[data_offset], &flags, &tx);
            break;
          case INS_SIGN:
            keycard_sign(G_io_apdu_buffer[OFFSET_P1], G_io_apdu_buffer[OFFSET_P2], G_io_apdu_buffer[OFFSET_LC], &G_io_apdu_buffer[OFFSET_CDATA + data_offset], &G_io_apdu_buffer[data_offset], &flags, &tx);
            break;
          case INS_SET_PINLESS_PATH:
          keycard_set_pinless_path(G_io_apdu_buffer[OFFSET_P1], G_io_apdu_buffer[OFFSET_P2], G_io_apdu_buffer[OFFSET_LC], &G_io_apdu_buffer[OFFSET_CDATA + data_offset], &G_io_apdu_buffer[data_offset], &flags, &tx);
            break;
          case INS_EXPORT_KEY:
            keycard_export(G_io_apdu_buffer[OFFSET_P1], G_io_apdu_buffer[OFFSET_P2], G_io_apdu_buffer[OFFSET_LC], &G_io_apdu_buffer[OFFSET_CDATA + data_offset], &G_io_apdu_buffer[data_offset], &flags, &tx);
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

        #if defined(SECURE_CHANNEL)
        if (sw == 0x6982) {
          data_offset = 0;
        } else if (sw == 0x6802) {
          sw = 0x6A80;
        }
        #endif

        G_io_apdu_buffer[data_offset + tx] = sw >> 8;
        G_io_apdu_buffer[data_offset + tx + 1] = sw;

        tx += 2;

        #if defined(SECURE_CHANNEL)
        if (sc_get_status() == SC_STATE_OPEN) {
          sc_postprocess_apdu(G_io_apdu_buffer, &tx);
        }
        #endif
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
      sc_init();
      #endif

      keycard_generate_key_uid();
      keycard_init_nvm();

      #if defined(TARGET_NANOX)
      G_io_app.plane_mode = os_setting_get(OS_SETTING_PLANEMODE, NULL, 0);
      BLE_power(0, NULL);
      BLE_power(1, "Nano X");
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
