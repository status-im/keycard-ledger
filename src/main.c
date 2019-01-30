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

#define DERIVE_KEY_P1_MASTER 0x00
#define DERIVE_KEY_P1_PARENT 0x40
#define DERIVE_KEY_P1_CURRENT 0x80

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

#define MAX_BIP32_PATH 10
#define HASH_LEN 32
#define EC_COMPONENT_LEN 32
#define EC_PUB_KEY_LEN (1 + (EC_COMPONENT_LEN * 2))

unsigned char G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];
uint32_t G_bip32_path[MAX_BIP32_PATH];
int G_bip32_path_len = 0;

static const bagl_element_t *io_seproxyhal_touch_exit(const bagl_element_t *e);

ux_state_t ux;

// ********************************************************************************
// Ledger Blue specific UI
// ********************************************************************************

static const bagl_element_t ui_idle_blue[] = {
  // {
  //     {type, userid, x, y, width, height, stroke, radius, fill, fgcolor, bgcolor, font_id, icon_id},
  //     text,
  //     touch_area_brim,
  //     overfgcolor,
  //     overbgcolor,
  //     tap,
  //     out,
  //     over,
  // },
  {
    {BAGL_RECTANGLE, 0x00, 0, 60, 320, 420, 0, 0, BAGL_FILL, 0xf9f9f9, 0xf9f9f9, 0, 0},
    NULL,
    0,
    0,
    0,
    NULL,
    NULL,
    NULL,
  },
  {
    {BAGL_RECTANGLE, 0x00, 0, 0, 320, 60, 0, 0, BAGL_FILL, 0x1d2028, 0x1d2028, 0, 0},
    NULL,
    0,
    0,
    0,
    NULL,
    NULL,
    NULL,
  },
  {
    {BAGL_LABEL, 0x00, 20, 0, 320, 60, 0, 0, BAGL_FILL, 0xFFFFFF, 0x1d2028, BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_MIDDLE, 0},
    "Keycard",
    0,
    0,
    0,
    NULL,
    NULL,
    NULL,
  },
  {
    {BAGL_BUTTON | BAGL_FLAG_TOUCHABLE, 0x00, 165, 225, 120, 40, 0, 6,
     BAGL_FILL, 0x41ccb4, 0xF9F9F9, BAGL_FONT_OPEN_SANS_LIGHT_14px |
     BAGL_FONT_ALIGNMENT_CENTER | BAGL_FONT_ALIGNMENT_MIDDLE, 0},
    "EXIT",
    0,
    0x37ae99,
    0xF9F9F9,
    io_seproxyhal_touch_exit,
    NULL,
    NULL,
  },
};

static unsigned int ui_idle_blue_button(unsigned int button_mask, unsigned int button_mask_counter) {
  return 0;
}

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
  {NULL, os_sched_exit, 0, &C_icon_dashboard, "Quit app", NULL, 50, 29},
  UX_MENU_END
};

static const bagl_element_t *io_seproxyhal_touch_exit(const bagl_element_t *e) {
  // Go back to the dashboard
  os_sched_exit(0);
  return NULL;
}

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
  if (os_seph_features() & SEPROXYHAL_TAG_SESSION_START_EVENT_FEATURE_SCREEN_BIG) {
    UX_DISPLAY(ui_idle_blue, NULL);
  } else {
    UX_MENU_DISPLAY(0, menu_main, NULL);
  }
}

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

void keycard_derive(unsigned char* apdu, volatile unsigned int *flags, volatile unsigned int *tx) {
  UNUSED(flags);
  UNUSED(tx);

  int bip32_offset;

  switch (apdu[OFFSET_P1]) {
    case DERIVE_KEY_P1_MASTER:
      bip32_offset = 0;
      break;
    case DERIVE_KEY_P1_PARENT:
      bip32_offset = G_bip32_path_len - 1;
      break;
    case DERIVE_KEY_P1_CURRENT:
      bip32_offset = G_bip32_path_len;
      break;
    default:
      THROW(0x6A86);
      break;
  }

  if (((bip32_offset + (apdu[OFFSET_LC] / 4)) > MAX_BIP32_PATH) || ((apdu[OFFSET_LC] % 4) != 0)) {
    THROW(0x6A80);
  }

  for (int i = 0; i < apdu[OFFSET_LC]; i += 4) {
    G_bip32_path[bip32_offset++] = U4BE(apdu, (i + OFFSET_CDATA));
  }

  G_bip32_path_len = bip32_offset;

  THROW(0x9000);
}

void keycard_sign(unsigned char* apdu, volatile unsigned int *flags, volatile unsigned int *tx) {
  UNUSED(flags);

  if (apdu[OFFSET_LC] != HASH_LEN) {
    THROW(0x6A80);
  }

  if (G_bip32_path_len == 0) {
    THROW(0x6985);
  }

  uint8_t private_key_data[EC_COMPONENT_LEN];
  uint8_t hash[HASH_LEN];
  cx_ecfp_private_key_t private_key;
  cx_ecfp_public_key_t public_key;

  os_memmove(hash, &apdu[OFFSET_CDATA], HASH_LEN);
  os_perso_derive_node_bip32(CX_CURVE_256K1, G_bip32_path, G_bip32_path_len, private_key_data, NULL);
  cx_ecfp_init_private_key(CX_CURVE_256K1, private_key_data, EC_COMPONENT_LEN, &private_key);
  cx_ecfp_generate_pair(CX_CURVE_256K1, &public_key, &private_key, 1);
  os_memset(&private_key_data, 0, sizeof(private_key_data));

  apdu[(*tx)++] = TLV_SIGNATURE_TEMPLATE;
  apdu[(*tx)++] = 4 + EC_PUB_KEY_LEN;
  apdu[(*tx)++] = TLV_PUB_KEY;
  apdu[(*tx)++] = EC_PUB_KEY_LEN;

  os_memmove(&apdu[*tx], public_key.W, EC_PUB_KEY_LEN);
  *tx += EC_PUB_KEY_LEN;

  int signature_len = cx_ecdsa_sign(&private_key, CX_RND_RFC6979 | CX_LAST, CX_SHA256, hash, HASH_LEN, &apdu[*tx], NULL);

  apdu[1] += signature_len;
  *tx += signature_len;

  os_memset(&private_key, 0, sizeof(private_key));

  THROW(0x9000);
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

        switch (G_io_apdu_buffer[OFFSET_INS]) {
          case INS_SELECT:
            THROW(0x6A81);
            break;
          case INS_GET_STATUS:
            keycard_get_status(G_io_apdu_buffer, &flags, &tx);
            break;
          case INS_SET_NDEF:
            THROW(0x6A81);
            break;
          case INS_INIT:
            THROW(0x6A81);
            break;
          case INS_VERIFY_PIN:
            THROW(0x6A81);
            break;
          case INS_CHANGE_PIN:
            THROW(0x6A81);
            break;
          case INS_UNBLOCK_PIN:
            THROW(0x6A81);
            break;
          case INS_LOAD_KEY:
            THROW(0x6A81);
            break;
          case INS_DERIVE_KEY:
            keycard_derive(G_io_apdu_buffer, &flags, &tx);
            break;
          case INS_GENERATE_MNEMONIC:
            THROW(0x6A81);
            break;
          case INS_REMOVE_KEY:
            THROW(0x6A81);
            break;
          case INS_GENERATE_KEY:
            THROW(0x6A81);
            break;
          case INS_DUPLICATE_KEY:
            THROW(0x6A81);
            break;
          case INS_SIGN:
            keycard_sign(G_io_apdu_buffer, &flags, &tx);
            break;
          case INS_SET_PINLESS_PATH:
            THROW(0x6A81);
            break;
          case INS_EXPORT_KEY:
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
