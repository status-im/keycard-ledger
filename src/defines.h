#ifndef _DEFINES_H_
#define _DEFINES_H_

#define OFFSET_CLA 0
#define OFFSET_INS 1
#define OFFSET_P1 2
#define OFFSET_P2 3
#define OFFSET_LC 4
#define OFFSET_CDATA 5

#define MAX_BIP32_PATH 10

#define UID_LENGTH 16
#define HASH_LEN 32
#define EC_COMPONENT_LEN 32
#define EC_PUB_KEY_LEN (1 + (EC_COMPONENT_LEN * 2))
#define INSTANCE_AID_LEN 9

#endif
