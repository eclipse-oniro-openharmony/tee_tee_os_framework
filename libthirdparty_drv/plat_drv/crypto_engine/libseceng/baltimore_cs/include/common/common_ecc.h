/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: ECC data structure
 * Author: s00294296
 * Create: 2020/02/20
 */
#ifndef __COMMON_ECC_H__
#define __COMMON_ECC_H__
#include <common_define.h>

#define SM2_KEY_WIDTH           (ECC_STDWIDTH_256)     /* key width */
#define SM2_KEY_LEN             (SM2_KEY_WIDTH >> 3)   /* key width (Bytes) */
#define SM2_POINT_LEN           (SM2_KEY_LEN << 1)     /* curve point bytes */

enum ecc_curve_id {
	CURVE_ID_SM2P256V1,
	CURVE_ID_SM9BN256V1,
	CURVE_ID_SM9BN256V1_G2,
	CURVE_ID_BRAINPOOLP256R1,
	CURVE_ID_MAX,
};

/*
 * @brief ECC standard key width
 */
enum ecc_keywidth_std {
	ECC_STDWIDTH_MIN = 192,
	ECC_STDWIDTH_192 = 192,
	ECC_STDWIDTH_224 = 224,
	ECC_STDWIDTH_256 = 256,
	ECC_STDWIDTH_384 = 384,
	ECC_STDWIDTH_521 = 521,
};

struct hisee_ecc_privkey {
	enum ecc_curve_id curve_id;
	u32 width;
	struct basic_data priv;
};

struct hisee_ecc_pubkey {
	enum ecc_curve_id curve_id;
	u32 width;
	struct basic_data pubx;
	struct basic_data puby;
};

struct hisee_ecc_keypair {
	enum ecc_curve_id curve_id;
	u32 width;
	struct basic_data priv;
	struct basic_data pubx;
	struct basic_data puby;
};

#endif

