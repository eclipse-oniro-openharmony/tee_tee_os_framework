/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Head file of mesp_decrypt
 */

#ifndef __MESP_DECRYPT_H__
#define __MESP_DECRYPT_H__

#include <stdint.h>

#define IV_SIZE 16
#define DERIVEIN_SIZE 32
#define PRIVATE_KEY_SIZE 32
#define HASH_SIZE 32
#define PUBLIC_KEY_SIZE 64
#define OUTPUT_SIZE 64
#define ALL_DATA_SIZE 132

#pragma pack (1)
struct data_for_mesp {
	uint8_t for_mesp[ALL_DATA_SIZE];
	uint8_t public_key[PUBLIC_KEY_SIZE];
	uint8_t output_data[OUTPUT_SIZE];
	uint8_t real_output_size;
};
#pragma pack()

struct encrypt_package {
	int chip_id;
	int version;
	int keytype; /* SYMM_KEYTYPE_GID */
	uint8_t derivein[DERIVEIN_SIZE];
	int curve_id; /* CURVE_ID_BRAINPOOLP256R1 */
	int alg; /* SYMM_ALGORITHM_AES */
	uint8_t iv[IV_SIZE];
	uint8_t private_key[PRIVATE_KEY_SIZE];
	uint8_t hash[HASH_SIZE];
};
#endif