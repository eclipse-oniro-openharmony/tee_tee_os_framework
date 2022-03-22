/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: TA sevice for privacydata protection
 * Create: 2020-03-10
 */
#ifndef PRIVACY_PROTECTION_COMMON_H
#define PRIVACY_PROTECTION_COMMON_H

#include "stdint.h"
#include "hisee_seceng.h"

#define MAX_PARA_NUM 7

struct drv_basic_data {
    uint64_t pdata;
    uint32_t size;
};

struct prip_drv_param {
	struct drv_basic_data buf[MAX_PARA_NUM];
	uint32_t param[MAX_PARA_NUM];
};

enum buf_id {
    ID0 = 0,
    ID1 = 1,
    ID2 = 2,
    ID3 = 3,
    ID4 = 4,
    ID5 = 5,
    ID6 = 6,
    ID7 = 7,
    ID8 = 8,
    ID9 = 9,
};

enum error_code {
    MSPE_TEE_OK                       =  0,
    MSPE_TEE_ERR                      = -1,
    MSPE_ERRCODE_TEE_POWERONERR       = 0x5400ff01,
    MSPE_ERRCODE_TEE_POWEROFFERR      = 0x5400ff02,
    MSPE_ERRCODE_TEE_PARAMERR         = 0x5400ff03,
    MSPE_ERRCODE_TEE_MALLOCERR        = 0x5400ff04,
    MSPE_ERRCODE_TEE_MEMCPYERR        = 0x5400ff05,
    MSPE_ERRCODE_TEE_GENTRNDERR       = 0x5400ff06,
    MSPE_ERRCODE_TEE_SM2GETKEYERR     = 0x5400ff08,
    MSPE_ERRCODE_TEE_SM2ENCRYPTERR    = 0x5400ff09,
    MSPE_ERRCODE_TEE_SM2DECRYPTERR    = 0x5400ff0a,
    MSPE_ERRCODE_TEE_SM3INITERR       = 0x5400ff0b,
    MSPE_ERRCODE_TEE_SM3UPDATEERR     = 0x5400ff0c,
    MSPE_ERRCODE_TEE_SM3DOFINALERR    = 0x5400ff0d,
    MSPE_ERRCODE_TEE_SM3SIGLEERR      = 0x5400ff0e,
    MSPE_ERRCODE_TEE_SM4SETKEYERR     = 0x5400ff0f,
    MSPE_ERRCODE_TEE_SM4SETKIVERR     = 0x5400ff10,
    MSPE_ERRCODE_TEE_SM4INITERR       = 0x5400ff11,
    MSPE_ERRCODE_TEE_SM4UPDATEERR     = 0x5400ff12,
    MSPE_ERRCODE_TEE_SM4DOFINALERR    = 0x5400ff13,
    MSPE_ERRCODE_TEE_KMDERIVEKEYERR   = 0x5400ff14,
    MSPE_ERRCODE_TEE_SM9SIGNERR       = 0x5400ff15,
    MSPE_ERRCODE_TEE_SM9VERIFYERR     = 0x5400ff16,
    MSPE_ERRCODE_TEE_SM9ENCRYPTERR    = 0x5400ff17,
    MSPE_ERRCODE_TEE_SM9DECRYPTERR    = 0x5400ff18,
    MSPE_ERRCODE_TEE_SM9WRAPKEYERR    = 0x5400ff19,
    MSPE_ERRCODE_TEE_SM9UNWRAPKEYERR  = 0x5400ff1a,
    MSPE_ERRCODE_TEE_SM9PREDATAERR    = 0x5400ff1b,
};

uint32_t mspe_poweron(uint32_t cmd, uint32_t id, uint32_t profile);

uint32_t mspe_poweroff(uint32_t cmd, uint32_t id, uint32_t profile);

uint32_t mspe_rnd_gen_trnd(uint32_t cmd, const struct prip_drv_param *param);

uint32_t mspe_sm2_gen_key(uint32_t cmd, const struct prip_drv_param *param);

uint32_t mspe_sm2_encrypt(uint32_t cmd, const struct prip_drv_param *param);

uint32_t mspe_sm2_decrypt(uint32_t cmd, const struct prip_drv_param *param);

uint32_t mspe_sm3_hash_init(uint32_t cmd, const struct prip_drv_param *param);

uint32_t mspe_sm3_hash_update(uint32_t cmd, const struct prip_drv_param *param);

uint32_t mspe_sm3_hash_dofinal(uint32_t cmd, const struct prip_drv_param *param);

uint32_t mspe_sm3_hash_sigle(uint32_t cmd, const struct prip_drv_param *param);

uint32_t mspe_sm4_set_key(uint32_t cmd, const struct prip_drv_param *param);

uint32_t mspe_sm4_set_iv(uint32_t cmd, const struct prip_drv_param *param);

uint32_t mspe_sm4_init(uint32_t cmd, const struct prip_drv_param *param);

uint32_t mspe_sm4_update(uint32_t cmd, const struct prip_drv_param *param);

uint32_t mspe_sm4_dofinal(uint32_t cmd, const struct prip_drv_param *param);

uint32_t mspe_km_derive_kdr(uint32_t cmd, const struct prip_drv_param *param);

uint32_t mspe_sm9_sign(uint32_t cmd, const struct prip_drv_param *param);

uint32_t mspe_sm9_verify(uint32_t cmd, const struct prip_drv_param *param);

uint32_t mspe_sm9_encrypt(uint32_t cmd, const struct prip_drv_param *param);

uint32_t mspe_sm9_decrypt(uint32_t cmd, const struct prip_drv_param *param);

uint32_t mspe_sm9_wrap_key(uint32_t cmd, const struct prip_drv_param *param);

uint32_t mspe_sm9_unwrap_key(uint32_t cmd, const struct prip_drv_param *param);

uint32_t mspe_sm9_pre_data(uint32_t cmd, const struct prip_drv_param *param);

#endif
