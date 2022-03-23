/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: privacy data protection api syscall interface, call tee drvier api
 * Create: 2020-03-10
 */
#ifndef HISI_PRIVACY_PROTECTION_DRV_H
#define HISI_PRIVACY_PROTECTION_DRV_H

#include "stdint.h"

/* privacy protection */
uint32_t __mspe_poweron(uint32_t cmd, uint32_t id, uint32_t profile);
uint32_t __mspe_poweroff(uint32_t cmd, uint32_t id, uint32_t profile);
uint32_t __mspe_rnd_gen_trnd(uint32_t cmd, const uint8_t *sendbuf, uint32_t sendlen);
uint32_t __mspe_sm2_gen_key(uint32_t cmd, const uint8_t *sendbuf, uint32_t sendlen);
uint32_t __mspe_sm2_encrypt(uint32_t cmd, const uint8_t *sendbuf, uint32_t sendlen);
uint32_t __mspe_sm2_decrypt(uint32_t cmd, const uint8_t *sendbuf, uint32_t sendlen);
uint32_t __mspe_sm3_hash_init(uint32_t cmd, const uint8_t *sendbuf, uint32_t sendlen);
uint32_t __mspe_sm3_hash_update(uint32_t cmd, const uint8_t *sendbuf, uint32_t sendlen);
uint32_t __mspe_sm3_hash_dofinal(uint32_t cmd, const uint8_t *sendbuf, uint32_t sendlen);
uint32_t __mspe_sm3_hash_sigle(uint32_t cmd, const uint8_t *sendbuf, uint32_t sendlen);
uint32_t __mspe_sm4_set_key(uint32_t cmd, const uint8_t *sendbuf, uint32_t sendlen);
uint32_t __mspe_sm4_set_iv(uint32_t cmd, const uint8_t *sendbuf, uint32_t sendlen);
uint32_t __mspe_sm4_init(uint32_t cmd, const uint8_t *sendbuf, uint32_t sendlen);
uint32_t __mspe_sm4_update(uint32_t cmd, const uint8_t *sendbuf, uint32_t sendlen);
uint32_t __mspe_sm4_dofinal(uint32_t cmd, const uint8_t *sendbuf, uint32_t sendlen);
uint32_t __mspe_km_derive_kdr(uint32_t cmd, const uint8_t *sendbuf, uint32_t sendlen);
uint32_t __mspe_sm9_sign(uint32_t cmd, const uint8_t *sendbuf, uint32_t sendlen);
uint32_t __mspe_sm9_verify(uint32_t cmd, const uint8_t *sendbuf, uint32_t sendlen);
uint32_t __mspe_sm9_wrap_key(uint32_t cmd, const uint8_t *sendbuf, uint32_t sendlen);
uint32_t __mspe_sm9_unwrap_key(uint32_t cmd, const uint8_t *sendbuf, uint32_t sendlen);
uint32_t __mspe_sm9_encrypt(uint32_t cmd, const uint8_t *sendbuf, uint32_t sendlen);
uint32_t __mspe_sm9_decrypt(uint32_t cmd, const uint8_t *sendbuf, uint32_t sendlen);
uint32_t __mspe_sm9_pre_data(uint32_t cmd, const uint8_t *sendbuf, uint32_t sendlen);

#endif
