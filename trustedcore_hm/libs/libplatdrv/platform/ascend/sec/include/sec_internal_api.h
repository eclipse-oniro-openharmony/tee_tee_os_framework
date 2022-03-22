/*
* Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
* Description: the internal function head of sec
* Author: chenyao
* Create: 2019/12/30
*/
#ifndef __SEC_INTERNAL_API_H__
#define __SEC_INTERNAL_API_H__

#include <stdint.h>

uint32_t sec_rst_req_en(void);
uint32_t sec_rst_req_disable(void);
uint32_t sec_clk_en(void);
uint32_t  sec_clk_disable(void);
uint32_t sec_clk_rst(void);

void sec_bd_fifo_conf(void);
uint32_t sec_pf_conf(void);
uint32_t sec_check_init(void);
uint32_t sec_init_check(void);

uint32_t km_req_key_hand(uint32_t type);

uint32_t sec_aes_sm4_bd(SEC_AES_INFO_S *aes_info);

uint32_t sec_aes_gcm_bd(SEC_AES_GCM_INFO_S *aes_gcm_info);
uint32_t sec_aes_gcm_km_bd(SEC_AES_GCM_INFO_S *aes_gcm_info);
uint32_t sec_aes_gcm_init_bd(SEC_AES_GCM_INFO_S *aes_gcm_info);
uint32_t sec_aes_gcm_update_bd(SEC_AES_GCM_INFO_S *aes_gcm_info);
uint32_t sec_aes_gcm_final_bd(SEC_AES_GCM_INFO_S *aes_gcm_info);

uint32_t sec_hash_bd(SEC_HASH_INFO_S *hash_info);
uint32_t sec_hash_init_bd(SEC_HASH_INFO_S *hash_info);
uint32_t sec_hash_update_bd(SEC_HASH_INFO_S *hash_info);
uint32_t sec_hash_final_bd(SEC_HASH_INFO_S *hash_info);

uint32_t sec_hmac_bd(SEC_HMAC_INFO_S *hmac_info);
uint32_t sec_hmac_init_bd(SEC_HMAC_INFO_S *hmac_info);
uint32_t sec_hmac_update_bd(SEC_HMAC_INFO_S *hmac_info);
uint32_t sec_hmac_final_bd(SEC_HMAC_INFO_S *hmac_info);

uint32_t sec_pbkdf2_bd(SEC_PBKDF2_INFO_S *pbkdf2_info);

uint32_t sec_add_task(unsigned long bd_addr);
uint32_t sec_task_check(unsigned long bd_addr);
uint32_t sec_final_task_check(unsigned long bd_addr);

#endif
