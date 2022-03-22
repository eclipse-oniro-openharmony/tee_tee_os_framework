/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: keymaster environment header
 * Create: 2020-05-04
 */

#ifndef __KM_ENV_H
#define __KM_ENV_H

#include "tee_internal_api.h"
#include "pthread.h"
#include "keymaster_defs.h"
/* keymaster1 versions */
#define VERSION_100 100 /* crypto and HMAC with kdf */
#define VERSION_110 110 /* crypto with ROT, HMAC with kdf */
/* keymaster2 versions */
#define VERSION_200 200 /* crypto and HMAC with kdf */
#define VERSION_210 210 /* crypto with ROT, HMAC with kdf */
/* the above version need dx interfaces */
#define VERSION_220 220 /* crypto and HMAC with ROT -> version 520 */
#define VERSION_230 230 /* crypto and HMAC with ROT using AES CTR ->version 530 */
#define VERSION_300 300 /* crypto and HMAC with application id -> version 500 */
#define VERSION_310 310 /* crypto and HMAC with application id using AES CTR -> version 510 */
#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
#define VERSION_340 340 /* crypto with enhanced application id, HMAC with HUK using AES CTR -> version 340 */
/* crypto with inse factor, enhanced application id, HMAC with HUK using AES CTR -> version 341 */
#define VERSION_341 341
#endif
#define VERSION_500 500 /* gp format keymaterial, crypto and HMAC with application id (v300) */
#define VERSION_510 510 /* gp format keymaterial, crypto and HMAC with application id using AES CTR (v310) */
#define VERSION_520 520 /* gp format keymaterial, crypto and HMAC with ROT(v220) */
#define VERSION_530 530 /* gp format keymaterial, crypto and HMAC with ROT using AES CTR(v230) */
#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
#define VERSION_540 540 /* gp format keymaterial, crypto with enhanced appid, HMAC with ROT using AES CTR(v340) */
/* gp format keymaterial, crypto with inse factor, enhanced appid, HMAC with ROT using AES CTR(v341) */
#define VERSION_541 541
#endif

#define DEF_RSA_PUB_EXPONENT 0x10001
#define KEY_MAX_SIZE         64
#define RSA_TAG_ENFORCED     5
#define EC_TAG_ENFORCED      4
#define KM_TAG_HIDDEN        3
#define ROT_SIZE             32


pthread_mutex_t *get_attest_key_lock(void);
pthread_mutex_t *get_key_index_lock(void);
pthread_mutex_t *get_opera_metafile_lock(void);

/* For TA call TA */
int32_t generate_rot(void);
uint8_t *get_rot(void);
int get_lock_color(int gen_or_check, int *adaptable, int *lock_color);
int preproc_keymaster_hmac(int gen_or_check, int *adaptable, uint32_t version,
    const keymaster_blob_t *application_id, uint8_t *key);
bool is_cfg_state_ready(void);

void set_lock_state(state_lock_t state);
state_lock_t get_lock_state(void);

state_set_t get_cfg_state(void);

void set_cfg_state(state_set_t cfg);

int init_verify_boot_info(void);

enum lock_state get_verify_boot_lock_state(void);
enum lock_color get_verify_boot_color(void);
uint32_t get_verify_boot_os_version(void);
uint32_t get_verify_boot_patch_level(void);
void set_sys_os_version(uint32_t os_version);
void set_sys_patch_level(uint32_t patch_level);
void set_vendor_patch_level(uint32_t patch_level);
void get_verify_boot_key(keymaster_blob_t *verified_boot_key);
#endif
