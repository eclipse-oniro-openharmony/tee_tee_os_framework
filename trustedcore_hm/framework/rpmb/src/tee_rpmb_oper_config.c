/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: rpmb operation config
 * Create: 2020-02-13
 */
#include "tee_rpmb_oper_config.h"
#include <string.h>
#include <securec.h>
#include <tee_mem_mgmt_api.h>
#include <tee_log.h>
#include "platform_get.h"
#include <mem_ops_ext.h>
#include <tee_ext_api.h>
#include <tee_private_api.h>
#include <tee_crypto_hal.h>
#include <crypto_hal_derive_key.h>
#include <crypto_hal_hmac.h>
#ifdef TEE_SUPPORT_HSM
#include <hsm_rpmb_api.h>
#endif
#include <openssl/hmac.h>
#include <openssl/ossl_typ.h>
#include <hmac/hmac_local.h>
#include <openssl/evp.h>
#include <evp/evp_local.h>
#include <hmdrv.h>
#include <sre_syscalls_id.h>
#include <boot_sharedmem.h>
#include "rpmb_key_stat.h"
#include "rpmb_config.h"
#ifdef CFG_TEE_RPMB_SUPPORT
#include "tee_flash_ext.h"
#endif
#include "sec_fs_type.h"

#define RPMB_BORINGSSL_OK 1
#define RPMB_SIZE_SINGLE (128U * 1024U)
#define RAW_RPMB_SIZE_MULT        0x20U
#define RPMB_MAX_BLOCK_IDX        ((RAW_RPMB_SIZE_MULT * RPMB_SIZE_SINGLE / RPMB_DATA_SIZE) - 1)
/* SEC MEM magic */
#define SEC_MEM_MAGIC 0x3C562817U
/* SEC MEM version */
#define SEC_MEM_VERSION 0x00010000U

#define CMAC_KEY_SIZE 16U

__attribute__((weak)) uint32_t g_rpmb_agent_buffersize;

struct rpmb_partition_info {
    uint32_t start_blk;
    uint32_t total_blk;
    uint32_t mdt;
    uint32_t support_bitmap;
    uint32_t version;
};

TEE_Result rpmb_reset_permission_in_tbl(const TEE_UUID *uuid)
{
    uint32_t i;

    if (uuid == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    for (i = 0; i < g_rpmb_permission_number; i++) {
        if ((TEE_MemCompare(uuid, &g_rpmb_permission_config[i].uuid, sizeof(*uuid)) == 0) &&
            ((RPMB_SPECIFIC_PERMISSION & g_rpmb_permission_config[i].permissions) != 0))
            return TEE_SUCCESS;
    }

    return TEE_ERROR_GENERIC;
}

/* Check the TA whether have the RPMB_GENERIC_PERMISSION or not */
TEE_Result rpmb_status_permission_in_tbl(const TEE_UUID *uuid)
{
    uint32_t i;

    if (uuid == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    for (i = 0; i < g_rpmb_permission_number; i++) {
        if ((TEE_MemCompare(uuid, &g_rpmb_permission_config[i].uuid, sizeof(*uuid)) == 0) &&
            ((RPMB_GENERIC_PERMISSION & g_rpmb_permission_config[i].permissions) != 0))
            return TEE_SUCCESS;
    }

    return TEE_ERROR_GENERIC;
}

TEE_Result rpmb_get_ta_threshold_in_tbl(const TEE_UUID *uuid, uint32_t *ta_threshold)
{
    uint32_t i;

    if (uuid == NULL || ta_threshold == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    for (i = 0; i < g_rpmb_ta_number; i++) {
        if (TEE_MemCompare(uuid, &(g_ta_rpmb_threshold_config[i].uuid), sizeof(*uuid)) == 0) {
            *ta_threshold = g_ta_rpmb_threshold_config[i].threshold;
            return TEE_SUCCESS;
        }
    }

    return TEE_ERROR_GENERIC;
}

uint32_t rpmb_get_all_ta_threshold_without_fingerprint(void)
{
    uint32_t i;
    TEE_UUID fp_uuid = TEE_SERVICE_FINGERPRINT;
    uint32_t other_threshold = 0;

    for (i = 0; i < g_rpmb_ta_number; i++) {
        if (TEE_MemCompare(&fp_uuid, &(g_ta_rpmb_threshold_config[i].uuid), sizeof(fp_uuid)) == 0)
            continue;
        other_threshold += g_ta_rpmb_threshold_config[i].threshold;
    }

    return other_threshold;
}

struct rpmb_chip_relation {
    uint32_t chip;
    uint32_t key_type;
    uint32_t meta_type;
};

const struct rpmb_chip_relation g_chip_relation_set[] = {
#if defined(WITH_CHIP_HI6250)
    { WITH_CHIP_HI6250,    RPMB_ACCESS_KEY, SEC_FS_META },
#elif defined(WITH_CHIP_HI3660)
    { WITH_CHIP_HI3660,    RPMB_ACCESS_KEY, SEC_FS_META_EX },
#elif defined(WITH_CHIP_HI3670)
    { WITH_CHIP_HI3670,    RPMB_ACCESS_KEY, SEC_FS_META_EX },
#elif defined(WITH_CHIP_HI6260)
    { WITH_CHIP_HI6260,    RPMB_ACCESS_KEY, SEC_FS_META_EX },
#elif defined(WITH_CHIP_HI3680)
    { WITH_CHIP_HI3680,    RPMB_ACCESS_KEY, SEC_FS_META_ENCRYPTO },
#elif defined(WITH_CHIP_MT6765)
    { WITH_CHIP_MT6765,    RPMB_M_KEY,    SEC_FS_META_ENCRYPTO },
#elif defined(WITH_CHIP_MT6873)
    { WITH_CHIP_MT6873,    RPMB_M_KEY,    SEC_FS_META_ENCRYPTO },
#elif defined(WITH_CHIP_MT6853)
    { WITH_CHIP_MT6853,    RPMB_M_KEY,    SEC_FS_META_ENCRYPTO },
#elif defined(WITH_CHIP_MT6768)
    { WITH_CHIP_MT6768,    RPMB_M_KEY,    SEC_FS_META_ENCRYPTO },
#elif defined(WITH_CHIP_MT6885)
    { WITH_CHIP_MT6885,    RPMB_M_KEY,    SEC_FS_META_ENCRYPTO_HMAC },
#elif defined(WITH_CHIP_KIRIN990)
    { WITH_CHIP_KIRIN990,  RPMB_ACCESS_KEY, SEC_FS_META_ENCRYPTO_ENHANCE },
#elif defined(WITH_CHIP_ORLANDO)
    { WITH_CHIP_ORLANDO,   RPMB_ACCESS_KEY, SEC_FS_META_ENCRYPTO_ENHANCE },
#elif defined(WITH_CHIP_BALTIMORE)
    { WITH_CHIP_BALTIMORE, RPMB_ACCESS_KEY, SEC_FS_META_ENCRYPTO_HMAC },
#elif defined(WITH_CHIP_BURBANK)
    { WITH_CHIP_BURBANK,   RPMB_ACCESS_KEY, SEC_FS_META_ENCRYPTO_HMAC },
#elif defined(WITH_CHIP_LEXINGTON)
    { WITH_CHIP_LEXINGTON, RPMB_ACCESS_KEY, SEC_FS_META_ENCRYPTO_HMAC },
#elif defined(WITH_CHIP_CHARLOTTE)
    { WITH_CHIP_CHARLOTTE, RPMB_ACCESS_KEY, SEC_FS_META_ENCRYPTO_HMAC },
#elif defined(WITH_CHIP_DENVER)
    { WITH_CHIP_DENVER,    RPMB_ACCESS_KEY, SEC_FS_META_ENCRYPTO_HMAC },
#elif defined(WITH_CHIP_MIAMICW)
    { WITH_CHIP_MIAMICW,   RPMB_ACCESS_KEY, SEC_FS_META_ENCRYPTO_HMAC },
#elif defined(WITH_CHIP_LAGUNA)
    { WITH_CHIP_LAGUNA,    RPMB_ACCESS_KEY, SEC_FS_META_ENCRYPTO_HMAC },
#elif defined(WITH_CHIP_SHAOLINGUN)
    { WITH_CHIP_SHAOLINGUN, RPMB_ACCESS_KEY, SEC_FS_META_ENCRYPTO_HMAC },
#endif
};
const uint32_t g_chip_relation_number = sizeof(g_chip_relation_set) / sizeof(g_chip_relation_set[0]);

void tee_rpmb_get_key_type(uint32_t *key_type)
{
    uint32_t platform;
    uint32_t chip;

    if (key_type == NULL)
        return;

    *key_type = RPMB_KEY_UNKOWN;
    if (__get_platform_chip(&platform, &chip) != 0) {
        tloge("get platform failed\n");
        return;
    }

    /* platform and chip value is same as defined in trustedcore.mk */
#if defined(WITH_HIGENERIC_PLATFORM) || defined(WITH_MTK_PLATFORM) || defined(WITH_HUANGLONG_PLATFORM)
    uint32_t i;
    for (i = 0; i < g_chip_relation_number; i++) {
        if (chip == g_chip_relation_set[i].chip) {
            *key_type = g_chip_relation_set[i].key_type;
            break;
        }
    }
#elif defined(WITH_ASCEND_PLATFORM)
    *key_type = RPMB_HSM_KEY;
#endif
}

void tee_rpmb_get_meta_type(uint32_t *meta_type)
{
    uint32_t platform;
    uint32_t chip;

    if (meta_type == NULL)
        return;

    *meta_type = SEC_FS_META_UNKOWN;
    if (__get_platform_chip(&platform, &chip) != 0) {
        tloge("get platform failed\n");
        return;
    }

    /* platform and chip value is same as defined in trustedcore.mk */
#if defined(WITH_HIGENERIC_PLATFORM) || defined(WITH_MTK_PLATFORM) || defined(WITH_HUANGLONG_PLATFORM)
    uint32_t i;
    for (i = 0; i < g_chip_relation_number; i++) {
        if (chip == g_chip_relation_set[i].chip) {
            *meta_type = g_chip_relation_set[i].meta_type;
            break;
        }
    }
#elif defined(WITH_ASCEND_PLATFORM)
    *meta_type = SEC_FS_META_ENCRYPTO_HMAC;
#endif
}

bool is_fingerprint(const TEE_UUID *uuid)
{
    TEE_UUID fp_uuid = TEE_SERVICE_FINGERPRINT;

    if (uuid == NULL)
        return false;

    if (TEE_MemCompare(uuid, &fp_uuid, sizeof(*uuid)) == 0)
        return true;
    else
        return false;
}

#define RPMB_ENCRYPTION_AAD "encrypt for rpmb key"
#define KEY_LEN             32U
static uint8_t g_rpmb_ccm_key[KEY_LEN];
static bool g_ccm_key_ready = false;
/* derive ase-256 key using 'derive_data' */
static TEE_Result tee_rpmb_key_init(uint8_t *dataout, uint32_t *size)
{
    TEE_Result cc_ret;
    errno_t rc;
    const char *derive_data = "derive for encrypt rpmb key";

    if (*size < KEY_LEN)
        return TEE_ERROR_SHORT_BUFFER;

    if (!g_ccm_key_ready) {
        cc_ret = tee_ext_root_derive_key2((uint8_t *)derive_data, strlen(derive_data),
            g_rpmb_ccm_key, sizeof(g_rpmb_ccm_key));
        if (cc_ret != TEE_SUCCESS) {
            tloge("cmac derive key failed, ret = 0x%x\n", cc_ret);
            return TEE_ERROR_GENERIC;
        }
        g_ccm_key_ready = true;
    }

    rc = memcpy_s(dataout, *size, g_rpmb_ccm_key, sizeof(g_rpmb_ccm_key));
    if (rc != EOK)
        return TEE_ERROR_SECURITY;

    *size = (uint32_t)sizeof(g_rpmb_ccm_key);
    return TEE_SUCCESS;
}

#define BORINGSSL_ENCRYPT 1U
#define BORINGSSL_DECRYPT 0U
#define NONCE_LEN         8U
#define TAG_LEN           16U

struct aes_ccm_st {
    uint8_t *nonce;
    uint32_t nonce_len;
    uint8_t *tag;
    uint32_t tag_len;
};

struct crypt_data_st {
    uint8_t *src_data;
    uint32_t src_len;
    uint8_t *dest_data;
};

static TEE_Result set_cipher_encrypt_tag_nonce_key(EVP_CIPHER_CTX *ctx, struct aes_ccm_st *encrypt_st,
                                                   const uint8_t *key, uint32_t mode)
{
    int32_t result;

    result = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, encrypt_st->nonce_len, NULL);
    if (result != RPMB_BORINGSSL_OK) {
        tloge("rpmb EVP CIPHER CTX ctrl set nonce_len failed!\n");
        return TEE_ERROR_GENERIC;
    }

    if (mode == BORINGSSL_ENCRYPT)
        result = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, encrypt_st->tag_len, NULL);
    else
        result = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, encrypt_st->tag_len, encrypt_st->tag);

    if (result != RPMB_BORINGSSL_OK) {
        tloge("rpmb compare tag error!\n");
        return TEE_ERROR_GENERIC;
    }

    result = EVP_CipherInit(ctx, NULL, key, encrypt_st->nonce, mode);
    if (result != RPMB_BORINGSSL_OK) {
        tloge("rpmb set key and nonce failed!\n");
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

static TEE_Result do_cipher_encrypt(struct aes_ccm_st *encrypt_st, struct crypt_data_st *data_st, const uint8_t *key,
                                    uint32_t mode)
{
    EVP_CIPHER_CTX ctx = { 0 };
    TEE_Result ret;
    int32_t result;

    result = EVP_CipherInit(&ctx, EVP_aes_256_ccm(), NULL, NULL, mode);
    if (result != RPMB_BORINGSSL_OK) {
        tloge("rpmb EVP Cipher Init failed!\n");
        ret = TEE_ERROR_GENERIC;
        goto clear;
    }

    ret = set_cipher_encrypt_tag_nonce_key(&ctx, encrypt_st, key, mode);
    if (ret != TEE_SUCCESS)
        goto clear;

    result = EVP_Cipher(&ctx, NULL, NULL, data_st->src_len);
    if (result != (int32_t)data_st->src_len) {
        tloge("rpmb set src Len to ctx failed!\n");
        ret = TEE_ERROR_GENERIC;
        goto clear;
    }

    result = EVP_Cipher(&ctx, NULL, (const uint8_t *)RPMB_ENCRYPTION_AAD, sizeof(RPMB_ENCRYPTION_AAD));
    if (result < 0) {
        tloge("rpmb set aad failed!\n");
        ret = TEE_ERROR_GENERIC;
        goto clear;
    }

    result = EVP_Cipher(&ctx, data_st->dest_data, data_st->src_data, data_st->src_len);
    if (result != (int32_t)data_st->src_len) {
        tloge("do encrypt failed!\n");
        ret = TEE_ERROR_GENERIC;
        goto clear;
    }

    if (mode == BORINGSSL_ENCRYPT) {
        result = EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_GET_TAG, encrypt_st->tag_len, encrypt_st->tag);
        if (result != RPMB_BORINGSSL_OK) {
            tloge("rpmb get tag failed!\n");
            ret = TEE_ERROR_GENERIC;
            goto clear;
        }
    }
clear:
    EVP_CIPHER_CTX_reset(&ctx);
    return ret;
}

static TEE_Result aes_ccm_encrypt(const uint8_t *key, const uint8_t *src_data, uint32_t src_len, uint8_t *dest_data,
                                  uint32_t *dest_len)
{
    errno_t rc;
    uint8_t nonce[NONCE_LEN] = { 0 }; /* Valid range = [7 .. 13] */
    uint8_t tag[TAG_LEN] = { 0 }; /* Valid range = [4, 6, 8, 10, 12, 14, 16] */
    struct aes_ccm_st encrypt_st = { 0 };
    struct crypt_data_st date_st = { 0 };
    uint32_t dest_size;

    if (*dest_len < (src_len + sizeof(nonce) + sizeof(tag)))
        return TEE_ERROR_SHORT_BUFFER;

    dest_size = *dest_len;
    /* generate one 8-bytes random number */
    TEE_GenerateRandom(nonce, sizeof(nonce));

    encrypt_st.nonce     = nonce;
    encrypt_st.nonce_len = (uint32_t)sizeof(nonce);
    encrypt_st.tag       = tag;
    encrypt_st.tag_len   = (uint32_t)sizeof(tag);

    date_st.src_len      = src_len;
    date_st.src_data     = (uint8_t *)src_data;
    date_st.dest_data    = dest_data;
    if (do_cipher_encrypt(&encrypt_st, &date_st, key, BORINGSSL_ENCRYPT) != TEE_SUCCESS) {
        tloge("do aes ccm encrypt failed!\n");
        return TEE_ERROR_GENERIC;
    }

    /* dest_data: encrypt_buffer + nonce + mac */
    rc = memcpy_s(dest_data + src_len, dest_size - src_len, nonce, sizeof(nonce));
    if (rc != EOK) {
        (void)memset_s(tag, sizeof(tag), 0, sizeof(tag));
        tloge("copy nonce failed!\n");
        return TEE_ERROR_SECURITY;
    }
    rc = memcpy_s(dest_data + src_len + sizeof(nonce), dest_size - src_len - sizeof(nonce), tag, sizeof(tag));
    (void)memset_s(tag, sizeof(tag), 0, sizeof(tag));
    if (rc != EOK) {
        tloge("copy tag failed!\n");
        return TEE_ERROR_SECURITY;
    }
    *dest_len = src_len + (uint32_t)sizeof(nonce) + (uint32_t)sizeof(tag);
    return TEE_SUCCESS;
}

static TEE_Result tee_rpmb_key_encrypt(const uint8_t *src_data, uint32_t src_len,
                                       uint8_t *dest_data, uint32_t *dest_len)
{
    uint8_t key[RPMB_KEY_MAC_SIZE] = { 0 }; /* MUST be 128, 192 or 256 bits */
    uint32_t key_len = (uint32_t)sizeof(key);
    TEE_Result ret;

    /* get a aes-256 key derived by 'derivedata' and 'DX_ROOT_KEY' */
    ret = tee_rpmb_key_init(key, &key_len);
    if (ret != TEE_SUCCESS) {
        tloge("rpmb key init failed ret = 0x%x\n", ret);
        return TEE_ERROR_GENERIC;
    }

    ret = aes_ccm_encrypt(key, src_data, src_len, dest_data, dest_len);
    if (ret != TEE_SUCCESS) {
        tloge("aes ccm encrypt failed, ret = 0x%x\n", ret);
        goto error;
    }
    ret = TEE_SUCCESS;
error:
    (void)memset_s(key, sizeof(key), 0, sizeof(key));
    return ret;
}

static TEE_Result aes_ccm_decrypt(const uint8_t *key, const uint8_t *src_data, uint32_t src_len, uint8_t *dest_data,
                                  uint32_t *dest_len)
{
    errno_t rc;
    TEE_Result ret;
    uint8_t nonce[NONCE_LEN] = { 0 }; /* Valid range = [7 .. 13] */
    uint8_t tag[TAG_LEN] = { 0 }; /* Valid range = [4, 6, 8, 10, 12, 14, 16] */
    struct aes_ccm_st encrypt_st = { 0 };
    struct crypt_data_st date_st = { 0 };
    uint32_t decrypt_buff_len;

    if (src_len < (uint32_t)(sizeof(tag) + sizeof(nonce))) {
        tloge("src len is too short!\n");
        return TEE_ERROR_SHORT_BUFFER;
    }
    if (*dest_len < src_len - (uint32_t)(sizeof(tag) + sizeof(nonce))) {
        tloge("dest len is too short!\n");
        return TEE_ERROR_SHORT_BUFFER;
    }

    decrypt_buff_len = src_len - (uint32_t)(sizeof(nonce) + sizeof(tag));
    rc = memcpy_s(nonce, sizeof(nonce), src_data + decrypt_buff_len, sizeof(nonce));
    if (rc != EOK) {
        tloge("memory copy nonce error!\n");
        return TEE_ERROR_SECURITY;
    }

    rc = memcpy_s(tag, sizeof(tag), src_data + decrypt_buff_len + sizeof(nonce), sizeof(tag));
    if (rc != EOK) {
        tloge("memory copy tag error!\n");
        return TEE_ERROR_SECURITY;
    }

    encrypt_st.nonce     = nonce;
    encrypt_st.nonce_len = (uint32_t)sizeof(nonce);
    encrypt_st.tag       = tag;
    encrypt_st.tag_len   = (uint32_t)sizeof(tag);

    date_st.src_len      = decrypt_buff_len;
    date_st.src_data     = (uint8_t *)src_data;
    date_st.dest_data    = dest_data;
    ret = do_cipher_encrypt(&encrypt_st, &date_st, key, BORINGSSL_DECRYPT);
    (void)memset_s(tag, sizeof(tag), 0, sizeof(tag));
    if (ret != TEE_SUCCESS) {
        tloge("do aes ccm encrypt failed!\n");
        return TEE_ERROR_GENERIC;
    }

    *dest_len = decrypt_buff_len;

    return TEE_SUCCESS;
}

static TEE_Result tee_rpmb_key_decrypt(const uint8_t *src_data, uint32_t src_len,
                                       uint8_t *dest_data, uint32_t *dest_len)
{
    uint8_t key[RPMB_KEY_MAC_SIZE] = { 0 }; /* MUST be 128, 192 or 256 bits */
    uint32_t key_len = (uint32_t)sizeof(key);
    TEE_Result ret;

    ret = tee_rpmb_key_init(key, &key_len);
    if (ret != TEE_SUCCESS) {
        tloge("rpmb key init failed, ret = 0x%x\n", ret);
        return TEE_ERROR_GENERIC;
    }
    ret = aes_ccm_decrypt(key, src_data, src_len, dest_data, dest_len);
    if (ret != TEE_SUCCESS) {
        tloge("aes ccm encrypt failed, ret = 0x%x\n", ret);
        goto error;
    }
    ret = TEE_SUCCESS;
error:
    (void)memset_s(key, sizeof(key), 0, sizeof(key));

    return ret;
}

#define RPMB_KEY_INFO_SIZE 0x100
static uint8_t g_u_key_info[RPMB_KEY_INFO_SIZE] __attribute__((aligned(0x100)));
static struct rpmb_atf_info g_u_rai __attribute__((aligned(0x400)));
static void tee_rpmb_clear_chip_info(void)
{
    /* clear the global variable to protect the key */
    (void)memset_s(g_u_key_info, sizeof(g_u_key_info), 0, sizeof(g_u_key_info));
    (void)memset_s(&g_u_rai, sizeof(g_u_rai), 0, sizeof(g_u_rai));
}

#if !defined(WITH_CHIP_SHAOLINGUN)
void rpmb_smc_switch(uint64_t addr, uint32_t size, uint64_t data_addr, uint32_t data_len);
static TEE_Result tee_rpmb_get_info_from_atf(const struct rpmb_atf_info *rai)
{
    /* smc switch to bl31 */
    rpmb_smc_switch((uintptr_t)rai, sizeof(*rai), (uintptr_t)g_u_key_info, sizeof(g_u_key_info));

    /* check result from ATF */
    if (rai->ret == 0) {
        tlogd("get info from ATF success\n");

        if (rai->total_blk == 0) {
            tloge("get info from ATF failed, total_blk is 0!\n");
            return TEE_ERROR_GENERIC;
        } else {
            return TEE_SUCCESS;
        }
    } else {
        tloge("get info from ATF failed, ret = 0x%x\n", rai->ret);
        return TEE_ERROR_GENERIC;
    }
}
#endif

static TEE_Result tee_rpmb_get_info(void)
{
    TEE_Result ret;

    g_u_rai.data_addr = (uintptr_t)g_u_key_info;
    g_u_rai.data_len  = (uint32_t)sizeof(g_u_key_info);
    g_u_rai.ret       = (uint32_t)TEE_ERROR_GENERIC;

#if defined(WITH_CHIP_SHAOLINGUN)
    ret = ext_tee_flash_get_rpmb_info(&g_u_rai, sizeof(g_u_rai));
#else
    /* data_addr should be phys addr, otherwise bl31 cannot access it. */
    g_u_rai.data_addr = (uint32_t)tee_virt_to_phys((uintptr_t)g_u_key_info);
    ret = tee_rpmb_get_info_from_atf(&g_u_rai);
    /* wh: after this call, we should resume the virt addr, thus rpmb can use it. */
    g_u_rai.data_addr = (uintptr_t)g_u_key_info;
#endif

    if (ret != TEE_SUCCESS) {
        tloge("rpmb get info from atf failed!\n");
        return TEE_ERROR_GENERIC;
    }

    if (g_u_rai.data_len > RPMB_ROOTKEY_SIZE_MAX) {
        tloge("the key size if too long 0x%x, max size 0x%x\n", g_u_rai.data_len, RPMB_ROOTKEY_SIZE_MAX);
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

static TEE_Result tee_rpmb_get_chip_info(uint32_t key_type)
{
    TEE_Result ret;
    uint32_t res_code;
    uint8_t tmp_buff[RPMB_ROOTKEY_SIZE_MAX] = { 0 };
    uint32_t tmp_buff_len = (uint32_t)sizeof(tmp_buff);

    tee_rpmb_clear_chip_info();

    ret = tee_rpmb_get_info();
    if (ret != TEE_SUCCESS) {
        tloge("rpmb get info from atf failed!\n");
        goto out;
    }

    res_code = rpmb_partition_info_write(&g_u_rai);
    if (res_code != RPMB_PARTITION_INFO_READY) {
        tloge("save partition infor failed, 0x%x\n", res_code);
        tee_rpmb_clear_chip_info();
        return TEE_ERROR_GENERIC;
    }
    if (key_type == RPMB_ACCESS_KEY) {
        ret = tee_rpmb_key_encrypt((uint8_t *)(uintptr_t)g_u_key_info, g_u_rai.data_len, tmp_buff, &tmp_buff_len);
        if (ret == TEE_SUCCESS) {
            /*
             * tmp_buff store the rpmb key info, and copy the key info into an global buffer.
             * encrypt_buffer + nonce + mac
             */
            res_code = rpmb_keyinfo_info_write((char *)tmp_buff, tmp_buff_len);
            if (res_code != RPMB_KEY_INFO_READY) {
                tloge("save info failed, 0x%x\n", res_code);
                ret = TEE_ERROR_GENERIC;
            }
        }
    } else {
        tloge("key type is not support, key type is %u\n", key_type);
        ret = TEE_ERROR_GENERIC;
    }

out:
    if (ret != TEE_SUCCESS)
        tee_rpmb_clear_chip_info();

    return ret;
}

static TEE_Result tee_rpmb_get_rootkey_data(uint8_t *data, uint32_t *size, uint32_t key_type)
{
    TEE_Result ret;
    uint32_t stat;
    uint8_t tmp_buff[RPMB_ROOTKEY_SIZE_MAX] = { 0 };
    uint32_t tmp_buff_len = (uint32_t)sizeof(tmp_buff);

    if (data == NULL || size == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    stat = rpmb_keyinfo_info_read((char *)tmp_buff, &tmp_buff_len);
    if (stat != RPMB_KEY_INFO_READY) {
        /* read from atf */
        ret = tee_rpmb_get_chip_info(key_type);
        if (ret != TEE_SUCCESS)
            return ret;

        tee_rpmb_clear_chip_info();
    }

    if (key_type == RPMB_ACCESS_KEY) {
        tmp_buff_len = (uint32_t)sizeof(tmp_buff);
        stat = rpmb_keyinfo_info_read((char *)tmp_buff, &tmp_buff_len);
        if (stat == RPMB_KEY_INFO_READY) {
            ret = tee_rpmb_key_decrypt(tmp_buff, tmp_buff_len, data, size);
        } else {
            tloge("read info error 0x%x\n", stat);
            ret = TEE_ERROR_GENERIC;
        }
    } else {
        tloge("key type is not support %u\n", key_type);
        ret = TEE_ERROR_BAD_PARAMETERS;
    }

    (void)memset_s(tmp_buff, sizeof(tmp_buff), 0, sizeof(tmp_buff));

    return ret;
}
/*
 * g_rpmb_key_prepare hold the RPMB Key.
 *
 * Notice:
 * For save the time of DeriveKey, we DeriveKey one time.
 * You can use it in write&read function.
 */
static TEE_Result tee_rpmb_key_prepare_access(uint8_t *key_prepare, uint32_t key_len)
{
    errno_t rc;
    TEE_Result ret;
    uint8_t data[RPMB_ROOTKEY_SIZE_MAX] = { 0 };
    uint32_t datalen = (uint32_t)sizeof(data);

    if (key_len < RPMB_KEY_MAC_SIZE)
        return TEE_ERROR_GENERIC;

    ret = tee_rpmb_get_rootkey_data(data, &datalen, RPMB_ACCESS_KEY);
    if (ret == TEE_SUCCESS) { /* get keyinfo from bl31 success */
        rc = memcpy_s(key_prepare, key_len, data, RPMB_KEY_MAC_SIZE);
        if (rc != EOK) {
            tloge("rpmb copy keyinfo faild!\n");
            ret = TEE_ERROR_SECURITY;
        }
    } else {
        tloge("get keyinfo from bl31 faild\n");
        ret = TEE_ERROR_GENERIC;
    }

    /* clear the stack variable to protect the key */
    (void) memset_s(data, sizeof(data), 0, sizeof(data));

    return ret;
}

static TEE_Result tee_rpmb_key_prepare_manage(uint8_t *key_prepare, uint32_t key_len)
{
    errno_t rc;
    TEE_Result ret;
    struct rpmb_devinfo rpmb_info;
    (void)memset_s(&rpmb_info, sizeof(rpmb_info), 0, sizeof(rpmb_info));
    /*
     * tee_ext_cmac_derive_key derive key size is 16 bytes,
     * so, SHOULD derive the key twice
     */
    if (key_len < RPMB_KEY_MAC_SIZE)
        return TEE_ERROR_GENERIC;

    ret = tee_rpmb_get_devinfo(&rpmb_info);
    if (ret != TEE_SUCCESS) {
        tloge("get dev info failed!");
        return TEE_ERROR_GENERIC;
    }

    uint32_t derive_type = CRYPTO_TYPE_HMAC_SHA256;
    struct memref_t salt = {0};
    salt.buffer = (uintptr_t)rpmb_info.cid;
    salt.size = (uint32_t)sizeof(rpmb_info.cid);

    struct memref_t cmac = {0};
    cmac.buffer = (uintptr_t)key_prepare;
    cmac.size = key_len;

    ret = (TEE_Result)tee_crypto_derive_root_key(derive_type, &salt, &cmac, 1);
    if (ret != TEE_SUCCESS) {
        tloge("rpmb cmac derive key failed, ret = 0x%x\n", ret);
        return TEE_ERROR_GENERIC;
    }
    rc = memcpy_s(key_prepare + CMAC_KEY_SIZE, key_len - CMAC_KEY_SIZE, key_prepare, CMAC_KEY_SIZE);
    if (rc != EOK)
        return TEE_ERROR_SECURITY;

    return TEE_SUCCESS;
}

static struct rpmb_partition_info_mtk g_mtk_partition_info;
static TEE_Result tee_rpmb_get_partition_info_mtk(void)
{
    uint32_t rc;

    tlogd("get partition info mtk");
    if (g_mtk_partition_info.readout_magic == SEC_MEM_MAGIC)
        return TEE_SUCCESS;

    uint64_t args[] = {
        (uint64_t)(uintptr_t)&g_mtk_partition_info,
        (uint64_t)sizeof(g_mtk_partition_info),
        (uint64_t)TEEOS_SHARED_MEM_MAILBOX,
    };

    rc = hm_drv_call(SW_SYSCALL_GET_TEESHAREDMEM, args, ARRAY_SIZE(args));
    if (rc != 0) {
        tloge("read rpmb memarg faild 0x%x\n", rc);
        return TEE_ERROR_GENERIC;
    }

    if (g_mtk_partition_info.magic != SEC_MEM_MAGIC) {
        tloge("get sec mem info failed, magic is 0x%x\n", g_mtk_partition_info.magic);
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

static TEE_Result tee_rpmb_key_prepare_mtk(uint8_t *key_prepare, uint32_t key_len)
{
    errno_t rc;
    TEE_Result ret;

    if (key_len < RPMB_KEY_MAC_SIZE)
        return TEE_ERROR_GENERIC;

    ret = tee_rpmb_get_partition_info_mtk();
    if (ret == TEE_SUCCESS) {
        rc = memcpy_s(key_prepare, key_len, g_mtk_partition_info.msg_auth_key, RPMB_KEY_MAC_SIZE);
        if (rc != EOK)
            return TEE_ERROR_SECURITY;
    } else {
        tloge("rpmb get mtk partition info failed!\n");
        return TEE_ERROR_GENERIC;
    }
    return TEE_SUCCESS;
}

#ifdef TEE_SUPPORT_HSM
#define RPMB_KEY_SIZE 80U
#else
#define RPMB_KEY_SIZE 32U
#endif
/* Notice: this function must be called after has_get_rpmb_info */
TEE_Result tee_rpmb_key_prepare(uint8_t **rpmb_key, uint32_t *key_size)
{
    TEE_Result ret;
    uint32_t key_type = RPMB_KEY_UNKOWN;

    if (rpmb_key == NULL || key_size == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    *key_size = RPMB_KEY_SIZE;
    if (*rpmb_key != NULL)
        return TEE_SUCCESS;

    *rpmb_key = TEE_Malloc(RPMB_KEY_SIZE, 0);
    if (*rpmb_key == NULL)
        return TEE_ERROR_OUT_OF_MEMORY;

    tee_rpmb_get_key_type(&key_type);
    if (key_type == RPMB_ACCESS_KEY) {
        ret = tee_rpmb_key_prepare_access(*rpmb_key, *key_size);
    } else if (key_type == RPMB_MANAGE_KEY) {
        ret = tee_rpmb_key_prepare_manage(*rpmb_key, *key_size);
    } else if (key_type == RPMB_M_KEY) {
        ret = tee_rpmb_key_prepare_mtk(*rpmb_key, *key_size);
#ifdef TEE_SUPPORT_HSM
    } else if (key_type == RPMB_HSM_KEY) {
        ret = TEE_HSM_GenRpmbWrappingKey(0, *rpmb_key);
#endif
    } else {
        tloge("unkown key type %u\n", key_type);
        ret = TEE_ERROR_BAD_STATE;
    }

    if (ret != TEE_SUCCESS && *rpmb_key != NULL) {
        TEE_Free(*rpmb_key);
        *rpmb_key = NULL;
    }
    return ret;
}

static TEE_Result tee_rpmb_get_partition_info(struct rpmb_partition_info *partition_info, uint32_t key_type)
{
    TEE_Result ret;
    uint32_t res_code;

    partition_info->start_blk      = 0;
    partition_info->total_blk      = 0;
    partition_info->mdt            = 0;
    partition_info->support_bitmap = 0;
    partition_info->version        = 0;

    res_code = rpmb_partition_info_read(&g_u_rai);
    if (res_code != RPMB_PARTITION_INFO_READY) {
        /* read from atf */
        ret = tee_rpmb_get_chip_info(key_type);
        if (ret != TEE_SUCCESS)
            return ret;
    }

    partition_info->start_blk      = g_u_rai.start_blk;
    partition_info->total_blk      = g_u_rai.total_blk;
    partition_info->mdt            = g_u_rai.mdt;
    partition_info->support_bitmap = g_u_rai.support_bit_map;
    partition_info->version        = g_u_rai.version;

    tee_rpmb_clear_chip_info();

    return TEE_SUCCESS;
}

#define RPMB_CTRL_SIZE 128
uint16_t tee_rpmb_get_max_access_cnt(const struct rpmb_devinfo *rdi)
{
    uint16_t can_writtencnt;
    uint16_t max_cnt;
    uint32_t emmc_bitmap;
    uint32_t tmp_bitmap;
    uint32_t i;

    if (rdi == NULL) {
        tloge("the rpmb dev info is not ready!\n");
        return 0;
    }

    if (g_rpmb_agent_buffersize < RPMB_AGENT_BUFF_SIZE ||
        g_rpmb_agent_buffersize > RPMB_AGENT_BUFF_NUM_MAX * RPMB_AGENT_BUFF_SIZE)
        return 0;

    /* the max blkcnt the agent buffer can fill. */
    max_cnt = (g_rpmb_agent_buffersize - RPMB_CTRL_SIZE - RPMB_FRAME_SIZE * RPMB_BUF_RES_BLK) /
               RPMB_FRAME_SIZE;

    switch (rdi->mdt) {
    case MDT_EMMC:
        can_writtencnt = 0;

        if (rdi->version != RPMB_CHIP_VERSION_01)
            emmc_bitmap = RPMB_EMMC_BITMAP_DEF;
        else
            emmc_bitmap = rdi->support_bit_map;

        for (i = RPMB_EMMC_BITMAP_BIT_MAX; i > 0; i--) {
            if (i > max_cnt)
                continue;

            tmp_bitmap = (1U << (i - 1));
            if ((tmp_bitmap & emmc_bitmap) == tmp_bitmap) {
                can_writtencnt = i;
                break;
            }
        }
        break;
    case MDT_UFS:
        max_cnt = (max_cnt > RPMB_UFS_MAX_WRITE_BLKCNT) ? RPMB_UFS_MAX_WRITE_BLKCNT : max_cnt;
        can_writtencnt = max_cnt;
        break;
    default:
        can_writtencnt = 0;
        break;
    }

    tlogd("max %u, can %u\n", max_cnt, can_writtencnt);
    return can_writtencnt;
}

static TEE_Result tee_rpmb_get_devinfo_access(struct rpmb_devinfo *rdi)
{
    TEE_Result ret;
    struct rpmb_partition_info partition_info = { 0 };

    ret = tee_rpmb_get_partition_info(&partition_info, RPMB_ACCESS_KEY);
    if (ret == TEE_SUCCESS) { /* get info from bl31 success */
        rdi->rpmb_size_mult       = RAW_RPMB_SIZE_MULT;
        rdi->blk_size             = RPMB_DATA_SIZE;
        rdi->max_blk_idx          = partition_info.total_blk - 1;
        rdi->access_start_blk_idx = partition_info.start_blk;
        rdi->access_total_blk     = partition_info.total_blk;
        rdi->mdt                  = partition_info.mdt;
        rdi->support_bit_map      = partition_info.support_bitmap;
        rdi->version              = partition_info.version;
        rdi->rel_wr_sec_cnt       = tee_rpmb_get_max_access_cnt(rdi);
        return TEE_SUCCESS;
    } else {
        tloge("get partition info from atf failed\n");
        return TEE_ERROR_GENERIC;
    }
}

#define RPMB_SIZE_MTK_MAX (8U * 1024U * 1024U)
static TEE_Result tee_rpmb_get_devinfo_mtk(struct rpmb_devinfo *rdi)
{
    TEE_Result ret;

    ret = tee_rpmb_get_partition_info_mtk();
    if (ret != TEE_SUCCESS) {
        tloge("get partition info error, ret-0x%x", ret);
        return ret;
    }
    rdi->rpmb_size_mult = ((g_mtk_partition_info.rpmb_size > RPMB_SIZE_MTK_MAX) ?
                           RPMB_SIZE_MTK_MAX : g_mtk_partition_info.rpmb_size) / RPMB_SIZE_SINGLE;
    rdi->rel_wr_sec_cnt       = g_mtk_partition_info.emmc_rel_wr_sec_c << 1;
    rdi->blk_size             = RPMB_DATA_SIZE;
    rdi->max_blk_idx          = rdi->rpmb_size_mult * RPMB_SIZE_SINGLE / RPMB_DATA_SIZE - 1;
    rdi->access_start_blk_idx = 0;
    rdi->access_total_blk     = rdi->max_blk_idx + 1;
    rdi->mdt                  = MDT_EMMC;
    rdi->support_bit_map      = 0;
    rdi->version              = 0;

    tlogd("rpmb info size 0x%x, orign 0x%x, sec cnt %u", rdi->rpmb_size_mult * RPMB_SIZE_SINGLE,
          g_mtk_partition_info.rpmb_size, rdi->rel_wr_sec_cnt);

    return TEE_SUCCESS;
}

#define RPMB_SIZE_MUIL_HSM  0x18
#define RELIABLE_WR_SEC_CNT 0x1U
static TEE_Result tee_rpmb_get_devinfo_hsm(struct rpmb_devinfo *rdi)
{
    rdi->rpmb_size_mult       = RPMB_SIZE_MUIL_HSM;
    rdi->rel_wr_sec_cnt       = RELIABLE_WR_SEC_CNT << 1;
    rdi->blk_size             = RPMB_DATA_SIZE;
    rdi->max_blk_idx          = rdi->rpmb_size_mult * RPMB_SIZE_SINGLE / RPMB_DATA_SIZE - 1;
    rdi->access_start_blk_idx = 0;
    rdi->access_total_blk     = rdi->max_blk_idx + 1;
    rdi->mdt                  = MDT_EMMC;
    rdi->support_bit_map      = 0;
    rdi->version              = 0;

    tlogd("rpmb info size 0x%x, orign 0x%x, sec cnt %u", rdi->rpmb_size_mult * RPMB_SIZE_SINGLE,
          g_mtk_partition_info.rpmb_size, rdi->rel_wr_sec_cnt);

    return TEE_SUCCESS;
}

TEE_Result tee_rpmb_get_devinfo(struct rpmb_devinfo *rdi)
{
    TEE_Result ret;
    uint32_t key_type = RPMB_KEY_UNKOWN;

    if (rdi == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    tee_rpmb_get_key_type(&key_type);
    if (key_type == RPMB_ACCESS_KEY) {
        ret = tee_rpmb_get_devinfo_access(rdi);
    } else if (key_type == RPMB_M_KEY) {
        ret = tee_rpmb_get_devinfo_mtk(rdi);
    } else if (key_type == RPMB_HSM_KEY) {
        ret = tee_rpmb_get_devinfo_hsm(rdi);
    } else {
        tloge("unkown key type!\n");
        ret = TEE_ERROR_BAD_STATE;
    }
    return ret;
}

#define RPMB_MAX_WRITE_BLKCNT 32U
TEE_Result tee_rpmb_calc_mac(const struct rpmb_data_frame *datafrms, uint16_t blkcnt,
                             const struct rpmb_key_info *rpmb_key, uint8_t *mac, uint32_t macsize)
{
    struct symmerit_key_t key = {0};
    struct memref_t data_in = {0};
    struct memref_t data_out = {0};
    uint16_t i;
    uint8_t *tmp_buf = NULL;
    uint32_t tmp_len;
    int32_t ret;

    if (datafrms == NULL || rpmb_key == NULL || rpmb_key->key == NULL ||
        mac == NULL || blkcnt > RPMB_MAX_WRITE_BLKCNT)
        return TEE_ERROR_BAD_PARAMETERS;

    tmp_len = blkcnt * RPMB_MAC_PROTECT_DATA_SIZE;
    tmp_buf = TEE_Malloc(tmp_len, 0);
    if (tmp_buf == NULL)
        return TEE_ERROR_OUT_OF_MEMORY;

    for (i = 0; i < blkcnt; i++) {
        if (memcpy_s(tmp_buf + i * RPMB_MAC_PROTECT_DATA_SIZE, tmp_len - i * RPMB_MAC_PROTECT_DATA_SIZE,
            datafrms[i].data, RPMB_MAC_PROTECT_DATA_SIZE) != EOK) {
            ret = TEE_ERROR_SECURITY;
            goto out;
        }
    }

    key.key_buffer = (uint64_t)(uintptr_t)(rpmb_key->key);
    key.key_size = rpmb_key->keysize;

    data_in.buffer = (uint64_t)(uintptr_t)tmp_buf;
    data_in.size = tmp_len;

    data_out.buffer = (uint64_t)(uintptr_t)mac;
    data_out.size = macsize;
#ifdef TEE_SUPPORT_HSM
    key.key_type = CRYPTO_KEYTYPE_RPMB;
    ret = tee_crypto_hmac(CRYPTO_TYPE_HMAC_SHA256, &key, &data_in, &data_out, SEC_CRYPTO);
#else
    key.key_type = CRYPTO_KEYTYPE_USER;
    ret = tee_crypto_hmac(CRYPTO_TYPE_HMAC_SHA256, &key, &data_in, &data_out, SOFT_CRYPTO);
#endif
    if (ret != 0)
        tloge("tee_crypto_hmac fail, ret:%x", ret);

out:
    TEE_Free(tmp_buf);
    tmp_buf = NULL;
    return (TEE_Result)ret;
}

void tee_rpmb_init_agent_buff_size(uint32_t size)
{
    g_rpmb_agent_buffersize = size;
}
uint32_t rpmb_get_agent_buff_size(void)
{
    return g_rpmb_agent_buffersize;
}
