/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: keymaster environment related process
 * Create: 2020-11-09
 */
#include "km_env.h"
#include "tee_crypto_api.h"
#include "kmrot_ops_ext.h"
#include "keymaster_defs.h"
#include "km_tag_operation.h"
#include "securec.h"
#include "tee_hw_ext_api.h"
#include "platform_get.h"
#include "tee_private_api.h"
#include "tee_inner_uuid.h"
#include "km_common.h"

/* this global value should be get from keymaster after each boot */
static unsigned char g_rot[ROT_SIZE] = { 0 };
pthread_mutex_t g_attest_key_lock;
pthread_mutex_t g_key_index_lock;
pthread_mutex_t g_opera_metafile_lock;
static struct verify_boot_info_struct g_verify_boot_info = { LSTATE_LOCKED, LOCK_GREEN, { 0 }, 0, 0, 0, 0 };
static const char *g_lock_state_str[] = { "LOCKED", "UNLOCKED" };
static const char *g_color_str[] = { "GREEN", "YELLOW", "ORANGE", "RED" };

int32_t generate_rot(void)
{
    int32_t ret;
    TEE_GenerateRandom(g_rot, ROT_SIZE);
    if (is_buff_zero(g_rot, ROT_SIZE)) {
        tloge("g_rot random failed\n");
        return -1;
    }
    ret = __SRE_SetKMROT(g_rot, ROT_SIZE);
    if (ret != 0)
        tloge("failed to set g_rot into kernel\n\n");
    return ret;
}

uint8_t *get_rot(void)
{
    int32_t ret;
    ret = __SRE_GetKMROT(g_rot, ROT_SIZE);
    if (ret != 0) {
        tloge("failed to get rot into kernel\n");
        return NULL;
    }
    return g_rot;
}

static struct cfg_state_t g_config_state = { STATE_LOCKED, STATE_UNCFG };

bool is_cfg_state_ready(void)
{
    bool config_check_fail = (g_config_state.is_lock == STATE_LOCKED && g_config_state.is_cfg == STATE_UNCFG);
    if (config_check_fail) {
        tloge("keymaster is not configured correctly\n");
        return false;
    }

    return true;
}

void set_lock_state(state_lock_t state)
{
    g_config_state.is_lock = state;
}

state_lock_t get_lock_state(void)
{
    return g_config_state.is_lock;
}
state_set_t get_cfg_state(void)
{
    return g_config_state.is_cfg;
}

void set_cfg_state(state_set_t cfg)
{
    g_config_state.is_cfg = cfg;
}

pthread_mutex_t *get_key_index_lock(void)
{
    return &g_key_index_lock;
}

pthread_mutex_t *get_opera_metafile_lock(void)
{
    return &g_opera_metafile_lock;
}

pthread_mutex_t *get_attest_key_lock(void)
{
    return &g_attest_key_lock;
}

#ifdef MTK_BOOT_INFO
static int init_mtk_verify_boot_info(void)
{
    struct verify_boot_mem_struct_mtk verify_boot_mem = { { 0 }, 0, 0, 0, { 0 } };
    errno_t rc;
    uint32_t ver_year;
    uint32_t ver_mon;

    tlogd("get mtk_verify_boot_info begin\n");
    /* 1.read VB info from share memory */
    if (TEE_EXT_GetVerifyBootInfo((char *)&verify_boot_mem, sizeof(verify_boot_mem))) {
        tloge("init mtk verify boot info failed\n");
        return -1;
    }

    /* 2.adapt VB lock state */
    if ((LSTATE_LOCKED != verify_boot_mem.device_lock_state) &&
        (LSTATE_UNLOCKED != verify_boot_mem.device_lock_state)) {
        tloge("the lock state is not match, lock state is %d\n", verify_boot_mem.device_lock_state);
        return -1;
    }
    g_verify_boot_info.lstate = (enum lock_state)verify_boot_mem.device_lock_state;
    tlogd("verify boot lock state is %s\n", g_lock_state_str[g_verify_boot_info.lstate]);

    /* 3.adapt VB lock color */
    if ((LOCK_GREEN > verify_boot_mem.verify_boot_state) || (LOCK_RED < verify_boot_mem.verify_boot_state)) {
        tloge("the lock color is not match, lock color is %d\n", verify_boot_mem.verify_boot_state);
        return -1;
    }
    g_verify_boot_info.color = (enum lock_color)verify_boot_mem.verify_boot_state;
    /* 4.adapt VB public key hash */
    rc = memcpy_s(g_verify_boot_info.pub_key, PUBLIC_KEY_SIZE, verify_boot_mem.pubk_hash, PUBLIC_KEY_HASH_SIZE);
    if (rc != EOK) {
        tloge("[error]memcpy_s failed, rc=%d\n", rc);
        return rc;
    }

    /* 5.adapt VB OS version */
    ver_mon = verify_boot_mem.os_version & (0xf);
    ver_year = (verify_boot_mem.os_version >> VER_YEAR_SHIFT_NUM) & (0x7f);
    g_verify_boot_info.boot_patch_level = ((ver_year + VER_YEAR_BASE_NUM) * PATCH_LEVER_SHIFT) + ver_mon;
    tlogd("get verify boot_patch_level, patch_level=%u\n", g_verify_boot_info.boot_patch_level);
    tlogd("get mtk_verify_boot_info success\n");
    return 0;
}
#endif

int init_verify_boot_info(void)
{
    struct verify_boot_mem_struct verify_boot_mem = { { 0 }, { 0 }, { 0 }, 0 };
    int lstate_match = 0;
    int color_match = 0;
    uint32_t ver_year, ver_mon;
    int i;
    errno_t rc;
    /* adapt for mtk */
#ifdef MTK_BOOT_INFO
    return init_mtk_verify_boot_info();
#endif

    if (TEE_EXT_GetVerifyBootInfo((char *)&verify_boot_mem, sizeof(verify_boot_mem))) {
        tloge("init verify boot info failed\n");
        return -1;
    }

    for (i = 0; i < (int)LSTATE_MAX; i++)
        if (!memcmp(verify_boot_mem.lock_state, g_lock_state_str[i], strlen(g_lock_state_str[i]) + 1)) {
            g_verify_boot_info.lstate = (enum lock_state)i;
            lstate_match = 1;
            break;
        }

    if (lstate_match == 0) {
        tloge("no lock state match\n");
        return -1;
    }
    g_verify_boot_info.color = LOCK_RED;
    for (i = 0; i < (int)LOCK_COLOR_MAX; i++)
        if (!memcmp(verify_boot_mem.lock_color, g_color_str[i], strlen(g_color_str[i]) + 1)) {
            g_verify_boot_info.color = (enum lock_color)i;
            color_match = 1;
            break;
        }

    if (color_match == 0) {
        tloge("no lock color match\n");
        return -1;
    }
    rc = memcpy_s(g_verify_boot_info.pub_key, PUBLIC_KEY_SIZE, verify_boot_mem.pub_key, PUBLIC_KEY_SIZE);
    if (rc != EOK) {
        tloge("[error]memcpy_s failed, rc=%d\n", rc);
        return rc;
    }
    ver_mon = verify_boot_mem.os_version_info & (0xf);
    ver_year = (verify_boot_mem.os_version_info >> VER_YEAR_SHIFT_NUM) & (0x7f);
    g_verify_boot_info.boot_patch_level = ((ver_year + VER_YEAR_BASE_NUM) * PATCH_LEVER_SHIFT) + ver_mon;

    return 0;
}

enum lock_state get_verify_boot_lock_state(void)
{
    return g_verify_boot_info.lstate;
}

enum lock_color get_verify_boot_color(void)
{
    return g_verify_boot_info.color;
}

uint32_t get_verify_boot_os_version(void)
{
    return g_verify_boot_info.os_version;
}

uint32_t get_verify_boot_patch_level(void)
{
    return g_verify_boot_info.patch_level;
}

void set_sys_os_version(uint32_t os_version)
{
    g_verify_boot_info.os_version = os_version;
}

void set_sys_patch_level(uint32_t patch_level)
{
    g_verify_boot_info.patch_level = patch_level;
}

void set_vendor_patch_level(uint32_t patch_level)
{
    g_verify_boot_info.vendor_patch_level = patch_level;
}

void get_verify_boot_key(keymaster_blob_t *verified_boot_key)
{
    if (verified_boot_key == NULL) {
        tloge("the verified_boot_key is null\n");
        return;
    }
    verified_boot_key->data_addr = (uint8_t *)g_verify_boot_info.pub_key;
    verified_boot_key->data_length = PUBLIC_KEY_SIZE;
}

static int check_gen_or_check(int gen_or_check)
{
    uint32_t index = 0;
    int support_gen_or_check_list[] = { GENERATE_HMAC, CHECK_ORIGINAL_LOCK_COLOR, CHECK_ADAPTABLE_LOCK_COLOR };

    for (; index < (sizeof(support_gen_or_check_list) / sizeof(uint32_t)); index++)
        if (gen_or_check == support_gen_or_check_list[index])
            return 0;

    return -1;
}

static int proc_check_adapt_lock_color(int *lock_color)
{
    /* use adaptable lock color  */
    if (*lock_color == LOCK_GREEN) {
        *lock_color = LOCK_ORANGE;
    } else if (*lock_color == LOCK_ORANGE) {
        *lock_color = LOCK_GREEN;
    } else {
        tloge("lock_color judge failed\n");
        return -1;
    }

    return 0;
}

static int adapt_lock_color(int gen_or_check, int *lock_color)
{
    int ret;
    /*
     * 1.when generate HMAC, LOCK_ORANGE will be made same with LOCK_GREEN;
     * 2.To adapt old version, we'll check again with an adaptable color
     *   after first check failed.
     */
    ret = check_gen_or_check(gen_or_check);
    if (ret != 0) {
        tloge("unsupported gen_or_check is %d\n", gen_or_check);
        return -1;
    }

    /* CHECK_ORIGINAL_LOCK_COLOR use original fastboot lock color */
    if (gen_or_check == GENERATE_HMAC) /* generate HMAC */
        if (*lock_color == LOCK_ORANGE)
            *lock_color = LOCK_GREEN;
    if (gen_or_check == CHECK_ADAPTABLE_LOCK_COLOR) {
        ret = proc_check_adapt_lock_color(lock_color);
        if (ret != 0) {
            tloge("proc_check_adapt_lock_color failed\n");
            return -1;
        }
    }

    return ret;
}

static void get_adaptable_value(int *adaptable, const int *lock_color)
{
    if ((*lock_color == LOCK_GREEN) || (*lock_color == LOCK_ORANGE))
        *adaptable = NEED_CHECK_ADAPTABLE_COLOR;
    else
        *adaptable = NO_NEED_CHECK_ADAPTABLE_COLOR;
}

int get_lock_color(int gen_or_check, int *adaptable, int *lock_color)
{
    char product_name[PRODUCT_NAME_LEN] = { 0 };
    int size = sizeof(product_name);
    int ret;

    if (lock_color == NULL) {
        tloge("lock_color is null\n");
        return -1;
    }

    ret = __get_target_product(product_name, &size);
    if (ret < 0) {
        tloge("get product name fail\n");
        return -1;
    }

    if (strncmp(product_name, EXCLUED_PRODUCT, strlen(EXCLUED_PRODUCT)) == 0) {
        tlogd("targe product is NEXT\n");
        *lock_color = LOCK_GREEN; /* disable the fastboot lock feature */
    } else {
        *lock_color = get_verify_boot_color();
    }
    tlogd("lock_color %u\n", *lock_color);
    /* return 'adaptable' to indicate if keyblob HMAC check need a double check */
    if (adaptable != NULL)
        get_adaptable_value(adaptable, lock_color);

    ret = adapt_lock_color(gen_or_check, lock_color);
    if (ret != 0) {
        tloge("adapt_lock_color failed\n");
        return -1;
    }
    tlogd("fastboot lock color %s\n", g_color_str[*lock_color]);

    return 0;
}

static int proc_without_appid_version_key_derive(const uint8_t *hmac_secret, uint32_t hmac_secret_lenth, uint8_t *key)
{
    errno_t rc;
    uint8_t *secret_buff = NULL;
    uint32_t total_len = hmac_secret_lenth + sizeof(TEE_UUID);
    TEE_UUID cur_uuid = TEE_SERVICE_KEYMASTER;

    if (total_len <= hmac_secret_lenth) {
        tloge("secret_buff len is error\n");
        return -1;
    }
    secret_buff = TEE_Malloc(total_len, 0);
    if (secret_buff == NULL) {
        tloge("secret_buff malloc failed\n");
        return -1;
    }

    rc = memmove_s(secret_buff, hmac_secret_lenth, hmac_secret, hmac_secret_lenth);
    if (rc != EOK) {
        tloge("memmove_s failed, rc is 0x%x\n", rc);
        goto error;
    }

    rc = memmove_s(secret_buff + hmac_secret_lenth, sizeof(TEE_UUID), (void *)&cur_uuid, sizeof(TEE_UUID));
    if (rc != EOK) {
        tloge("memmove_s failed, rc is 0x%x\n", rc);
        goto error;
    }

    /* derive key from root key */
    if (TEE_EXT_ROOT_DeriveKey2(secret_buff, total_len, key, HMAC_SIZE)) {
        tloge("derive key from root key failed\n");
        rc = memset_s(key, HMAC_SIZE, 0, HMAC_SIZE);
        if (rc != EOK)
            tloge("memset_s key without appid failed, rc is %d\n", rc);
        goto error;
    }

    TEE_Free(secret_buff);
    return 0;

error:
    TEE_Free(secret_buff);
    return -1;
}


static int pre_proc_high_version_key_derive(const uint8_t *hmac_secret, uint32_t hmac_secret_len, uint8_t *secret_buff,
                                            uint32_t secret_buff_len, const keymaster_blob_t *application_id)
{
    errno_t rc;
    TEE_UUID cur_uuid = TEE_SERVICE_KEYMASTER;

    rc = memmove_s(secret_buff, secret_buff_len, hmac_secret, hmac_secret_len);
    if (rc != EOK) {
        tloge("memmove_s failed, rc 0x%x\n", rc);
        return -1;
    }
    rc = memmove_s(secret_buff + hmac_secret_len, secret_buff_len - hmac_secret_len, (void *)&cur_uuid,
                   sizeof(TEE_UUID));
    if (rc != EOK) {
        tloge("memmove_s failed, rc 0x%x\n", rc);
        return -1;
    }
    rc = memmove_s(secret_buff + hmac_secret_len + sizeof(TEE_UUID),
                   secret_buff_len - hmac_secret_len - sizeof(TEE_UUID), (void *)application_id->data_addr,
                   application_id->data_length);
    if (rc != EOK) {
        tloge("memmove_s failed, rc 0x%x\n", rc);
        return -1;
    }
    return 0;
}
static int proc_appid_version_key_derive(const uint8_t *hmac_secret, uint32_t hmac_secret_len,
                                         const keymaster_blob_t *application_id, uint8_t *key)
{
    uint8_t *secret_buff = NULL;

    uint32_t total_len = hmac_secret_len + sizeof(TEE_UUID) + application_id->data_length;
    if (total_len < hmac_secret_len + sizeof(TEE_UUID) || application_id->data_length > KM_INPUT_BLOB_MAX_LEN) {
        tloge("appID length is not right!\n");
        return -1;
    }
    secret_buff = TEE_Malloc(total_len, 0);
    if (secret_buff == NULL) {
        tloge("secret_buff malloc failed\n");
        return -1;
    }

    if (pre_proc_high_version_key_derive(hmac_secret, hmac_secret_len, secret_buff, total_len, application_id))
        goto error;

    /* derive key from root key */
    if (TEE_EXT_ROOT_DeriveKey2(secret_buff, total_len, key, HMAC_SIZE)) {
        tloge("derive key from root key failed\n");
        /* no need judge the return code */
        errno_t rc = memset_s(key, HMAC_SIZE, 0, HMAC_SIZE);
        if (rc != EOK)
            tloge("memset_s key with appid failed, rc is %d\n", rc);
        goto error;
    }
    TEE_Free(secret_buff);
    return 0;

error:
    TEE_Free(secret_buff);
    return -1;
}
static int proc_key_derive(const uint8_t *hmac_secret, uint32_t hmac_secret_len, uint32_t version,
                           const keymaster_blob_t *application_id, uint8_t *key)
{
    int ret = 0;

    bool is_deprecated_version =
        ((version == VERSION_100) || (version == VERSION_200) || (version == VERSION_110) || (version == VERSION_210));
    bool is_without_appid_version = ((version == VERSION_520) || (version == VERSION_530) ||
#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
    (version == VERSION_220) || (version == VERSION_230) || (version == VERSION_340) || (version == VERSION_540) ||
    (version == VERSION_341) || (version == VERSION_541));
#else
    (version == VERSION_220) || (version == VERSION_230));
#endif
    bool is_appid_version = ((version == VERSION_300) || (version == VERSION_310) ||
        (version == VERSION_500) || (version == VERSION_510));
    if (is_deprecated_version) {
        tloge("deprecated version %u, derive key failed\n", version);
        return -1;
    } else if (is_without_appid_version) {
        tlogd("derive key without appid\n");
        ret = proc_without_appid_version_key_derive(hmac_secret, hmac_secret_len, key);
        if (ret) {
            tloge("proc without appid version key derive failed\n");
            return -1;
        }
    } else if ((is_appid_version) && (application_id->data_addr != NULL)) {
        tlogd("derive key with appid\n");
        ret = proc_appid_version_key_derive(hmac_secret, hmac_secret_len, application_id, key);
        if (ret) {
            tloge("proc_appid_version_key_derive failed\n");
            return -1;
        }
    } else {
        return -1;
    }
    return ret;
}

int preproc_keymaster_hmac(int gen_or_check, int *adaptable, uint32_t version,
    const keymaster_blob_t *application_id, uint8_t *key)
{
    int ret;
    int lock_color;
    uint8_t keyblob_hmac_secret[] = { 'T', 'r', 'u', 's', 't', 'e', 'd', 'C', 'o', 'r', 'e',
                                      'k', 'e', 'y', 'm', 'a', 's', 't', 'e', 'r', 'M' };

    ret = get_lock_color(gen_or_check, adaptable, &lock_color);
    if (ret) {
        tloge("get_lock_color failed\n");
        return -1;
    }
    if (lock_color == LOCK_GREEN) {
        tlogd("green color\n");
        ret = proc_key_derive(keyblob_hmac_secret, sizeof(keyblob_hmac_secret), version, application_id, key);
        if (ret) {
            tloge("proc_key_derive failed\n");
            return -1;
        }
    } else {
        tlogd("other color\n");
        ret = proc_key_derive((uint8_t *)g_color_str[lock_color], strlen(g_color_str[lock_color]), version,
                              application_id, key);
        if (ret) {
            tloge("proc_key_derive failed\n");
            return -1;
        }
    }
    return ret;
}
